use std::{num::NonZeroU16, str::FromStr, time::Duration};

use crate::{
    secret_manager::{SecretManager, SecretManagerError},
    services::{
        key_event_watcher::{KeyRegistryEventError, handler::KeyRegistryEventHandler},
        secret_gen::DLogSecretGenService,
        transaction_handler::{TransactionHandler, TransactionHandlerArgs},
    },
    tests::keygen_test_secret_manager::TestKeyGenSecretManager,
};
use alloy::{network::EthereumWallet, primitives::U160, signers::local::PrivateKeySigner};
use groth16_material::circom::{CircomGroth16Material, CircomGroth16MaterialBuilder};
use nodes_common::{Environment, web3::HttpRpcProviderBuilder};
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_test_utils::{DeploySetup, OPRF_PEER_PRIVATE_KEY_0, PEER_ADDRESSES, TestSetup};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    chain::{OprfKeyRegistry, RevertError, Verifier::VerifierErrors},
};

use super::events::KeyRegistryEvent;

// Key IDs that trigger special behaviour in TestOprfKeyRegistry:
//   43 → loadPeerPublicKeysForProducers returns hardcoded EPKs; addRound2Contribution runs the
//        verifier with all-zero public inputs so any real proof yields ProofInvalid.
//   44 → loadPeerPublicKeysForProducers reverts with WrongRound, exercising the consumer path.
const INVALID_PROOF_KEY: u32 = 43;
const WRONG_ROUND_LOAD_PEER_PUBLIC_KEYS: u32 = 44;

struct HandlerFixture {
    handler: KeyRegistryEventHandler,
    secret_manager: TestKeyGenSecretManager,
    secret_gen: DLogSecretGenService,
}

fn key_gen_material(deploy_setup: DeploySetup) -> CircomGroth16Material {
    CircomGroth16MaterialBuilder::new()
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .build_from_paths(deploy_setup.key_gen_path(), deploy_setup.witness_path())
        .expect("Can build key_gen_material")
}

fn fixture(setup: &TestSetup) -> HandlerFixture {
    let secret_manager = TestKeyGenSecretManager::new(OPRF_PEER_PRIVATE_KEY_0);
    let secret_gen =
        DLogSecretGenService::init(key_gen_material(setup.setup), secret_manager.service());

    let rpc_provider =
        HttpRpcProviderBuilder::with_default_values(vec![setup.anvil.endpoint_url()])
            .environment(Environment::Dev)
            .chain_id(31_337)
            .wallet(EthereumWallet::new(
                PrivateKeySigner::from_str(OPRF_PEER_PRIVATE_KEY_0).expect("works"),
            ))
            .build()
            .expect("can build RPC providers");

    let transaction_handler = TransactionHandler::new(TransactionHandlerArgs {
        max_wait_time_watch_transaction: Duration::from_secs(10),
        confirmations_for_transaction: 1,
        sleep_between_get_receipt: Duration::from_millis(500),
        max_tries_fetching_receipt: 5,
        max_gas_per_transaction: 10_000_000,
        rpc_provider,
        wallet_address: PEER_ADDRESSES[0],
        contract_address: setup.oprf_key_registry,
    });

    let contract = OprfKeyRegistry::new(setup.oprf_key_registry, setup.provider.clone());
    let threshold = NonZeroU16::new(2).expect("2 is non-zero");
    let handler =
        KeyRegistryEventHandler::new(contract, secret_gen.clone(), threshold, transaction_handler);

    HandlerFixture {
        handler,
        secret_manager,
        secret_gen,
    }
}

fn random_share() -> DLogShareShamir {
    DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>())
}

#[tokio::test]
async fn test_round2_invalid_proof() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let fx = fixture(&setup);
    let key_id = OprfKeyId::from(U160::from(INVALID_PROOF_KEY));
    let epoch = ShareEpoch::default();

    // Generate local intermediates (TestOprfKeyRegistry returns hardcoded EPKs for key 43,
    // so producer_round2 will produce a proof whose public inputs mismatch on-chain → ProofInvalid).
    fx.secret_gen
        .key_gen_round1(key_id, epoch, NonZeroU16::new(2).expect("non-zero"))
        .await?;

    let error = fx
        .handler
        .handle(
            KeyRegistryEvent::Round2 { key_id, epoch },
            &tracing::Span::none(),
        )
        .await
        .expect_err("should fail with ProofInvalid");

    assert!(matches!(
        error,
        KeyRegistryEventError::Revert(RevertError::Verifier(VerifierErrors::ProofInvalid(_)))
    ));
    Ok(())
}

#[tokio::test]
async fn test_round2_consumer_path_when_contract_in_wrong_round() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let fx = fixture(&setup);
    let key_id = OprfKeyId::from(U160::from(WRONG_ROUND_LOAD_PEER_PUBLIC_KEYS));
    let epoch = ShareEpoch::default();

    fx.secret_gen
        .key_gen_round1(key_id, epoch, NonZeroU16::new(2).expect("non-zero"))
        .await?;

    // TestOprfKeyRegistry reverts with WrongRound for key 44; handler takes the consumer path → Ok(()).
    fx.handler
        .handle(
            KeyRegistryEvent::Round2 { key_id, epoch },
            &tracing::Span::none(),
        )
        .await
        .expect("consumer path should succeed");

    // Intermediates survive; no share was confirmed.
    fx.secret_manager
        .fetch_keygen_intermediates(key_id, epoch)
        .await?;
    assert!(
        fx.secret_manager
            .get_share_by_epoch(key_id, epoch)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn test_delete() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let fx = fixture(&setup);
    let key_id = OprfKeyId::new(U160::from(42u32));
    let confirmed_epoch = ShareEpoch::default();
    let pending_epoch = confirmed_epoch.next();

    fx.secret_manager.add_random_key_material_with_id_epoch(
        key_id,
        confirmed_epoch,
        &mut rand::thread_rng(),
    );
    fx.secret_gen
        .reshare_round1(key_id, pending_epoch, NonZeroU16::new(2).expect("non-zero"))
        .await?;
    fx.secret_manager
        .store_pending_dlog_share(key_id, pending_epoch, random_share())
        .await?;

    assert!(
        fx.secret_manager
            .get_share_by_epoch(key_id, confirmed_epoch)
            .await?
            .is_some()
    );
    fx.secret_manager
        .fetch_keygen_intermediates(key_id, pending_epoch)
        .await?;

    fx.handler
        .handle(KeyRegistryEvent::Delete { key_id }, &tracing::Span::none())
        .await
        .expect("delete should succeed");

    // Confirmed share removed.
    assert!(
        fx.secret_manager
            .get_share_by_epoch(key_id, confirmed_epoch)
            .await?
            .is_none()
    );

    // Intermediates cleared.
    let err = fx
        .secret_manager
        .fetch_keygen_intermediates(key_id, pending_epoch)
        .await
        .expect_err("intermediates must be gone");
    assert!(
        matches!(err, SecretManagerError::MissingIntermediates(id, ep) if id == key_id && ep == pending_epoch),
        "unexpected error: {err}"
    );

    Ok(())
}

#[tokio::test]
async fn test_abort() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let fx = fixture(&setup);
    let key_id = OprfKeyId::new(U160::from(142u32));
    let confirmed_epoch = ShareEpoch::default();
    let pending_epoch = confirmed_epoch.next();

    fx.secret_manager.add_random_key_material_with_id_epoch(
        key_id,
        confirmed_epoch,
        &mut rand::thread_rng(),
    );
    fx.secret_gen
        .reshare_round1(key_id, pending_epoch, NonZeroU16::new(2).expect("non-zero"))
        .await?;
    fx.secret_manager
        .store_pending_dlog_share(key_id, pending_epoch, random_share())
        .await?;

    fx.handler
        .handle(KeyRegistryEvent::Abort { key_id }, &tracing::Span::none())
        .await?;

    // In-progress state cleared.
    let err = fx
        .secret_manager
        .fetch_keygen_intermediates(key_id, pending_epoch)
        .await
        .expect_err("intermediates must be gone");
    assert!(
        matches!(err, SecretManagerError::MissingIntermediates(id, ep) if id == key_id && ep == pending_epoch),
        "unexpected error: {err}"
    );

    // Confirmed share preserved.
    assert!(
        fx.secret_manager
            .get_share_by_epoch(key_id, confirmed_epoch)
            .await?
            .is_some()
    );
    Ok(())
}
