use std::{str::FromStr, time::Duration};

use crate::{
    secret_manager::{SecretManager, SecretManagerError, SecretManagerService},
    services::{
        key_event_watcher::{
            KeyRegistryEventError, handle_abort, handle_delete, handle_not_enough_producers,
        },
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
    crypto::OprfPublicKey,
};

const INVALID_PROOF_KEY: usize = 43;
const WRONG_ROUND_LOAD_PEER_PUBLIC_KEYS: usize = 44;
fn key_gen_material(deploy_setup: DeploySetup) -> CircomGroth16Material {
    CircomGroth16MaterialBuilder::new()
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .build_from_paths(deploy_setup.key_gen_path(), deploy_setup.witness_path())
        .expect("Can build key_gen_material")
}

fn test_secret_manager() -> TestKeyGenSecretManager {
    TestKeyGenSecretManager::new(OPRF_PEER_PRIVATE_KEY_0)
}

fn random_share() -> DLogShareShamir {
    DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>())
}

fn random_public_key() -> OprfPublicKey {
    OprfPublicKey::new(rand::random())
}

fn test_config(setup: &TestSetup) -> (CircomGroth16Material, TransactionHandler) {
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

    (key_gen_material(setup.setup), transaction_handler)
}

#[tokio::test]
async fn test_send_invalid_proof() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let (key_gen_material, transaction_handler) = test_config(&setup);
    let secret_manager = test_secret_manager();
    let secret_manager_service: SecretManagerService = secret_manager.service();
    let secret_gen = DLogSecretGenService::init(key_gen_material, secret_manager_service);
    let key_id = U160::from(INVALID_PROOF_KEY);
    secret_gen
        .key_gen_round1(
            key_id.into(),
            ShareEpoch::default(),
            2.try_into().expect("1 is non-zero"),
        )
        .await?;
    let error = super::handle_round2(
        OprfKeyId::from(key_id),
        ShareEpoch::from(0u32),
        &OprfKeyRegistry::new(setup.oprf_key_registry, setup.provider.clone()),
        &secret_gen,
        &transaction_handler,
    )
    .await
    .expect_err("should fail");
    assert!(matches!(
        error,
        KeyRegistryEventError::Revert(RevertError::Verifier(VerifierErrors::ProofInvalid(_)))
    ));
    Ok(())
}

#[tokio::test]
async fn test_delete() -> eyre::Result<()> {
    let secret_manager = test_secret_manager();
    let secret_manager_service: SecretManagerService = secret_manager.service();
    let secret_gen = DLogSecretGenService::init(
        key_gen_material(DeploySetup::TwoThree),
        secret_manager_service,
    );

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let confirmed_epoch = ShareEpoch::default();
    let pending_epoch = confirmed_epoch.next();
    secret_manager.add_random_key_material_with_id_epoch(
        oprf_key_id,
        confirmed_epoch,
        &mut rand::thread_rng(),
    );
    secret_gen
        .reshare_round1(
            oprf_key_id,
            pending_epoch,
            2.try_into().expect("2 is non-zero"),
        )
        .await?;
    secret_manager
        .store_pending_dlog_share(oprf_key_id, pending_epoch, random_share())
        .await?;

    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, confirmed_epoch)
            .await?
            .is_some()
    );
    secret_manager
        .fetch_keygen_intermediates(oprf_key_id, pending_epoch)
        .await?;

    handle_delete(oprf_key_id, &secret_gen)
        .await
        .expect("Works");

    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, confirmed_epoch)
            .await?
            .is_none()
    );
    let should_err = secret_manager
        .fetch_keygen_intermediates(oprf_key_id, pending_epoch)
        .await
        .expect_err("Should have missing intermediates");

    assert!(
        matches!(
            should_err,
            SecretManagerError::MissingIntermediates(is_oprf_key, is_epoch) if is_oprf_key == oprf_key_id && is_epoch == pending_epoch
        ),
        "Should be MissingIntermediates but is {should_err}"
    );

    let error = secret_manager
        .confirm_dlog_share(oprf_key_id, pending_epoch, random_public_key())
        .await
        .expect_err("delete must clear pending shares");
    assert!(matches!(
        error,
        SecretManagerError::MissingIntermediates(id, epoch)
            if id == oprf_key_id && epoch == pending_epoch
    ));

    Ok(())
}

#[tokio::test]
async fn test_round2_in_wrong_round_during_load_public_keys() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let (key_gen_material, transaction_handler) = test_config(&setup);
    let secret_manager = test_secret_manager();
    let secret_manager_service: SecretManagerService = secret_manager.service();
    let secret_gen = DLogSecretGenService::init(key_gen_material, secret_manager_service);
    let key_id = OprfKeyId::from(U160::from(WRONG_ROUND_LOAD_PEER_PUBLIC_KEYS));
    let epoch = ShareEpoch::default();

    secret_gen
        .key_gen_round1(key_id, epoch, 2.try_into().expect("2 is non-zero"))
        .await?;
    secret_manager
        .fetch_keygen_intermediates(key_id, epoch)
        .await?;

    super::handle_round2(
        key_id,
        epoch,
        &OprfKeyRegistry::new(setup.oprf_key_registry, setup.provider.clone()),
        &secret_gen,
        &transaction_handler,
    )
    .await
    .expect("Should still work");

    secret_manager
        .fetch_keygen_intermediates(key_id, epoch)
        .await?;
    assert!(
        secret_manager
            .get_share_by_epoch(key_id, epoch)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn test_abort() -> eyre::Result<()> {
    let secret_manager = test_secret_manager();
    let secret_manager_service: SecretManagerService = secret_manager.service();
    let secret_gen = DLogSecretGenService::init(
        key_gen_material(DeploySetup::TwoThree),
        secret_manager_service,
    );

    let oprf_key_id = OprfKeyId::new(U160::from(142));
    let confirmed_epoch = ShareEpoch::default();
    let pending_epoch = confirmed_epoch.next();
    secret_manager.add_random_key_material_with_id_epoch(
        oprf_key_id,
        confirmed_epoch,
        &mut rand::thread_rng(),
    );
    secret_gen
        .reshare_round1(
            oprf_key_id,
            pending_epoch,
            2.try_into().expect("2 is non-zero"),
        )
        .await?;
    secret_manager
        .store_pending_dlog_share(oprf_key_id, pending_epoch, random_share())
        .await?;

    secret_manager
        .fetch_keygen_intermediates(oprf_key_id, pending_epoch)
        .await?;
    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, confirmed_epoch)
            .await?
            .is_some()
    );

    handle_abort(oprf_key_id, &secret_gen).await?;

    let error = secret_manager
        .fetch_keygen_intermediates(oprf_key_id, pending_epoch)
        .await
        .expect_err("Intermediates must be gone now");
    assert!(matches!(
        error,
        SecretManagerError::MissingIntermediates(id, epoch)
            if id == oprf_key_id && epoch == pending_epoch
    ));
    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, confirmed_epoch)
            .await?
            .is_some()
    );

    let error = secret_manager
        .confirm_dlog_share(oprf_key_id, pending_epoch, random_public_key())
        .await
        .expect_err("abort must clear pending shares");
    assert!(matches!(
        error,
        SecretManagerError::MissingIntermediates(id, epoch)
            if id == oprf_key_id && epoch == pending_epoch
    ));

    Ok(())
}

#[tokio::test]
async fn test_not_enough_producers() -> eyre::Result<()> {
    let secret_manager = test_secret_manager();
    let secret_manager_service: SecretManagerService = secret_manager.service();
    let secret_gen = DLogSecretGenService::init(
        key_gen_material(DeploySetup::TwoThree),
        secret_manager_service,
    );

    let oprf_key_id = OprfKeyId::new(U160::from(242));
    let confirmed_epoch = ShareEpoch::default();
    let pending_epoch = confirmed_epoch.next();
    secret_manager.add_random_key_material_with_id_epoch(
        oprf_key_id,
        confirmed_epoch,
        &mut rand::thread_rng(),
    );
    secret_gen
        .reshare_round1(
            oprf_key_id,
            pending_epoch,
            2.try_into().expect("2 is non-zero"),
        )
        .await?;
    secret_manager
        .store_pending_dlog_share(oprf_key_id, pending_epoch, random_share())
        .await?;

    secret_manager
        .fetch_keygen_intermediates(oprf_key_id, pending_epoch)
        .await?;
    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, confirmed_epoch)
            .await?
            .is_some()
    );

    handle_not_enough_producers(oprf_key_id, &secret_gen).await?;

    let error = secret_manager
        .fetch_keygen_intermediates(oprf_key_id, pending_epoch)
        .await
        .expect_err("Should be an error");

    assert!(matches!(
        error,
        SecretManagerError::MissingIntermediates(id, epoch)
            if id == oprf_key_id && epoch == pending_epoch
    ));
    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, confirmed_epoch)
            .await?
            .is_some()
    );

    let error = secret_manager
        .confirm_dlog_share(oprf_key_id, pending_epoch, random_public_key())
        .await
        .expect_err("not-enough-producers must clear pending shares");
    assert!(matches!(
        error,
        SecretManagerError::MissingIntermediates(id, epoch)
            if id == oprf_key_id && epoch == pending_epoch
    ));

    Ok(())
}
