use std::{str::FromStr, sync::Arc, time::Duration};

use alloy::{network::EthereumWallet, primitives::U160, signers::local::PrivateKeySigner};
use groth16_material::circom::{CircomGroth16Material, CircomGroth16MaterialBuilder};
use nodes_common::{Environment, web3::RpcProviderBuilder};
use oprf_test_utils::{
    DeploySetup, OPRF_PEER_PRIVATE_KEY_0, PEER_ADDRESSES, TestSetup, key_gen_test_secret_manager,
    test_secret_manager::TestSecretManager,
};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    chain::{OprfKeyRegistry, RevertError, Verifier::VerifierErrors},
};

use crate::{
    secret_manager::SecretManagerService,
    services::{
        key_event_watcher::{
            TransactionError, handle_abort, handle_delete, handle_not_enough_producers,
        },
        secret_gen::DLogSecretGenService,
        transaction_handler::TransactionHandler,
    },
};

key_gen_test_secret_manager!(
    crate::secret_manager::SecretManager,
    KeyGenTestSecretManager,
    oprf_types,
    oprf_core::ddlog_equality::shamir::DLogShareShamir
);

const INVALID_PROOF_KEY: usize = 43;
const WRONG_ROUND_LOAD_PEER_PUBLIC_KEYS: usize = 44;

fn key_gen_material(deploy_setup: DeploySetup) -> CircomGroth16Material {
    CircomGroth16MaterialBuilder::new()
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .build_from_paths(deploy_setup.key_gen_path(), deploy_setup.witness_path())
        .expect("Can build key_gen_material")
}

async fn test_config(setup: &TestSetup) -> (CircomGroth16Material, TransactionHandler) {
    let rpc_provider = RpcProviderBuilder::with_default_values(
        vec![setup.anvil.endpoint_url()],
        setup.anvil.ws_endpoint_url(),
    )
    .environment(Environment::Dev)
    .chain_id(31_337)
    .wallet(EthereumWallet::new(
        PrivateKeySigner::from_str(OPRF_PEER_PRIVATE_KEY_0).expect("works"),
    ))
    .build()
    .await
    .expect("can build RPC providers");

    let transaction_handler = TransactionHandler::new(
        Duration::from_secs(10),
        10_000_000,
        1,
        rpc_provider,
        PEER_ADDRESSES[0],
    );

    (key_gen_material(setup.setup), transaction_handler)
}

#[tokio::test]
async fn test_send_invalid_proof() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let (key_gen_material, transaction_handler) = test_config(&setup).await;
    let mut secret_gen = DLogSecretGenService::init(key_gen_material);
    let key_id = U160::from(INVALID_PROOF_KEY);
    secret_gen.key_gen_round1(key_id.into(), 2);
    let error = super::handle_round2(
        OprfKeyId::from(key_id),
        ShareEpoch::from(0u32),
        &OprfKeyRegistry::new(setup.oprf_key_registry, setup.provider.clone()),
        &mut secret_gen,
        &transaction_handler,
    )
    .await
    .expect_err("should fail");
    assert!(matches!(
        error,
        TransactionError::Revert(RevertError::Verifier(VerifierErrors::ProofInvalid(_)))
    ));
    Ok(())
}

#[tokio::test]
async fn test_delete() -> eyre::Result<()> {
    let key_gen_material = key_gen_material(DeploySetup::TwoThree);
    let mut secret_gen = DLogSecretGenService::init(key_gen_material);
    let secret_manager = Arc::new(TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_0));
    let key_gen_secret_manager: SecretManagerService =
        Arc::new(KeyGenTestSecretManager(Arc::clone(&secret_manager)));

    let oprf_key_id = secret_manager.add_random_key_material(&mut rand::thread_rng());
    secret_gen.key_gen_round1(oprf_key_id, 2);

    assert!(secret_gen.has_round1(oprf_key_id));
    secret_manager
        .is_key_id_stored(oprf_key_id, ShareEpoch::default())
        .await
        .expect("Should be able to check key-id");

    handle_delete(oprf_key_id, &mut secret_gen, &key_gen_secret_manager)
        .await
        .expect("Works");

    assert!(!secret_gen.has_round1(oprf_key_id));
    secret_manager
        .is_key_id_not_stored(oprf_key_id)
        .await
        .expect("Should be able to check key-id");

    Ok(())
}

#[tokio::test]
async fn test_round2_in_wrong_round_during_load_public_keys() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let (key_gen_material, transaction_handler) = test_config(&setup).await;
    let mut secret_gen = DLogSecretGenService::init(key_gen_material);
    let key_id = U160::from(WRONG_ROUND_LOAD_PEER_PUBLIC_KEYS);
    secret_gen.key_gen_round1(key_id.into(), 2);
    assert!(!secret_gen.has_round2(OprfKeyId::from(key_id)));
    super::handle_round2(
        OprfKeyId::from(key_id),
        ShareEpoch::from(0u32),
        &OprfKeyRegistry::new(setup.oprf_key_registry, setup.provider.clone()),
        &mut secret_gen,
        &transaction_handler,
    )
    .await
    .expect("Should still work");

    // check that we did consumer round 2
    assert!(secret_gen.has_round2(OprfKeyId::from(key_id)));
    Ok(())
}

#[tokio::test]
async fn test_abort() -> eyre::Result<()> {
    let key_gen_material = key_gen_material(DeploySetup::TwoThree);
    let mut secret_gen = DLogSecretGenService::init(key_gen_material);
    let secret_manager = Arc::new(TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_0));

    let oprf_key_id = secret_manager.add_random_key_material(&mut rand::thread_rng());
    secret_gen.key_gen_round1(oprf_key_id, 2);

    assert!(secret_gen.has_round1(oprf_key_id));
    secret_manager
        .is_key_id_stored(oprf_key_id, ShareEpoch::default())
        .await
        .expect("Should be able to check key-id");

    handle_abort(oprf_key_id, &mut secret_gen);

    assert!(!secret_gen.has_round1(oprf_key_id));
    // still has the key
    secret_manager
        .is_key_id_stored(oprf_key_id, ShareEpoch::default())
        .await
        .expect("Should be able to check key-id");

    Ok(())
}

#[tokio::test]
async fn test_not_enough_producers() -> eyre::Result<()> {
    let key_gen_material = key_gen_material(DeploySetup::TwoThree);
    let mut secret_gen = DLogSecretGenService::init(key_gen_material);
    let secret_manager = Arc::new(TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_0));

    let oprf_key_id = secret_manager.add_random_key_material(&mut rand::thread_rng());
    secret_gen.key_gen_round1(oprf_key_id, 2);

    assert!(secret_gen.has_round1(oprf_key_id));
    secret_manager
        .is_key_id_stored(oprf_key_id, ShareEpoch::default())
        .await
        .expect("Should be able to check key-id");

    handle_not_enough_producers(oprf_key_id, &mut secret_gen);

    assert!(!secret_gen.has_round1(oprf_key_id));
    // still has the key
    secret_manager
        .is_key_id_stored(oprf_key_id, ShareEpoch::default())
        .await
        .expect("Should be able to check key-id");

    Ok(())
}
