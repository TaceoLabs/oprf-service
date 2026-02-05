use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use alloy::primitives::U160;
use groth16_material::circom::{CircomGroth16Material, CircomGroth16MaterialBuilder};
use oprf_test_utils::{
    DeploySetup, OPRF_PEER_PRIVATE_KEY_0, PEER_ADDRESSES, TestSetup, key_gen_test_secret_manager,
    test_secret_manager::TestSecretManager,
};
use oprf_types::{
    ShareEpoch,
    chain::{OprfKeyRegistry, RevertError, Verifier::VerifierErrors},
    crypto::PartyId,
};

use crate::{
    secret_manager::SecretManagerService,
    services::{
        key_event_watcher::{
            TransactionError, handle_abort, handle_delete, handle_not_enough_producers,
        },
        secret_gen::DLogSecretGenService,
        transaction_handler::{TransactionHandler, TransactionHandlerInitArgs},
    },
};

key_gen_test_secret_manager!(
    crate::secret_manager::SecretManager,
    KeyGenTestSecretManager
);

const INVALID_PROOF_KEY: usize = 43;

fn key_gen_material(deploy_setup: DeploySetup) -> CircomGroth16Material {
    CircomGroth16MaterialBuilder::new()
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .build_from_paths(deploy_setup.key_gen_path(), deploy_setup.witness_path())
        .expect("Can build key_gen_material")
}

async fn test_config(setup: &TestSetup) -> (CircomGroth16Material, TransactionHandler) {
    let party_id = PartyId(0);

    let (transaction_handler, _) = TransactionHandler::new(TransactionHandlerInitArgs {
        max_wait_time: Duration::from_secs(10),
        max_gas_per_transaction: 10_000_000,
        confirmations_for_transaction: 1,
        attempts: 3,
        party_id,
        contract_address: setup.oprf_key_registry,
        provider: setup.provider.clone(),
        wallet_address: PEER_ADDRESSES[0],
        start_signal: Arc::new(AtomicBool::new(false)),
        cancellation_token: setup.cancellation_token.child_token(),
    })
    .await
    .expect("while spawning transaction handler");

    (key_gen_material(setup.setup), transaction_handler)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_send_invalid_proof() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let (key_gen_material, transaction_handler) = test_config(&setup).await;
    let mut secret_gen = DLogSecretGenService::init(key_gen_material);
    let key_id = U160::from(INVALID_PROOF_KEY);
    secret_gen.key_gen_round1(key_id.into(), 2);
    let error = super::handle_round2(
        PartyId(0),
        OprfKeyRegistry::SecretGenRound2 {
            oprfKeyId: key_id,
            epoch: 0,
        },
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

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_delete() -> eyre::Result<()> {
    let key_gen_material = key_gen_material(DeploySetup::TwoThree);
    let mut secret_gen = DLogSecretGenService::init(key_gen_material);
    let secret_manager = Arc::new(TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_0));
    let key_gen_secret_manager: SecretManagerService =
        Arc::new(KeyGenTestSecretManager(Arc::clone(&secret_manager)));

    let oprf_key_id = secret_manager.add_random_key_material(&mut rand::thread_rng());
    secret_gen.key_gen_round1(oprf_key_id, 2);

    assert!(secret_gen.has_round1(oprf_key_id));
    assert!(
        secret_manager
            .is_key_id_stored(oprf_key_id, ShareEpoch::default())
            .await
            .is_ok()
    );

    let event = OprfKeyRegistry::KeyDeletion {
        oprfKeyId: oprf_key_id.into_inner(),
    };

    handle_delete(event, &mut secret_gen, &key_gen_secret_manager)
        .await
        .expect("Works");

    assert!(!secret_gen.has_round1(oprf_key_id));
    assert!(
        secret_manager
            .is_key_id_not_stored(oprf_key_id)
            .await
            .is_ok()
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_abort() -> eyre::Result<()> {
    let key_gen_material = key_gen_material(DeploySetup::TwoThree);
    let mut secret_gen = DLogSecretGenService::init(key_gen_material);
    let secret_manager = Arc::new(TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_0));

    let oprf_key_id = secret_manager.add_random_key_material(&mut rand::thread_rng());
    secret_gen.key_gen_round1(oprf_key_id, 2);

    assert!(secret_gen.has_round1(oprf_key_id));
    assert!(
        secret_manager
            .is_key_id_stored(oprf_key_id, ShareEpoch::default())
            .await
            .is_ok()
    );

    let event = OprfKeyRegistry::KeyGenAbort {
        oprfKeyId: oprf_key_id.into_inner(),
    };

    handle_abort(event, &mut secret_gen).await;

    assert!(!secret_gen.has_round1(oprf_key_id));
    // still has the key
    assert!(
        secret_manager
            .is_key_id_stored(oprf_key_id, ShareEpoch::default())
            .await
            .is_ok()
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_not_enough_producers() -> eyre::Result<()> {
    let key_gen_material = key_gen_material(DeploySetup::TwoThree);
    let mut secret_gen = DLogSecretGenService::init(key_gen_material);
    let secret_manager = Arc::new(TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_0));

    let oprf_key_id = secret_manager.add_random_key_material(&mut rand::thread_rng());
    secret_gen.key_gen_round1(oprf_key_id, 2);

    assert!(secret_gen.has_round1(oprf_key_id));
    assert!(
        secret_manager
            .is_key_id_stored(oprf_key_id, ShareEpoch::default())
            .await
            .is_ok()
    );

    let event = OprfKeyRegistry::NotEnoughProducers {
        oprfKeyId: oprf_key_id.into_inner(),
    };

    handle_not_enough_producers(event, &mut secret_gen).await;

    assert!(!secret_gen.has_round1(oprf_key_id));
    // still has the key
    assert!(
        secret_manager
            .is_key_id_stored(oprf_key_id, ShareEpoch::default())
            .await
            .is_ok()
    );

    Ok(())
}
