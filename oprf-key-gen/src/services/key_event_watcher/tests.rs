use std::time::Duration;

use alloy::primitives::U160;
use groth16_material::circom::{CircomGroth16Material, CircomGroth16MaterialBuilder};
use oprf_test_utils::{DeploySetup, PEER_ADDRESSES, TestSetup};
use oprf_types::{
    chain::{OprfKeyRegistry, RevertError, Verifier::VerifierErrors},
    crypto::PartyId,
};

use crate::services::{
    key_event_watcher::TransactionError,
    secret_gen::DLogSecretGenService,
    transaction_handler::{TransactionHandler, TransactionHandlerInitArgs},
};

const INVALID_PROOF_KEY: usize = 43;

async fn test_config(setup: &TestSetup) -> (CircomGroth16Material, TransactionHandler) {
    let key_gen_material = CircomGroth16MaterialBuilder::new()
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .build_from_paths(setup.setup.key_gen_path(), setup.setup.witness_path())
        .expect("Can build key_gen_material");

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
        cancellation_token: setup.cancellation_token.child_token(),
    })
    .await
    .expect("while spawning transaction handler");

    (key_gen_material, transaction_handler)
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
