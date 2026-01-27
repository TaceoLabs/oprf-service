use alloy::{primitives::U160, sol_types::SolEvent};
use oprf_test_utils::{DeploySetup, TestSetup};
use oprf_types::{OprfKeyId, ShareEpoch, chain::OprfKeyRegistry};

mod setup;

pub(crate) use setup::TestKeyGen;

use crate::setup::keygen_asserts;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_delete_oprf_key() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let key_gen = TestKeyGen::start(0, &setup).await?;

    let inserted_key = key_gen
        .secret_manager
        .add_random_key_material(&mut rand::thread_rng());
    assert!(
        key_gen
            .secret_manager
            .get_key_material(inserted_key)
            .is_some(),
        "we added it"
    );
    setup.delete_oprf_key(inserted_key).await?;

    key_gen
        .secret_manager
        .is_key_id_not_stored(inserted_key)
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_keygen_works_two_three() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let key_gens = TestKeyGen::start_three(&setup).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    setup.init_keygen(oprf_key_id).await?;
    let _oprf_public_key =
        keygen_asserts::all_have_key(&key_gens, oprf_key_id, ShareEpoch::default()).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_keygen_works_three_five() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::ThreeFive).await?;
    let key_gens = TestKeyGen::start_five(&setup).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    setup.init_keygen(oprf_key_id).await?;
    let _oprf_public_key =
        keygen_asserts::all_have_key(&key_gens, oprf_key_id, ShareEpoch::default()).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_reshare_five_times_works_two_three() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let key_gens = TestKeyGen::start_three(&setup).await?;
    test_reshare_five_times_works_inner(&setup, &key_gens).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_reshare_five_times_works_three_five() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::ThreeFive).await?;
    let key_gens = TestKeyGen::start_five(&setup).await?;
    test_reshare_five_times_works_inner(&setup, &key_gens).await
}

async fn test_reshare_five_times_works_inner(
    setup: &TestSetup,
    key_gens: &[TestKeyGen],
) -> eyre::Result<()> {
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    setup.init_keygen(oprf_key_id).await?;
    let mut epoch = ShareEpoch::default();
    let oprf_public_key_key_gen =
        keygen_asserts::all_have_key(key_gens, oprf_key_id, epoch).await?;
    for _ in 0..5 {
        epoch = epoch.next();
        setup.init_reshare(oprf_key_id).await?;
        let oprf_public_key_reshare =
            keygen_asserts::all_have_key(key_gens, oprf_key_id, epoch).await?;
        assert_eq!(oprf_public_key_reshare, oprf_public_key_key_gen);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_reshare_with_consumer_two_three() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let key_gens = TestKeyGen::start_three(&setup).await?;
    test_reshare_with_consumer_inner(&setup, &key_gens, 1).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_reshare_with_consumer_three_five() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::ThreeFive).await?;
    let key_gens = TestKeyGen::start_five(&setup).await?;
    test_reshare_with_consumer_inner(&setup, &key_gens, 2).await
}

async fn test_reshare_with_consumer_inner(
    setup: &TestSetup,
    key_gens: &[TestKeyGen],
    consumer: usize,
) -> eyre::Result<()> {
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    setup.init_keygen(oprf_key_id).await?;
    let mut epoch = ShareEpoch::default();
    let oprf_public_key_key_gen =
        keygen_asserts::all_have_key(key_gens, oprf_key_id, epoch).await?;

    // init reshare shall work even if we reset the secret manager from a random party
    for party in 0..5 {
        // now reset the secret manager from key-gen 2
        for i in 0..consumer {
            key_gens[(party + i) % key_gens.len()]
                .secret_manager
                .clear();
        }
        epoch = epoch.next();
        setup.init_reshare(oprf_key_id).await?;
        let oprf_public_key_reshare =
            keygen_asserts::all_have_key(key_gens, oprf_key_id, epoch).await?;
        assert_eq!(oprf_public_key_reshare, oprf_public_key_key_gen);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_reshare_emits_stuck_if_two_consumer() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let key_gens = TestKeyGen::start_three(&setup).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    setup.init_keygen(oprf_key_id).await?;
    let mut epoch = ShareEpoch::default();
    let oprf_public_key_key_gen =
        keygen_asserts::all_have_key(&key_gens, oprf_key_id, epoch).await?;

    // we clear one secret manager completely and one we simply take the shares
    let secret_manager0 = key_gens[0].secret_manager.take();
    key_gens[1].secret_manager.clear();

    let signal = setup
        .expect_event(OprfKeyRegistry::NotEnoughProducers::SIGNATURE_HASH)
        .await?;
    setup.init_reshare(oprf_key_id).await?;
    assert!(signal.await.is_ok());
    // abort and restart
    setup.abort_keygen(oprf_key_id).await?;
    // restore secret manager for 0
    key_gens[0].secret_manager.put(secret_manager0);
    // now reshare should work
    epoch = epoch.next();
    setup.init_reshare(oprf_key_id).await?;
    let oprf_public_key_reshare =
        keygen_asserts::all_have_key(&key_gens, oprf_key_id, epoch).await?;
    assert_eq!(oprf_public_key_reshare, oprf_public_key_key_gen);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_not_a_participant() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    // for this setup this node is not registered
    TestKeyGen::start_with_error(4, &setup)
        .await?
        .has_err("while loading party id")
        .await;
    Ok(())
}
