#![allow(clippy::large_futures, reason = "doesnt matter for tests")]
use std::time::Duration;

use alloy::{primitives::U160, sol_types::SolEvent};
use eyre::Context as _;
use oprf_key_gen::event_cursor_store::ChainCursorStorage as _;
use oprf_types::{OprfKeyId, ShareEpoch, chain::OprfKeyRegistry};
use taceo_oprf_test_utils::{
    DeploySetup, MineStrategy, OPRF_PEER_ADDRESS_0, TestSetup,
    key_gen_setup::{TestKeyGen, keygen_asserts},
    test_timeout, wait_until_started,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delete_oprf_key() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::TwoThree, MineStrategy::Interval(1)).await?;
    let key_gen = TestKeyGen::start(0, &setup).await?;

    let inserted_key = key_gen
        .add_random_key_material(&mut rand::thread_rng())
        .await?;
    assert!(key_gen.has_key_material(inserted_key).await?, "we added it");
    setup.delete_oprf_key(inserted_key).await?;

    key_gen.is_key_id_not_stored(inserted_key).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_keygen_works_two_three() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::TwoThree, MineStrategy::Interval(1)).await?;
    let key_gens = TestKeyGen::start_three(&setup).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    setup.init_keygen(oprf_key_id).await?;
    let _oprf_public_key =
        keygen_asserts::all_have_key(&key_gens, oprf_key_id, ShareEpoch::default()).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_keygen_works_when_init_before_start() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::TwoThree, MineStrategy::Interval(1)).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    setup.init_keygen(oprf_key_id).await?;
    let key_gens = TestKeyGen::start_three(&setup).await?;
    let _oprf_public_key =
        keygen_asserts::all_have_key(&key_gens, oprf_key_id, ShareEpoch::default()).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_keygen_works_when_crashing_in_between() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::TwoThree, MineStrategy::Interval(1)).await?;
    // start only two key-gens so that we don't go over round 1
    let (keygen0, keygen1) =
        tokio::join!(TestKeyGen::start(0, &setup), TestKeyGen::start(1, &setup));
    // init a key-gen and wait for the two KeyGenConfirmations
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let round1_confirmations = setup
        .expect_event(OprfKeyRegistry::KeyGenConfirmation::SIGNATURE_HASH, 2)
        .await?;
    setup.init_keygen(oprf_key_id).await?;
    round1_confirmations.await?;
    // cancel the key-gens
    let keygen0 = keygen0?;
    let keygen1 = keygen1?;

    let (keygen0_restart, keygen1_restart) =
        tokio::join!(keygen0.restart(&setup), keygen1.restart(&setup));

    // start the third one
    let keygen2 = TestKeyGen::start(2, &setup).await;

    let key_gens = [keygen0_restart?, keygen1_restart?, keygen2?];
    let _oprf_public_key =
        keygen_asserts::all_have_key(&key_gens, oprf_key_id, ShareEpoch::default()).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 5)]
async fn test_keygen_works_three_five() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::ThreeFive, MineStrategy::Interval(1)).await?;
    let key_gens = TestKeyGen::start_five(&setup).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    setup.init_keygen(oprf_key_id).await?;
    let _oprf_public_key =
        keygen_asserts::all_have_key(&key_gens, oprf_key_id, ShareEpoch::default()).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_reshare_five_times_works_two_three() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::TwoThree, MineStrategy::Interval(1)).await?;
    let key_gens = TestKeyGen::start_three(&setup).await?;
    test_reshare_five_times_works_inner(&setup, &key_gens).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 5)]
async fn test_reshare_five_times_works_three_five() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::ThreeFive, MineStrategy::Interval(1)).await?;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_reshare_with_consumer_two_three() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::TwoThree, MineStrategy::Interval(1)).await?;
    let key_gens = TestKeyGen::start_three(&setup).await?;
    test_reshare_with_consumer_inner(&setup, &key_gens, 1).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 5)]
async fn test_reshare_with_consumer_three_five() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::ThreeFive, MineStrategy::Interval(1)).await?;
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

    for party in 0..5 {
        for i in 0..consumer {
            key_gens[(party + i) % key_gens.len()].clear().await?;
        }
        epoch = epoch.next();
        setup.init_reshare(oprf_key_id).await?;
        let oprf_public_key_reshare =
            keygen_asserts::all_have_key(key_gens, oprf_key_id, epoch).await?;
        assert_eq!(oprf_public_key_reshare, oprf_public_key_key_gen);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_reshare_emits_stuck_if_two_consumer() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::TwoThree, MineStrategy::Interval(1)).await?;
    let key_gens = TestKeyGen::start_three(&setup).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    setup.init_keygen(oprf_key_id).await?;
    let epoch = ShareEpoch::default();
    let _oprf_public_key_key_gen =
        keygen_asserts::all_have_key(&key_gens, oprf_key_id, epoch).await?;

    key_gens[0].clear().await?;
    key_gens[1].clear().await?;

    let signal = setup
        .expect_event(OprfKeyRegistry::NotEnoughProducers::SIGNATURE_HASH, 1)
        .await?;
    setup.init_reshare(oprf_key_id).await?;
    signal.await.expect("Should receive signal");
    Ok(())
}

/// Merges the not-a-participant and invalid-threshold sanity check failures against one setup,
/// saving an anvil + contract deployment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_start_sanity_checks() -> eyre::Result<()> {
    let mut setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let is_error = TestKeyGen::start(4, &setup).await.expect_err("Should fail");
    assert_eq!(is_error.to_string(), "while doing sanity checks");

    setup.setup = DeploySetup::ThreeFive;
    let is_error = TestKeyGen::start(0, &setup).await.expect_err("Should fail");
    assert_eq!(is_error.to_string(), "while doing sanity checks");
    Ok(())
}

/// Covers the `/health`, `/wallet` and `/version` routes against one key-gen.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_service_routes() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::TwoThree, MineStrategy::Interval(1)).await?;
    let key_gen = TestKeyGen::start(0, &setup).await?;
    wait_until_started(&key_gen.started_services).await?;

    let result = key_gen.server.get("/health").expect_success().await;
    result.assert_status_ok();
    result.assert_text("healthy");

    let result = key_gen.server.get("/wallet").expect_success().await;
    result.assert_status_ok();
    result.assert_text(OPRF_PEER_ADDRESS_0.to_string());

    let result = key_gen.server.get("/version").expect_success().await;
    result.assert_status_ok();
    let is_text = result.text();
    assert!(is_text.starts_with("taceo-oprf-key-gen"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_health_route_not_ready() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let key_gen = TestKeyGen::start(0, &setup).await?;
    let _not_started_service = key_gen.started_services.new_service();
    let result = key_gen.server.get("/health").expect_failure().await;
    result.assert_status_service_unavailable();
    result.assert_text("starting");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_gen_dies_on_cancellation() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::TwoThree, MineStrategy::Interval(1)).await?;
    let key_gen = TestKeyGen::start(0, &setup).await?;
    key_gen.cancellation_token.cancel();
    tokio::time::timeout(test_timeout(), key_gen.key_gen_task.join())
        .await
        .expect("Can shutdown in time")
        .expect("Was a graceful shutdown");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_keygen_works_when_all_three_crash() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::TwoThree, MineStrategy::Interval(1)).await?;
    let (keygen0, keygen1, keygen2) = tokio::join!(
        TestKeyGen::start(0, &setup),
        TestKeyGen::start(1, &setup),
        TestKeyGen::start(2, &setup)
    );
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let round1_done = setup
        .expect_event(OprfKeyRegistry::KeyGenConfirmation::SIGNATURE_HASH, 2)
        .await?;
    setup.init_keygen(oprf_key_id).await?;
    round1_done.await?;
    let (r0, r1, r2) = tokio::join!(
        keygen0?.restart(&setup),
        keygen1?.restart(&setup),
        keygen2?.restart(&setup),
    );
    let key_gens = [r0?, r1?, r2?];
    keygen_asserts::all_have_key(&key_gens, oprf_key_id, ShareEpoch::default()).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_keygen_replays_deletion_via_backfill() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::TwoThree, MineStrategy::Interval(1)).await?;
    let key_gens = TestKeyGen::start_three(&setup).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    setup.init_keygen(oprf_key_id).await?;
    keygen_asserts::all_have_key(&key_gens, oprf_key_id, ShareEpoch::default()).await?;

    let [keygen0, _, _] = key_gens;
    let (party_id, pool, secret_manager) = keygen0.shutdown().await?;

    setup.delete_oprf_key(oprf_key_id).await?;

    let keygen0 =
        TestKeyGen::start_with_secret_manager(party_id, &setup, secret_manager, pool).await?;
    keygen0.is_key_id_not_stored(oprf_key_id).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_reshare_replayed_via_backfill() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::TwoThree, MineStrategy::Interval(1)).await?;
    let key_gens = TestKeyGen::start_three(&setup).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    setup.init_keygen(oprf_key_id).await?;
    keygen_asserts::all_have_key(&key_gens, oprf_key_id, ShareEpoch::default()).await?;

    let [keygen0, keygen1, keygen2] = key_gens;
    let (party_id, pool, secret_manager) = keygen0.shutdown().await?;

    let epoch1 = ShareEpoch::default().next();
    setup.init_reshare(oprf_key_id).await?;

    let keygen0 =
        TestKeyGen::start_with_secret_manager(party_id, &setup, secret_manager, pool).await?;

    keygen_asserts::all_have_key(&[keygen0, keygen1, keygen2], oprf_key_id, epoch1).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cursor_checkpoint_persists() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::TwoThree, MineStrategy::Interval(1)).await?;
    let key_gen = TestKeyGen::start(0, &setup).await?;

    let cursor_service = key_gen.secret_manager.clone();
    tokio::time::timeout(test_timeout(), async {
        loop {
            if cursor_service.load_chain_cursor().await?.block() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        eyre::Ok(())
    })
    .await
    .context("while waiting for cursor-service to store checkpoint")??;
    Ok(())
}
