#![allow(clippy::large_futures, reason = "doesnt matter for tests")]
use std::fmt;
use std::num::NonZeroUsize;
use std::time::Duration;

use alloy::{primitives::U160, sol_types::SolEvent};
use axum_test::TestServer;
use eyre::Context as _;
use nodes_common::web3::HttpRpcProviderConfig;
use nodes_common::web3::event_stream::{ChainCursor, SkipBackfill};
use nodes_common::{Environment, StartedServices};
use oprf_test_utils::{
    DeploySetup, MineStrategy, OPRF_PEER_ADDRESS_0, PEER_PRIVATE_KEYS, TestSetup,
};

use oprf_test_utils::TEST_TIMEOUT;
use oprf_types::{OprfKeyId, ShareEpoch, chain::OprfKeyRegistry};
use tokio_util::sync::CancellationToken;

use crate::services::event_cursor_store::ChainCursorStorage;
use crate::tests::keygen_test_secret_manager::TestChainCursorService;
use crate::{
    KeyGenTasks,
    config::{OprfKeyGenServiceConfig, OprfKeyGenServiceConfigMandatoryValues},
    start,
    tests::keygen_test_secret_manager::TestKeyGenSecretManager,
};

pub(crate) mod keygen_test_secret_manager;

pub(crate) struct TestKeyGen {
    pub(crate) party_id: usize,
    pub(crate) secret_manager: TestKeyGenSecretManager,
    pub(crate) server: TestServer,
    pub(crate) key_gen_task: KeyGenTasks,
    pub(crate) started_services: StartedServices,
    pub(crate) cursor_service: TestChainCursorService,
    pub(crate) cancellation_token: CancellationToken,
}

pub(crate) struct TestKeyGenBuilder<'a> {
    party_id: usize,
    test_setup: &'a TestSetup,
    secret_manager: Option<TestKeyGenSecretManager>,
    skip_backfill: SkipBackfill,
    cursor_service: TestChainCursorService,
    cursor_checkpoint_interval: Option<Duration>,
}

impl<'a> TestKeyGenBuilder<'a> {
    pub(crate) fn new(party_id: usize, test_setup: &'a TestSetup) -> Self {
        Self {
            party_id,
            test_setup,
            secret_manager: None,
            skip_backfill: SkipBackfill::Yes,
            cursor_service: TestChainCursorService::default(),
            cursor_checkpoint_interval: None,
        }
    }

    pub(crate) fn secret_manager(mut self, secret_manager: TestKeyGenSecretManager) -> Self {
        self.secret_manager = Some(secret_manager);
        self
    }

    pub(crate) fn skip_backfill(mut self, skip_backfill: SkipBackfill) -> Self {
        self.skip_backfill = skip_backfill;
        self
    }

    pub(crate) fn cursor_service(mut self, cursor_service: TestChainCursorService) -> Self {
        self.cursor_service = cursor_service;
        self
    }

    pub(crate) fn starting_cursor(mut self, cursor: ChainCursor) -> Self {
        self.cursor_service = TestChainCursorService::with_cursor(cursor);
        self
    }

    pub(crate) fn cursor_checkpoint_interval(mut self, interval: Duration) -> Self {
        self.cursor_checkpoint_interval = Some(interval);
        self
    }

    pub(crate) async fn build(self) -> eyre::Result<TestKeyGen> {
        TestKeyGen::start_inner(
            self.party_id,
            self.test_setup,
            self.skip_backfill,
            self.secret_manager
                .unwrap_or_else(|| TestKeyGenSecretManager::new(PEER_PRIVATE_KEYS[self.party_id])),
            self.cursor_service,
            self.cursor_checkpoint_interval,
        )
        .await
    }
}

impl fmt::Debug for TestKeyGen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestKeyGen")
            .field("party_id", &self.party_id)
            .finish_non_exhaustive()
    }
}

impl TestKeyGen {
    async fn start_inner(
        party_id: usize,
        test_setup: &TestSetup,
        skip_backfill: SkipBackfill,
        secret_manager: TestKeyGenSecretManager,
        cursor_service: TestChainCursorService,
        cursor_checkpoint_interval: Option<Duration>,
    ) -> eyre::Result<Self> {
        let TestSetup {
            anvil,
            oprf_key_registry,
            cancellation_token,
            setup,
            ..
        } = test_setup;

        assert!(party_id < 5, "can only spawn 5 key-gens");
        let private_key = PEER_PRIVATE_KEYS[party_id];
        let child_token = cancellation_token.child_token();
        let (expected_threshold, expected_num_peers) = match test_setup.setup {
            DeploySetup::TwoThree => (2, 3),
            DeploySetup::ThreeFive => (3, 5),
        };

        let mut config =
            OprfKeyGenServiceConfig::with_default_values(OprfKeyGenServiceConfigMandatoryValues {
                environment: Environment::Dev,
                oprf_key_registry_contract: *oprf_key_registry,
                wallet_private_key: private_key.into(),
                zkey_path: setup.key_gen_path(),
                witness_graph_path: setup.witness_path(),
                expected_threshold: expected_threshold.try_into().expect("Is non-zero"),
                expected_num_peers: expected_num_peers.try_into().expect("Is non-zero"),
                rpc_provider_config: HttpRpcProviderConfig::with_default_values(vec![
                    anvil.endpoint_url(),
                ]),
                ws_rpc_url: anvil.ws_endpoint_url(),
            });

        config.confirmations_for_transaction = 0;
        config.rpc_provider_config.chain_id = Some(31_337);
        config.event_stream_config.skip_backfill = skip_backfill;
        config.event_stream_config.confirmations_after_sync_block =
            NonZeroUsize::try_from(2).expect("2 is non-zero");
        if let Some(interval) = cursor_checkpoint_interval {
            config.cursor_checkpoint_interval = interval;
        }

        let started_services = StartedServices::new();
        let (router, key_gen_task) = start(
            config,
            secret_manager.service(),
            cursor_service.service(),
            started_services.clone(),
            child_token.clone(),
        )
        .await?;
        let server = TestServer::builder()
            .http_transport()
            .build(router)
            .expect("can build test-server");
        Ok(Self {
            party_id,
            secret_manager,
            server,
            key_gen_task,
            cursor_service,
            started_services,
            cancellation_token: child_token,
        })
    }

    pub(crate) async fn start(party_id: usize, test_setup: &TestSetup) -> eyre::Result<Self> {
        TestKeyGenBuilder::new(party_id, test_setup).build().await
    }

    pub(crate) async fn start_three_with_backfill(
        test_setup: &TestSetup,
    ) -> eyre::Result<[Self; 3]> {
        let starting_cursor = ChainCursor::new(0, 1);
        let (keygen0, keygen1, keygen2) = tokio::join!(
            TestKeyGenBuilder::new(0, test_setup)
                .skip_backfill(SkipBackfill::No)
                .starting_cursor(starting_cursor)
                .build(),
            TestKeyGenBuilder::new(1, test_setup)
                .skip_backfill(SkipBackfill::No)
                .starting_cursor(starting_cursor)
                .build(),
            TestKeyGenBuilder::new(2, test_setup)
                .skip_backfill(SkipBackfill::No)
                .starting_cursor(starting_cursor)
                .build(),
        );
        Ok([keygen0?, keygen1?, keygen2?])
    }

    pub(crate) async fn start_three(test_setup: &TestSetup) -> eyre::Result<[Self; 3]> {
        let (keygen0, keygen1, keygen2) = tokio::join!(
            Self::start(0, test_setup),
            Self::start(1, test_setup),
            Self::start(2, test_setup)
        );
        Ok([keygen0?, keygen1?, keygen2?])
    }

    pub(crate) async fn start_five(test_setup: &TestSetup) -> eyre::Result<[Self; 5]> {
        let (keygen0, keygen1, keygen2, keygen3, keygen4) = tokio::join!(
            Self::start(0, test_setup),
            Self::start(1, test_setup),
            Self::start(2, test_setup),
            Self::start(3, test_setup),
            Self::start(4, test_setup)
        );
        Ok([keygen0?, keygen1?, keygen2?, keygen3?, keygen4?])
    }

    pub(crate) async fn shutdown(
        self,
    ) -> eyre::Result<(usize, TestKeyGenSecretManager, TestChainCursorService)> {
        let fut = async move {
            self.cancellation_token.cancel();
            self.key_gen_task.join().await?;
            Ok((self.party_id, self.secret_manager, self.cursor_service))
        };
        tokio::time::timeout(TEST_TIMEOUT, fut)
            .await
            .context("Cannot shutdown in time")?
    }

    pub(crate) async fn restart(self, test_setup: &TestSetup) -> eyre::Result<TestKeyGen> {
        let restart_fut = async {
            self.cancellation_token.cancel();
            self.key_gen_task.join().await?;
            TestKeyGenBuilder::new(self.party_id, test_setup)
                .skip_backfill(SkipBackfill::No)
                .secret_manager(self.secret_manager)
                .cursor_service(self.cursor_service)
                .build()
                .await
        };
        tokio::time::timeout(TEST_TIMEOUT, restart_fut)
            .await
            .context("Cannot restart in time")?
    }
}

pub(crate) mod keygen_asserts {
    use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
    use tokio::task::JoinSet;

    use super::TestKeyGen;

    pub(crate) async fn all_have_key(
        instances: &[TestKeyGen],
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> eyre::Result<OprfPublicKey> {
        let mut keys = instances
            .iter()
            .map(|instance| {
                let secret_manager = instance.secret_manager.clone();
                async move { secret_manager.is_key_id_stored(oprf_key_id, epoch).await }
            })
            .collect::<JoinSet<_>>()
            .join_all()
            .await
            .into_iter()
            .collect::<eyre::Result<Vec<_>>>()?;
        assert_eq!(keys.len(), instances.len());
        let oprf_public_key = keys.pop().expect("is there");
        assert!(keys.into_iter().all(|key| key == oprf_public_key));
        Ok(oprf_public_key)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_keygen_works_two_three() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
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
    let key_gens = TestKeyGen::start_three_with_backfill(&setup).await?;
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
    let keygen2 = TestKeyGenBuilder::new(2, &setup)
        .skip_backfill(SkipBackfill::No)
        .starting_cursor(ChainCursor::new(0, 1))
        .build()
        .await;

    let key_gens = [keygen0_restart?, keygen1_restart?, keygen2?];
    let _oprf_public_key =
        keygen_asserts::all_have_key(&key_gens, oprf_key_id, ShareEpoch::default()).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 5)]
async fn test_keygen_works_three_five() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::ThreeFive).await?;
    let key_gens = TestKeyGen::start_five(&setup).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    setup.init_keygen(oprf_key_id).await?;
    let _oprf_public_key =
        keygen_asserts::all_have_key(&key_gens, oprf_key_id, ShareEpoch::default()).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_reshare_five_times_works_two_three() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let key_gens = TestKeyGen::start_three(&setup).await?;
    test_reshare_five_times_works_inner(&setup, &key_gens).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 5)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_reshare_with_consumer_two_three() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let key_gens = TestKeyGen::start_three(&setup).await?;
    test_reshare_with_consumer_inner(&setup, &key_gens, 1).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 5)]
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

    for party in 0..5 {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_reshare_emits_stuck_if_two_consumer() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let key_gens = TestKeyGen::start_three(&setup).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    setup.init_keygen(oprf_key_id).await?;
    let mut epoch = ShareEpoch::default();
    let oprf_public_key_key_gen =
        keygen_asserts::all_have_key(&key_gens, oprf_key_id, epoch).await?;

    let secret_manager0 = key_gens[0].secret_manager.take();
    key_gens[1].secret_manager.clear();

    let signal = setup
        .expect_event(OprfKeyRegistry::NotEnoughProducers::SIGNATURE_HASH, 1)
        .await?;
    setup.init_reshare(oprf_key_id).await?;
    signal.await.expect("Should receive signal");
    setup.abort_keygen(oprf_key_id).await?;
    key_gens[0].secret_manager.put(secret_manager0);

    epoch = epoch.next();
    setup.init_reshare(oprf_key_id).await?;
    let oprf_public_key_reshare =
        keygen_asserts::all_have_key(&key_gens, oprf_key_id, epoch).await?;
    assert_eq!(oprf_public_key_reshare, oprf_public_key_key_gen);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_not_a_participant() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let is_error = TestKeyGen::start(4, &setup).await.expect_err("Should fail");
    assert_eq!(is_error.to_string(), "while doing sanity checks");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_invalid_threshold() -> eyre::Result<()> {
    let mut setup = TestSetup::new(DeploySetup::TwoThree).await?;
    setup.setup = DeploySetup::ThreeFive;
    let is_error = TestKeyGen::start(0, &setup).await.expect_err("Should fail");
    assert_eq!(is_error.to_string(), "while doing sanity checks");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_health_route() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let key_gen = TestKeyGen::start(0, &setup).await?;
    let started_services = key_gen.started_services.clone();
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if started_services.all_started() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    let result = key_gen.server.get("/health").expect_success().await;
    result.assert_status_ok();
    result.assert_text("healthy");
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
async fn test_wallet() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let key_gen = TestKeyGen::start(0, &setup).await?;
    let result = key_gen.server.get("/wallet").expect_success().await;
    result.assert_status_ok();
    result.assert_text(OPRF_PEER_ADDRESS_0.to_string());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_version() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let key_gen = TestKeyGen::start(0, &setup).await?;
    let result = key_gen.server.get("/version").expect_success().await;
    result.assert_status_ok();
    result.assert_text(nodes_common::version_info!());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_gen_dies_on_cancellation() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let key_gen = TestKeyGen::start(0, &setup).await?;
    key_gen.cancellation_token.cancel();
    tokio::time::timeout(TEST_TIMEOUT, key_gen.key_gen_task.join())
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
    let (party_id, secret_manager, cursor_service) = keygen0.shutdown().await?;

    setup.delete_oprf_key(oprf_key_id).await?;

    let keygen0 = TestKeyGenBuilder::new(party_id, &setup)
        .skip_backfill(SkipBackfill::No)
        .secret_manager(secret_manager)
        .cursor_service(cursor_service)
        .build()
        .await?;
    keygen0
        .secret_manager
        .is_key_id_not_stored(oprf_key_id)
        .await?;
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
    let (party_id, secret_manager, cursor_service) = keygen0.shutdown().await?;

    let epoch1 = ShareEpoch::default().next();
    setup.init_reshare(oprf_key_id).await?;

    let keygen0 = TestKeyGenBuilder::new(party_id, &setup)
        .skip_backfill(SkipBackfill::No)
        .secret_manager(secret_manager)
        .cursor_service(cursor_service)
        .build()
        .await?;

    keygen_asserts::all_have_key(&[keygen0, keygen1, keygen2], oprf_key_id, epoch1).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cursor_checkpoint_persists() -> eyre::Result<()> {
    let setup =
        TestSetup::with_mine_strategy(DeploySetup::TwoThree, MineStrategy::Interval(1)).await?;
    let key_gen = TestKeyGenBuilder::new(0, &setup)
        .cursor_checkpoint_interval(Duration::from_millis(100))
        .build()
        .await?;

    let cursor_service = key_gen.cursor_service.clone();
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if cursor_service.load_chain_cursor().await?.block() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        eyre::Ok(())
    })
    .await
    .context("while waiting for cursor-service to store checkpoint")??;
    Ok(())
}
