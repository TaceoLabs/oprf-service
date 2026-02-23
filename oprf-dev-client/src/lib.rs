use std::{
    collections::HashMap,
    str::FromStr as _,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U160},
    providers::{DynProvider, Provider as _, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use eyre::Context;
use oprf_client::{Connector, OprfSessions};
use oprf_core::{
    ddlog_equality::shamir::{DLogCommitmentsShamir, DLogProofShareShamir},
    oprf::BlindedOprfRequest,
};
use oprf_test_utils::health_checks;
use oprf_types::{OprfKeyId, ShareEpoch, api::OprfRequest, crypto::OprfPublicKey};
use rand::{CryptoRng, Rng, SeedableRng};
use rustls::{ClientConfig, RootCertStore};
use secrecy::ExposeSecret as _;
use serde::Serialize;
use tokio::{sync::mpsc, task::JoinSet};
use uuid::Uuid;

pub use oprf_test_utils;

pub(crate) mod config;
pub use config::*;
pub use oprf_types::async_trait;

#[async_trait::async_trait]
pub trait DevClient: Send + Sync + 'static {
    type Setup: Send + Sync + 'static + Clone;
    type RequestAuth: Clone + Serialize + Send + 'static;

    async fn setup_oprf_test(
        &self,
        config: &DevClientConfig,
        provider: DynProvider,
    ) -> eyre::Result<Self::Setup>;

    async fn run_oprf(
        &self,
        config: &DevClientConfig,
        setup: Self::Setup,
        connector: Connector,
    ) -> eyre::Result<ShareEpoch>;

    async fn prepare_stress_test_item<R: Rng + CryptoRng + Send>(
        &self,
        setup: &Self::Setup,
        rng: &mut R,
    ) -> eyre::Result<StressTestItem<Self::RequestAuth>>;

    fn get_oprf_key(&self, setup: &Self::Setup) -> OprfPublicKey;
    fn get_oprf_key_id(&self, setup: &Self::Setup) -> OprfKeyId;
    fn auth_module(&self) -> String;
}

pub struct StressTestItem<OprfRequestAuth> {
    pub request_id: Uuid,
    pub blinded_query: BlindedOprfRequest,
    pub init_request: OprfRequest<OprfRequestAuth>,
}

fn avg(durations: &[Duration]) -> Duration {
    let n = durations.len();
    if n != 0 {
        let total = durations.iter().sum::<Duration>();
        total / n as u32
    } else {
        Duration::ZERO
    }
}

pub fn setup_connector() -> Connector {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let rustls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Connector::Rustls(Arc::new(rustls_config))
}

pub async fn delete_test(config: DevClientConfig, provider: DynProvider) -> eyre::Result<()> {
    tracing::info!("creating new key to delete afterwards");
    let (oprf_key_id, _) = init_key_gen(
        &config.nodes,
        config.oprf_key_registry_contract,
        provider.clone(),
        config.max_wait_time,
    )
    .await?;
    tracing::info!("created the key - now delete it..");
    oprf_test_utils::delete_oprf_key_material(
        provider,
        config.oprf_key_registry_contract,
        oprf_key_id,
    )
    .await?;
    tracing::info!("sent delete event - ping nodes to check this works");
    health_checks::assert_key_id_unknown(oprf_key_id, &config.nodes, config.max_wait_time).await?;
    tracing::info!("successfully deleted key-material");
    Ok(())
}

pub async fn send_init_requests<OprfRequestAuth: Clone + Serialize + Send + 'static>(
    nodes: &[String],
    module: &str,
    threshold: usize,
    connector: Connector,
    sequential: bool,
    requests: HashMap<Uuid, OprfRequest<OprfRequestAuth>>,
) -> eyre::Result<(
    HashMap<Uuid, OprfSessions>,
    HashMap<Uuid, DLogCommitmentsShamir>,
)> {
    tracing::info!("start sending init requests..");
    let n = requests.len();
    let mut init_results = JoinSet::new();
    let start = Instant::now();

    for (id, req) in requests.into_iter() {
        let nodes = nodes.to_vec();
        let module = module.to_owned();
        let connector = connector.clone();
        init_results.spawn(async move {
            let init_start = Instant::now();
            let sessions = oprf_client::init_sessions(&nodes, &module, threshold, req, connector)
                .await
                .context(format!("while handling session-id: {id}"))?;
            let init_duration = init_start.elapsed();
            eyre::Ok((id, sessions, init_duration))
        });
        if sequential {
            init_results.join_next().await;
        }
    }

    // wait for all results
    let init_results = init_results.join_all().await;
    let init_full_duration = start.elapsed();

    let mut sessions = HashMap::with_capacity(n);
    let mut finish_requests = HashMap::with_capacity(n);
    let mut durations = Vec::with_capacity(n);
    for result in init_results {
        match result {
            Ok((id, session, duration)) => {
                let finish_request = oprf_client::generate_challenge_request(&session);
                sessions.insert(id, session);
                finish_requests.insert(id, finish_request);
                durations.push(duration);
            }
            Err(err) => tracing::error!("got an error during init: {err:?}"),
        }
    }

    if durations.len() != n {
        eyre::bail!("init did encounter errors - see logs");
    }

    let init_throughput = n as f64 / init_full_duration.as_secs_f64();
    let init_avg = avg(&durations);
    tracing::info!(
        "init req - total time: {init_full_duration:?} avg: {init_avg:?} throughput: {init_throughput} req/s"
    );

    Ok((sessions, finish_requests))
}

pub async fn send_finish_requests(
    mut sessions: HashMap<Uuid, OprfSessions>,
    sequential: bool,
    requests: HashMap<Uuid, DLogCommitmentsShamir>,
) -> eyre::Result<HashMap<Uuid, Vec<DLogProofShareShamir>>> {
    tracing::info!("start sending finish requests..");
    let n = requests.len();
    let mut finish_results = JoinSet::new();
    let start = Instant::now();

    for (id, req) in requests {
        let session = sessions.remove(&id).expect("is there");
        finish_results.spawn(async move {
            let finish_start = Instant::now();
            let responses = oprf_client::finish_sessions(session, req.clone())
                .await
                .context(format!("while handling session-id: {id}"))?;
            let duration = finish_start.elapsed();
            eyre::Ok((id, responses, duration))
        });
        if sequential {
            finish_results.join_next().await;
        }
    }

    let finish_results = finish_results.join_all().await;
    let finish_full_duration = start.elapsed();

    let mut responses = HashMap::with_capacity(n);
    let mut durations = Vec::with_capacity(n);
    for result in finish_results {
        match result {
            Ok((id, res, duration)) => {
                responses.insert(id, res);
                durations.push(duration);
            }
            Err(err) => tracing::error!("Got an error during finish: {err:?}"),
        }
    }

    let final_throughput = n as f64 / finish_full_duration.as_secs_f64();
    let finish_avg = avg(&durations);
    tracing::info!(
        "finish req - total time: {finish_full_duration:?} avg: {finish_avg:?} throughput: {final_throughput} req/s"
    );

    Ok(responses)
}

pub async fn init_key_gen(
    nodes: &[String],
    oprf_key_registry: Address,
    provider: DynProvider,
    max_wait_time: Duration,
) -> eyre::Result<(OprfKeyId, OprfPublicKey)> {
    let oprf_key_id_u32: u32 = rand::random();
    let oprf_key_id = OprfKeyId::new(U160::from(oprf_key_id_u32));
    tracing::info!("init OPRF key gen with: {oprf_key_id}");
    oprf_test_utils::init_key_gen(provider, oprf_key_registry, oprf_key_id).await?;
    tracing::info!("waiting for key-gen to finish..");
    let oprf_public_key = health_checks::oprf_public_key_from_services(
        oprf_key_id,
        ShareEpoch::default(),
        nodes,
        max_wait_time,
    )
    .await?;
    tracing::info!("key-gen successful");
    Ok((oprf_key_id, oprf_public_key))
}

async fn stress_test_key_gen(
    cmd: StressTestKeyGenCommand,
    nodes: &[String],
    oprf_key_registry: Address,
    provider: DynProvider,
    max_wait_time: Duration,
) -> eyre::Result<()> {
    // initiate key-gens and reshares
    let mut key_gens = JoinSet::new();
    for _ in 0..cmd.runs {
        let oprf_key_id_u32: u32 = rand::random();
        let oprf_key_id = OprfKeyId::new(U160::from(oprf_key_id_u32));
        tracing::debug!("init OPRF key gen with: {oprf_key_id}");
        oprf_test_utils::init_key_gen(provider.clone(), oprf_key_registry, oprf_key_id).await?;
        key_gens.spawn({
            let nodes = nodes.to_vec();
            async move {
                health_checks::oprf_public_key_from_services(
                    oprf_key_id,
                    ShareEpoch::default(),
                    &nodes,
                    max_wait_time,
                )
                .await?;
                eyre::Ok(oprf_key_id)
            }
        });
    }
    tracing::info!("finished init key-gens, now starting reshares");
    let mut reshares = JoinSet::new();
    while let Some(key_gen_result) = key_gens.join_next().await {
        let key_id = key_gen_result
            .expect("Can join")
            .context("Could not fetch oprf-key-gen")?;
        tracing::debug!("init OPRF reshare for {key_id}");
        oprf_test_utils::init_reshare(provider.clone(), oprf_key_registry, key_id).await?;
        // do an oprf to check if correct
        reshares.spawn({
            let nodes = nodes.to_vec();
            async move {
                health_checks::oprf_public_key_from_services(
                    key_id,
                    ShareEpoch::default().next(),
                    &nodes,
                    max_wait_time,
                )
                .await?;
                eyre::Ok(())
            }
        });
    }
    tracing::info!(
        "started {} key-gens + reshare - waiting to finish",
        cmd.runs
    );
    reshares
        .join_all()
        .await
        .into_iter()
        .collect::<eyre::Result<Vec<_>>>()
        .context("cannot finish reshares")?;
    Ok(())
}

async fn stress_test<T: DevClient>(
    dev_client: T,
    config: DevClientConfig,
    cmd: StressTestOprfCommand,
    setup: T::Setup,
    connector: Connector,
) -> eyre::Result<()> {
    let mut rng = rand_chacha::ChaCha12Rng::from_rng(rand::thread_rng())?;
    let StressTestOprfCommand {
        runs,
        sequential,
        skip_checks,
    } = cmd;

    let mut blinded_requests = HashMap::with_capacity(cmd.runs);
    let mut init_requests = HashMap::with_capacity(cmd.runs);
    for _ in 0..runs {
        let StressTestItem {
            request_id,
            blinded_query,
            init_request,
        } = dev_client
            .prepare_stress_test_item(&setup, &mut rng)
            .await?;
        blinded_requests.insert(request_id, blinded_query);
        init_requests.insert(request_id, init_request);
    }
    tracing::info!("sending init requests..");
    let (sessions, finish_requests) = send_init_requests(
        &config.nodes,
        &dev_client.auth_module(),
        config.threshold,
        connector,
        sequential,
        init_requests,
    )
    .await?;
    tracing::info!("sending finish requests..");
    let responses = send_finish_requests(sessions, cmd.sequential, finish_requests.clone()).await?;

    if !skip_checks {
        tracing::info!("checking OPRF + proofs");
        for (id, res) in responses {
            let blinded_req = blinded_requests.get(&id).expect("is there").to_owned();
            let finish_req = finish_requests.get(&id).expect("is there").to_owned();
            let _dlog_proof = oprf_client::verify_dlog_equality(
                id,
                dev_client.get_oprf_key(&setup),
                &blinded_req,
                res,
                finish_req,
            )?;
        }
    }
    Ok(())
}

async fn reshare_test<T: DevClient>(
    dev_client: T,
    acceptance_num: usize,
    config: DevClientConfig,
    setup: T::Setup,
    provider: DynProvider,
    connector: Connector,
) -> eyre::Result<()> {
    let oprf_key_id = dev_client.get_oprf_key_id(&setup);
    tracing::info!("running OPRF to get current epoch..");
    let current_epoch = dev_client
        .run_oprf(&config, setup.clone(), connector.clone())
        .await?;
    tracing::info!("current epoch: {current_epoch}");

    tracing::info!("start OPRF client task");
    let (tx, mut rx) = mpsc::channel(32);
    // we need this so that we don't get random warnings when we kill the task abruptly
    let shutdown_signal = Arc::new(AtomicBool::new(false));
    let oprf_client_task = tokio::task::spawn({
        let config = config.clone();
        let connector = connector.clone();
        let shutdown_signal = Arc::clone(&shutdown_signal);
        let setup = setup.clone();
        async move {
            let mut counter = 0;
            loop {
                if shutdown_signal.load(Ordering::Relaxed) {
                    break;
                }
                let result = dev_client
                    .run_oprf(&config, setup.clone(), connector.clone())
                    .await;
                counter += 1;
                if counter % 50 == 0 {
                    tracing::debug!("send OPRF: {}", counter);
                }
                if tx.send(result).await.is_err() {
                    break;
                }
            }
        }
    });

    tracing::info!("Doing reshare!");
    oprf_test_utils::init_reshare(
        provider.clone(),
        config.oprf_key_registry_contract,
        oprf_key_id,
    )
    .await?;
    tokio::time::timeout(
        config.max_wait_time,
        wait_for_epoch(&mut rx, acceptance_num, current_epoch.next()),
    )
    .await??;

    tracing::info!("Doing reshare!");
    oprf_test_utils::init_reshare(
        provider.clone(),
        config.oprf_key_registry_contract,
        oprf_key_id,
    )
    .await?;
    tokio::time::timeout(
        config.max_wait_time,
        wait_for_epoch(&mut rx, acceptance_num, current_epoch.next().next()),
    )
    .await??;
    shutdown_signal.store(true, Ordering::Relaxed);

    if tokio::time::timeout(Duration::from_secs(5), oprf_client_task)
        .await
        .is_err()
    {
        tracing::warn!("test succeeded but could not finish client tasks in 5 seconds?")
    };
    Ok(())
}

async fn wait_for_epoch(
    rx: &mut mpsc::Receiver<Result<ShareEpoch, eyre::Report>>,
    acceptance_num: usize,
    target_epoch: ShareEpoch,
) -> eyre::Result<()> {
    let mut new_epoch_found = 0;
    while let Some(result) = rx.recv().await {
        match result {
            Ok(epoch) if epoch == target_epoch => {
                new_epoch_found += 1;
                if new_epoch_found == acceptance_num {
                    tracing::info!(
                        "successfully used new epoch {} {acceptance_num} times!",
                        target_epoch
                    );
                    return Ok(());
                }
            }
            Ok(_) => continue,
            Err(err) => {
                return Err(err);
            }
        }
    }
    eyre::bail!("Channel closed without getting {acceptance_num}");
}

pub async fn run<T: DevClient>(config: DevClientConfig, dev_client: T) -> eyre::Result<()> {
    tracing::info!("health check for all nodes...");
    health_checks::services_health_check(&config.nodes, Duration::from_secs(5))
        .await
        .context("while doing health checks")?;

    tracing::info!("everyone online..");

    let private_key = PrivateKeySigner::from_str(config.taceo_private_key.expose_secret())?;
    let wallet = EthereumWallet::from(private_key.clone());

    tracing::info!("init rpc provider..");
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(config.chain_rpc_url.expose_secret())
        .await
        .context("while connecting to RPC")?
        .erased();
    let connector = setup_connector();

    match config.command.clone() {
        Command::Test => {
            tracing::info!("running oprf-test");
            let setup = dev_client
                .setup_oprf_test(&config, provider.clone())
                .await?;
            tracing::info!("starting oprf computation");
            dev_client.run_oprf(&config, setup, connector).await?;
            tracing::info!("oprf-test successful");
        }
        Command::DeleteTest => {
            tracing::info!("running delete-test");
            delete_test(config, provider).await?;
            tracing::info!("oprf delete test successful");
        }
        Command::StressTestOprf(cmd) => {
            tracing::info!("running oprf stress-test");
            let setup = dev_client
                .setup_oprf_test(&config, provider.clone())
                .await?;
            stress_test(dev_client, config, cmd, setup, connector).await?;
            tracing::info!("stress-test successful");
        }
        Command::StressTestKeyGen(cmd) => {
            tracing::info!("running key-gen stress-test");
            stress_test_key_gen(
                cmd,
                &config.nodes,
                config.oprf_key_registry_contract,
                provider,
                config.max_wait_time,
            )
            .await?;
            tracing::info!("stress-test successful");
        }
        Command::ReshareTest(ReshareTest { acceptance_num }) => {
            tracing::info!("running reshare-test");
            let setup = dev_client
                .setup_oprf_test(&config, provider.clone())
                .await?;
            reshare_test(
                dev_client,
                acceptance_num,
                config,
                setup,
                provider,
                connector,
            )
            .await?;
            tracing::info!("reshare-test successful");
        }
    }
    Ok(())
}
