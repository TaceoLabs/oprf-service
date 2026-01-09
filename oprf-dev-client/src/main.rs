use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::primitives::{Address, U160};
use ark_ff::UniformRand as _;
use clap::{Parser, Subcommand};
use eyre::Context as _;
use oprf_client::{BlindingFactor, Connector};
use oprf_core::oprf::BlindedOprfRequest;
use oprf_test::{health_checks, oprf_key_registry_scripts};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    api::v1::{OprfRequest, ShareIdentifier},
    crypto::OprfPublicKey,
};
use rand::SeedableRng;
use rustls::{ClientConfig, RootCertStore};
use secrecy::{ExposeSecret, SecretString};
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::endless_run::EndlessRunCommand;

mod endless_run;

#[derive(Clone, Parser, Debug)]
pub struct StressTestCommand {
    /// The amount of OPRF runs
    #[clap(long, env = "OPRF_DEV_CLIENT_RUNS", default_value = "10")]
    pub runs: usize,

    /// Send requests sequentially instead of concurrently
    #[clap(long, env = "OPRF_DEV_CLIENT_SEQUENTIAL")]
    pub sequential: bool,

    /// Send requests sequentially instead of concurrently
    #[clap(long, env = "OPRF_DEV_CLIENT_SKIP_CHECKS")]
    pub skip_checks: bool,
}

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    Test,
    StressTest(StressTestCommand),
    EndlessRun(EndlessRunCommand),
}

/// The configuration for the OPRF client.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct OprfDevClientConfig {
    /// The URLs to all OPRF Services
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_NODES",
        value_delimiter = ',',
        default_value = "http://127.0.0.1:10000,http://127.0.0.1:10001,http://127.0.0.1:10002"
    )]
    pub services: Vec<String>,

    /// The threshold of services that need to respond
    #[clap(long, env = "OPRF_DEV_CLIENT_THRESHOLD", default_value = "2")]
    pub threshold: usize,

    /// The start epoch. Will be ignored if we need to create a key.
    #[clap(long, env = "OPRF_DEV_CLIENT_START_EPOCH", default_value = "0")]
    pub start_epoch: u128,

    /// The Address of the OprfKeyRegistry contract.
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT",
        default_value = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
    )]
    pub oprf_key_registry_contract: Address,

    /// The RPC for chain communication
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_CHAIN_RPC_URL",
        default_value = "http://localhost:8545"
    )]
    pub chain_rpc_url: SecretString,

    /// The PRIVATE_KEY of the TACEO admin wallet - used to register the OPRF nodes
    ///
    /// Default is anvil wallet 0
    #[clap(
        long,
        env = "TACEO_ADMIN_PRIVATE_KEY",
        default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )]
    pub taceo_private_key: SecretString,

    /// rp id of already registered rp
    #[clap(long, env = "OPRF_DEV_CLIENT_OPRF_KEY_ID")]
    pub oprf_key_id: Option<U160>,

    /// max wait time for init key-gen to succeed.
    #[clap(long, env = "OPRF_DEV_CLIENT_KEY_GEN_WAIT_TIME", default_value="2min", value_parser=humantime::parse_duration)]
    pub max_wait_time_key_gen: Duration,

    /// Whether we want to do a reshare as well.
    #[clap(long, env = "OPRF_DEV_CLIENT_WITH_RESHARE")]
    pub reshare: bool,

    /// Command
    #[command(subcommand)]
    pub command: Command,
}

async fn test_run(
    config: &OprfDevClientConfig,
    start_epoch: ShareEpoch,
    oprf_key_id: OprfKeyId,
    oprf_public_key: OprfPublicKey,
    connector: Connector,
) -> eyre::Result<()> {
    tracing::info!("running single OPRF");
    run_oprf(
        config.services.clone(),
        start_epoch,
        config.threshold,
        oprf_key_id,
        oprf_public_key,
        connector.clone(),
    )
    .await?;
    tracing::info!("OPRF successful");
    if config.reshare {
        tracing::info!("running reshare test");
        oprf_key_registry_scripts::init_reshare(
            oprf_key_id,
            config.chain_rpc_url.expose_secret(),
            config.oprf_key_registry_contract,
            config.taceo_private_key.expose_secret(),
        );
        tracing::info!("started reshare for OPRF key with: {oprf_key_id}");
        let next_epoch = start_epoch.next();
        tracing::info!("waiting for services to finish reshare..");
        let oprf_public_key_reshare = health_checks::oprf_public_key_from_services(
            oprf_key_id,
            next_epoch,
            &config.services,
            config.max_wait_time_key_gen,
        )
        .await?;
        assert_eq!(oprf_public_key, oprf_public_key_reshare);
        tracing::info!("running OPRF after reshare");
        run_oprf(
            config.services.clone(),
            next_epoch,
            config.threshold,
            oprf_key_id,
            oprf_public_key,
            connector,
        )
        .await?;
        tracing::info!("OPRF successful");
    }
    Ok(())
}

async fn run_oprf(
    nodes: Vec<String>,
    epoch: ShareEpoch,
    threshold: usize,
    oprf_key_id: OprfKeyId,
    oprf_public_key: OprfPublicKey,
    connector: Connector,
) -> eyre::Result<()> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let action = ark_babyjubjub::Fq::rand(&mut rng);

    // the client example internally checks the DLog equality
    oprf_client_example::distributed_oprf(
        &nodes,
        threshold,
        oprf_public_key,
        oprf_key_id,
        epoch,
        action,
        connector,
        &mut rng,
    )
    .await?;

    Ok(())
}

fn prepare_oprf_stress_test_oprf_request(
    oprf_key_id: OprfKeyId,
) -> eyre::Result<(Uuid, BlindedOprfRequest, OprfRequest<()>)> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let request_id = Uuid::new_v4();
    let action = ark_babyjubjub::Fq::rand(&mut rng);
    let blinding_factor = BlindingFactor::rand(&mut rng);
    let query = action;
    let blinded_request = oprf_core::oprf::client::blind_query(query, blinding_factor);
    let oprf_req = OprfRequest {
        request_id,
        blinded_query: blinded_request.blinded_query(),
        share_identifier: ShareIdentifier {
            oprf_key_id,
            share_epoch: ShareEpoch::default(),
        },
        auth: (),
    };

    Ok((request_id, blinded_request, oprf_req))
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

async fn stress_test(
    cmd: StressTestCommand,
    services: &[String],
    threshold: usize,
    oprf_key_id: OprfKeyId,
    oprf_public_key: OprfPublicKey,
    connector: Connector,
) -> eyre::Result<()> {
    tracing::info!("preparing requests..");
    let mut request_ids = HashMap::with_capacity(cmd.runs);
    let mut blinded_requests = HashMap::with_capacity(cmd.runs);
    let mut init_requests = Vec::with_capacity(cmd.runs);

    for idx in 0..cmd.runs {
        let (request_id, blinded_req, req) = prepare_oprf_stress_test_oprf_request(oprf_key_id)?;
        request_ids.insert(idx, request_id);
        blinded_requests.insert(idx, blinded_req);
        init_requests.push(req);
    }

    let mut init_results = JoinSet::new();

    tracing::info!("start sending init requests..");
    let start = Instant::now();
    for (idx, req) in init_requests.into_iter().enumerate() {
        let services = services.to_vec();
        let connector = connector.clone();
        init_results.spawn(async move {
            let init_start = Instant::now();
            let sessions = oprf_client::init_sessions(&services, threshold, req, connector).await?;
            eyre::Ok((idx, sessions, init_start.elapsed()))
        });
        if cmd.sequential {
            init_results.join_next().await;
        }
    }
    let init_results = init_results.join_all().await;
    let init_full_duration = start.elapsed();
    let mut sessions = Vec::with_capacity(cmd.runs);
    let mut durations = Vec::with_capacity(cmd.runs);
    for result in init_results {
        match result {
            Ok((idx, session, duration)) => {
                sessions.push((idx, session));
                durations.push(duration);
            }
            Err(err) => tracing::error!("Got an error during init: {err:?}"),
        }
    }
    if durations.len() != cmd.runs {
        eyre::bail!("init did encounter errors - see logs");
    }
    let init_throughput = cmd.runs as f64 / init_full_duration.as_secs_f64();
    let init_avg = avg(&durations);

    let mut finish_challenges = sessions
        .iter()
        .map(|(idx, sessions)| {
            let request_id = *request_ids.get(idx).expect("is there");
            eyre::Ok((
                *idx,
                (
                    request_id,
                    oprf_client::generate_challenge_request(sessions),
                ),
            ))
        })
        .collect::<eyre::Result<HashMap<_, _>>>()?;

    let mut finish_results = JoinSet::new();

    tracing::info!("start sending finish requests..");
    durations.clear();
    for (idx, sessions) in sessions {
        let blinded_req = blinded_requests.get(&idx).expect("is there").to_owned();
        let (session_id, challenge) = finish_challenges.remove(&idx).expect("is there");
        finish_results.spawn(async move {
            let finish_start = Instant::now();
            let responses = oprf_client::finish_sessions(sessions, challenge.clone()).await?;
            let duration = finish_start.elapsed();
            let dlog_proof = oprf_client::verify_dlog_equality(
                session_id,
                oprf_public_key,
                &blinded_req,
                responses,
                challenge.clone(),
            )?;
            eyre::Ok((idx, dlog_proof, challenge, duration))
        });
        if cmd.sequential {
            finish_results.join_next().await;
        }
    }
    let finish_results = finish_results.join_all().await;
    if cmd.skip_checks {
        tracing::info!("got all results - skipping checks");
    } else {
        tracing::info!("got all results - checking OPRF + proofs");
    }
    let finish_full_duration = start.elapsed();

    let mut durations = Vec::with_capacity(cmd.runs);

    for result in finish_results {
        match result {
            Ok((_idx, _dlog_proof, _challenge, duration)) => {
                durations.push(duration);
            }
            Err(err) => tracing::error!("Got an error during finish: {err:?}"),
        }
    }

    tracing::info!(
        "init req - total time: {init_full_duration:?} avg: {init_avg:?} throughput: {init_throughput} req/s"
    );
    let final_throughput = cmd.runs as f64 / finish_full_duration.as_secs_f64();
    let finish_avg = avg(&durations);
    tracing::info!(
        "finish req - total time: {finish_full_duration:?} avg: {finish_avg:?} throughput: {final_throughput} req/s"
    );
    Ok(())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    nodes_observability::install_tracing("taceo_oprf_dev_client=trace,warn");
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let config = OprfDevClientConfig::parse();
    tracing::info!("starting oprf-dev-client with config: {config:#?}");

    tracing::info!("health check for all nodes...");
    health_checks::services_health_check(&config.services, Duration::from_secs(5))
        .await
        .context("while doing health checks")?;
    tracing::info!("everyone online..");

    let mut start_epoch = ShareEpoch::from(config.start_epoch);

    let (oprf_key_id, oprf_public_key) = if let Some(oprf_key_id) = config.oprf_key_id {
        let oprf_key_id = OprfKeyId::new(oprf_key_id);
        let oprf_public_key = health_checks::oprf_public_key_from_services(
            oprf_key_id,
            start_epoch,
            &config.services,
            config.max_wait_time_key_gen,
        )
        .await?;
        (oprf_key_id, oprf_public_key)
    } else {
        if !start_epoch.is_initial_epoch() {
            tracing::warn!(
                "requesting epoch: {start_epoch} but key not provided - ignoring epoch.."
            );
            start_epoch = ShareEpoch::default();
        }
        let oprf_key_id = oprf_key_registry_scripts::init_key_gen(
            config.chain_rpc_url.expose_secret(),
            config.oprf_key_registry_contract,
            config.taceo_private_key.expose_secret(),
        );
        tracing::info!("registered OPRF key with: {oprf_key_id}");
        let oprf_public_key = health_checks::oprf_public_key_from_services(
            oprf_key_id,
            start_epoch,
            &config.services,
            config.max_wait_time_key_gen,
        )
        .await?;
        (oprf_key_id, oprf_public_key)
    };

    // setup TLS config - even if we are http
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let rustls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = Connector::Rustls(Arc::new(rustls_config));

    match config.command.clone() {
        Command::Test => {
            test_run(
                &config,
                start_epoch,
                oprf_key_id,
                oprf_public_key,
                connector,
            )
            .await?;
        }
        Command::StressTest(cmd) => {
            tracing::info!("running stress-test");
            stress_test(
                cmd,
                &config.services,
                config.threshold,
                oprf_key_id,
                oprf_public_key,
                connector,
            )
            .await?;
            tracing::info!("stress-test successful");
        }
        Command::EndlessRun(endless_run) => {
            endless_run::endless_run(config, oprf_key_id, oprf_public_key, endless_run, connector)
                .await?
        }
    }

    Ok(())
}
