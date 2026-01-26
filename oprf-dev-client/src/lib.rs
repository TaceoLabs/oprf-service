use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use alloy::{primitives::Address, providers::DynProvider};
use clap::{Parser, Subcommand};
use oprf_client::{Connector, OprfSessions};
use oprf_core::ddlog_equality::shamir::{DLogCommitmentsShamir, DLogProofShareShamir};
use oprf_test_utils::{health_checks, oprf_key_registry};
use oprf_types::{OprfKeyId, ShareEpoch, api::OprfRequest, crypto::OprfPublicKey};
use serde::Serialize;
use tokio::task::JoinSet;
use uuid::Uuid;

pub use oprf_test_utils;

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
    ReshareTest,
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
            let sessions =
                oprf_client::init_sessions(&nodes, &module, threshold, req, connector).await?;
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
            let responses = oprf_client::finish_sessions(session, req.clone()).await?;
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
    let oprf_key_id = OprfKeyId::new(rand::random());
    tracing::info!("init OPRF key gen with: {oprf_key_id}");
    oprf_key_registry::init_key_gen(provider, oprf_key_registry, oprf_key_id).await?;
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

pub async fn reshare(
    nodes: &[String],
    oprf_key_registry: Address,
    provider: DynProvider,
    max_wait_time: Duration,
    oprf_key_id: OprfKeyId,
    share_epoch: ShareEpoch,
) -> eyre::Result<(ShareEpoch, OprfPublicKey)> {
    tracing::info!("init reshare for: {oprf_key_id}");
    oprf_key_registry::init_reshare(provider, oprf_key_registry, oprf_key_id).await?;
    tracing::info!("waiting for reshare to finish..");
    let next_epoch = share_epoch.next();
    let oprf_public_key =
        health_checks::oprf_public_key_from_services(oprf_key_id, next_epoch, nodes, max_wait_time)
            .await?;
    tracing::info!("reshare successful");
    Ok((next_epoch, oprf_public_key))
}
