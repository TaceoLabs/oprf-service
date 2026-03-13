//! OPRF Key Gen Binary
//!
//! This is the main entry point for the OPRF node service.
//! It initializes tracing, metrics, and starts the service with configuration
//! from environment variables using the `TACEO_OPRF_KEY_GEN__` prefix.

use std::{net::SocketAddr, process::ExitCode, sync::Arc, time::Duration};

use config::Config;
use eyre::Context;
use nodes_common::{StartedServices, postgres::PostgresConfig};
use serde::Deserialize;
use taceo_oprf_key_gen::{
    config::OprfKeyGenServiceConfig, secret_manager::postgres::PostgresSecretManager,
};

/// The top-level configuration for the OPRF key-gen binary.
///
/// Configured via environment variables using the `TACEO_OPRF_KEY_GEN__` prefix and `__` as separator.
#[derive(Clone, Debug, Deserialize)]
struct OprfKeyGenConfig {
    /// Secret Id of the wallet private key.
    pub wallet_private_key_secret_id: String,

    /// The bind addr of the AXUM server
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,

    /// Max wait time the service waits for its workers during shutdown.
    #[serde(default = "default_max_wait_shutdown")]
    #[serde(with = "humantime_serde")]
    pub max_wait_time_shutdown: Duration,

    /// The OPRF key-gen config
    #[serde(rename = "service")]
    pub key_gen_config: OprfKeyGenServiceConfig,

    /// The postgres config for the secret-manager
    #[serde(rename = "postgres")]
    pub postgres_config: PostgresConfig,
}

fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:4321".parse().expect("valid SocketAddr")
}

fn default_max_wait_shutdown() -> Duration {
    Duration::from_secs(10)
}

fn load_key_gen_config() -> eyre::Result<OprfKeyGenConfig> {
    let cfg = Config::builder()
        .add_source(config::Environment::with_prefix("TACEO_OPRF_KEY_GEN").separator("__"));

    cfg.build()
        .context("while building from config")?
        .try_deserialize()
        .context("while parsing config")
}

async fn run() -> eyre::Result<()> {
    taceo_oprf_key_gen::metrics::describe_metrics();
    tracing::info!("{}", nodes_common::version_info!());

    let config = load_key_gen_config().context("while loading config")?;
    tracing::info!("starting oprf-key-gen with config: {config:#?}");

    // Load AWS config from environment
    let aws_config = aws_config::load_from_env().await;

    // Load the Postgres secret manager.
    let secret_manager = Arc::new(
        PostgresSecretManager::init(
            &config.postgres_config,
            aws_config,
            &config.wallet_private_key_secret_id,
        )
        .await
        .context("while starting postgres secret-manager")?,
    );

    let (cancellation_token, _) =
        nodes_common::spawn_shutdown_task(nodes_common::default_shutdown_signal());

    // Clone the values we need afterwards as well
    let bind_addr = config.bind_addr;
    let max_wait_time_shutdown = config.max_wait_time_shutdown;

    let (key_gen_router, key_gen_task) = taceo_oprf_key_gen::start(
        config.key_gen_config,
        secret_manager,
        StartedServices::new(),
        cancellation_token.clone(),
    )
    .await
    .context("while initiating key-gen service")?;

    let server = tokio::spawn({
        let cancellation_token = cancellation_token.clone();
        async move {
            // we cancel the token if this task closes for some reason
            let _drop_guard = cancellation_token.drop_guard_ref();
            tracing::info!("starting axum server on to {bind_addr}");
            let tcp_listener = tokio::net::TcpListener::bind(bind_addr)
                .await
                .context("while binding tcp-listener")?;
            let axum_result = axum::serve(tcp_listener, key_gen_router)
                .with_graceful_shutdown({
                    let cancellation_token = cancellation_token.clone();
                    async move { cancellation_token.cancelled().await }
                })
                .await
                .context("while running axum");
            tracing::info!("axum server shutdown");
            axum_result
        }
    });

    tracing::info!("everything started successfully - now waiting for shutdown...");
    cancellation_token.cancelled().await;

    tracing::info!("waiting for shutdown of services (max wait time {max_wait_time_shutdown:?})..");

    match tokio::time::timeout(max_wait_time_shutdown, async move {
        let (axum_result, key_gen_result) = tokio::join!(server, key_gen_task.join());
        axum_result??;
        key_gen_result?;
        eyre::Ok(())
    })
    .await
    {
        Ok(Ok(_)) => {
            tracing::info!("successfully finished shutdown in time");
            Ok(())
        }
        Ok(Err(err)) => Err(err),
        Err(_) => {
            eyre::bail!("could not finish shutdown in time");
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    // we panic if we cannot setup tracing + TLS - if that fails we won't see anything anyways on tracing endpoint
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Can install");
    let tracing_config =
        nodes_observability::TracingConfig::try_from_env().expect("Can create TryingConfig");
    let _tracing_handle =
        nodes_observability::initialize_tracing(&tracing_config).expect("Can get tracing handle");
    match run().await {
        Ok(_) => {
            tracing::info!("good night");
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!("key-gen did shutdown: {err:?}");
            tracing::error!("good night anyways");
            ExitCode::FAILURE
        }
    }
}
