//! OPRF Key Gen Binary
//!
//! This is the main entry point for the OPRF key-gen service.
//! It initializes tracing, metrics, and starts the service with configuration
//! from environment variables using the `TACEO_OPRF_KEY_GEN__` prefix.

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use std::{net::SocketAddr, process::ExitCode, sync::Arc, time::Duration};

use config::Config;
use eyre::Context;
use nodes_common::{StartedServices, postgres::PostgresConfig};
use serde::Deserialize;
use taceo_oprf_key_gen::{config::OprfKeyGenServiceConfig, postgres::PostgresDb};

/// The top-level configuration for the OPRF key-gen binary.
///
/// Configured via environment variables using the `TACEO_OPRF_KEY_GEN__` prefix and `__` as separator.
#[derive(Clone, Debug, Deserialize)]
struct OprfKeyGenConfig {
    /// The bind addr of the AXUM server
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,

    /// Max wait time the service waits for its workers during shutdown.
    #[serde(default = "default_max_wait_shutdown")]
    #[serde(with = "humantime_serde")]
    pub max_wait_time_shutdown: Duration,

    /// The OPRF key-gen service config
    #[serde(rename = "service")]
    pub key_gen_config: OprfKeyGenServiceConfig,

    /// Postgres config used by the shared [`PostgresDb`] backend (secret manager and chain cursor store).
    #[serde(rename = "postgres")]
    pub postgres_config: PostgresConfig,
}

fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:4321".parse().expect("valid SocketAddr")
}

fn default_max_wait_shutdown() -> Duration {
    Duration::from_secs(10)
}

// we are not allowed to build an eyre::Report yet because telemetry-batteries expects to install
// the color-eyre hook
fn load_key_gen_config() -> Result<OprfKeyGenConfig, config::ConfigError> {
    let cfg = Config::builder().add_source(
        config::Environment::with_prefix("TACEO_OPRF_KEY_GEN")
            .separator("__")
            .list_separator(",")
            .with_list_parse_key("service.rpc.http_urls")
            .try_parsing(true),
    );

    let key_gen_config = cfg.build()?.try_deserialize()?;

    // Unset all env vars with our prefix to prevent leakage to subprocesses.
    // Safety: this is called before any threads are spawned.
    let keys_to_remove: Vec<String> = std::env::vars()
        .filter_map(|(k, _)| k.starts_with("TACEO_OPRF_KEY_GEN_").then_some(k))
        .collect();
    for key in keys_to_remove {
        // SAFETY: no other threads are running at this point in the startup sequence.
        unsafe {
            std::env::remove_var(&key);
        }
    }

    Ok(key_gen_config)
}

async fn run(config: OprfKeyGenConfig) -> eyre::Result<()> {
    taceo_oprf_key_gen::metrics::describe_metrics();
    tracing::info!("{}", nodes_common::version_info!());

    tracing::info!("connecting to postgres DB...");

    let postgres = PostgresDb::init(&config.postgres_config)
        .await
        .context("while starting postgres secret-manager")?;

    // Init postgres secret manager (Postgres backed)
    let secret_manager = Arc::new(postgres.clone());

    // Init chain event store (Postgres backed)
    let chain_cursor_store = Arc::new(postgres.clone());

    let (cancellation_token, _) =
        nodes_common::spawn_shutdown_task(nodes_common::default_shutdown_signal());

    // Clone the values we need afterwards as well
    let bind_addr = config.bind_addr;
    let max_wait_time_shutdown = config.max_wait_time_shutdown;

    let (key_gen_router, key_gen_task) = taceo_oprf_key_gen::start(
        config.key_gen_config,
        secret_manager,
        chain_cursor_store,
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

fn main() -> ExitCode {
    // try loading config and unsetting vars before we do any potentially multithreaded work;
    let maybe_config = load_key_gen_config();

    // we panic if we cannot setup tracing + TLS - if that fails we won't see anything anyways on tracing endpoint
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Can install");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Can build Tokio runtime");
    runtime.block_on(async {
        let _guard = telemetry_batteries::init().expect("Can initialize tracing");

        // load the config
        let config = match maybe_config {
            Ok(config) => config,
            Err(err) => {
                tracing::error!("failed to load config: {err}");
                return ExitCode::FAILURE;
            }
        };
        tracing::info!("starting taceo-oprf-key-gen with config: {config:#?}");
        match run(config).await {
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
    })
}
