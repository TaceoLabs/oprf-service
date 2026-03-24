use std::{
    net::SocketAddr,
    process::ExitCode,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use config::{Config, Environment};
use eyre::Context;
use nodes_common::postgres::PostgresConfig;
use serde::Deserialize;
use taceo_oprf_service::{
    OprfServiceBuilder, StartedServices,
    config::OprfNodeServiceConfig,
    secret_manager::{SecretManagerService, postgres::PostgresSecretManager},
};

use crate::simple_authenticator::ExampleOprfRequestAuthenticator;

mod simple_authenticator;

/// The top-level configuration for the OPRF node example binary.
///
/// Configured via environment variables using the `TACEO_OPRF_NODE__` prefix and `__` as separator.
#[derive(Clone, Debug, Deserialize)]
pub struct ExampleOprfNodeConfig {
    /// The bind addr of the AXUM server
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,

    /// Max wait time the service waits for its workers during shutdown.
    #[serde(default = "default_max_wait_shutdown")]
    #[serde(with = "humantime_serde")]
    pub max_wait_time_shutdown: Duration,

    /// The OPRF service config
    #[serde(rename = "service")]
    pub node_config: OprfNodeServiceConfig,

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

pub fn load_example_config() -> eyre::Result<ExampleOprfNodeConfig> {
    let cfg =
        Config::builder().add_source(Environment::with_prefix("TACEO_OPRF_NODE").separator("__"));

    cfg.build()
        .context("while building from config")?
        .try_deserialize()
        .context("while parsing config")
}

#[tokio::main]
async fn main() -> eyre::Result<ExitCode> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    nodes_observability::install_tracing("oprf_service_example=trace, info");
    tracing::info!("{}", nodes_common::version_info!());

    let config = load_example_config()?;
    tracing::info!("starting oprf-service with config: {config:#?}");

    // Load the postgres secret manager.
    let secret_manager = Arc::new(
        PostgresSecretManager::init(&config.postgres_config)
            .await
            .context("while starting postgres secret-manager")?,
    );
    let result = start_service(
        config,
        secret_manager,
        nodes_common::default_shutdown_signal(),
    )
    .await;
    match result {
        Ok(()) => {
            tracing::info!("good night!");
            Ok(ExitCode::SUCCESS)
        }
        Err(err) => {
            // we don't want to double print the error therefore we just return FAILURE
            tracing::error!("{err:?}");
            Ok(ExitCode::FAILURE)
        }
    }
}

pub async fn start_service(
    config: ExampleOprfNodeConfig,
    secret_manager: SecretManagerService,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> eyre::Result<()> {
    let (cancellation_token, is_graceful_shutdown) =
        nodes_common::spawn_shutdown_task(shutdown_signal);

    tracing::info!("init oprf service..");
    let (oprf_service_router, key_event_watcher) = OprfServiceBuilder::init(
        config.node_config,
        secret_manager,
        StartedServices::default(),
        cancellation_token.clone(),
    )
    .await?
    .module("/example", Arc::new(ExampleOprfRequestAuthenticator))
    .build();

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    let axum_cancel_token = cancellation_token.clone();
    let server = tokio::spawn(async move {
        tracing::info!(
            "starting axum server on {}",
            listener
                .local_addr()
                .map(|x| x.to_string())
                .unwrap_or(String::from("invalid addr"))
        );
        let axum_shutdown_signal = axum_cancel_token.clone();
        let axum_result = axum::serve(listener, oprf_service_router)
            .with_graceful_shutdown(async move { axum_shutdown_signal.cancelled().await })
            .await;
        tracing::info!("axum server shutdown");
        if let Err(err) = axum_result {
            tracing::error!("got error from axum: {err:?}");
        }
        // we cancel the token in case axum encountered an error to shutdown the service
        axum_cancel_token.cancel();
    });

    tracing::info!("everything started successfully - now waiting for shutdown...");
    cancellation_token.cancelled().await;

    tracing::info!(
        "waiting for shutdown of services (max wait time {:?})..",
        config.max_wait_time_shutdown
    );
    match tokio::time::timeout(config.max_wait_time_shutdown, async move {
        tokio::join!(server, key_event_watcher)
    })
    .await
    {
        Ok(_) => tracing::info!("successfully finished shutdown in time"),
        Err(_) => tracing::warn!("could not finish shutdown in time"),
    }
    if is_graceful_shutdown.load(Ordering::Relaxed) {
        Ok(())
    } else {
        eyre::bail!("Unexpected shutdown - check error logs")
    }
}
