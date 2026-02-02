use std::{
    net::SocketAddr,
    process::ExitCode,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use clap::Parser;
use eyre::Context;
use taceo_oprf_service::{
    OprfServiceBuilder, StartedServices,
    config::OprfNodeConfig,
    secret_manager::{SecretManagerService, postgres::PostgresSecretManager},
};

use crate::simple_authenticator::ExampleOprfRequestAuthenticator;

mod simple_authenticator;

/// The configuration for the OPRF node.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct ExampleOprfNodeConfig {
    /// The bind addr of the AXUM server
    #[clap(long, env = "OPRF_NODE_BIND_ADDR", default_value = "0.0.0.0:4321")]
    pub bind_addr: SocketAddr,

    /// Max wait time the service waits for its workers during shutdown.
    #[clap(
        long,
        env = "OPRF_NODE_MAX_WAIT_TIME_SHUTDOWN",
        default_value = "10s",
        value_parser = humantime::parse_duration

    )]
    pub max_wait_time_shutdown: Duration,

    /// The OPRF service config
    #[clap(flatten)]
    pub service_config: OprfNodeConfig,
}

#[tokio::main]
async fn main() -> eyre::Result<ExitCode> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    nodes_observability::install_tracing("oprf_service_example=trace, info");
    tracing::info!("{}", nodes_common::version_info!());

    let config = ExampleOprfNodeConfig::parse();

    // Load the AWS secret manager.
    let secret_manager = Arc::new(
        PostgresSecretManager::init(
            &config.service_config.db_connection_string,
            &config.service_config.db_schema,
            config.service_config.db_max_connections,
        )
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
    tracing::info!("starting oprf-service with config: {config:#?}");
    let service_config = config.service_config;
    let (cancellation_token, is_graceful_shutdown) =
        nodes_common::spawn_shutdown_task(shutdown_signal);

    tracing::info!("init oprf request auth service..");
    let oprf_req_auth_service = Arc::new(ExampleOprfRequestAuthenticator);

    tracing::info!("init oprf service..");
    let (oprf_service_router, key_event_watcher) = OprfServiceBuilder::init(
        service_config,
        secret_manager,
        StartedServices::default(),
        cancellation_token.clone(),
    )
    .await?
    .module("/example", oprf_req_auth_service)
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
