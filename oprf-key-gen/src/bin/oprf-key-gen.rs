//! OPRF Key Gen Binary
//!
//! This is the main entry point for the OPRF node service.
//! It initializes tracing, metrics, and starts the service with configuration
//! from command-line arguments or environment variables.

use std::{
    process::ExitCode,
    sync::{Arc, atomic::Ordering},
};

use clap::Parser;
use eyre::Context;
use taceo_oprf_key_gen::{
    config::{Environment, OprfKeyGenConfig},
    secret_manager::postgres::PostgresSecretManager,
};

#[tokio::main]
async fn main() -> eyre::Result<ExitCode> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let tracing_config = nodes_observability::TracingConfig::try_from_env()?;
    let _tracing_handle = nodes_observability::initialize_tracing(&tracing_config)?;
    taceo_oprf_key_gen::metrics::describe_metrics();

    tracing::info!("{}", nodes_common::version_info!());

    let config = OprfKeyGenConfig::parse();

    tracing::info!("starting oprf-key-gen with config: {config:#?}");

    let aws_config = match config.environment {
        Environment::Prod => aws_config::load_from_env().await,
        Environment::Dev => nodes_common::localstack_aws_config().await,
    };

    // Load the Postgres secret manager.
    let secret_manager = Arc::new(
        PostgresSecretManager::init(
            &config.db_connection_string,
            &config.db_schema,
            aws_config,
            &config.wallet_private_key_secret_id,
        )
        .await
        .context("while starting postgres secret-manager")?,
    );

    let (cancellation_token, is_graceful_shutdown) =
        nodes_common::spawn_shutdown_task(nodes_common::default_shutdown_signal());

    // Clone the values we need afterwards as well
    let bind_addr = config.bind_addr;
    let max_wait_time_shutdown = config.max_wait_time_shutdown;

    let (key_gen_router, key_gen_task) =
        taceo_oprf_key_gen::start(config, secret_manager, cancellation_token.clone())
            .await
            .context("while initiating key-gen service")?;

    tracing::info!("binding to {}", bind_addr);
    let tcp_listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .context("while binding tcp-listener")?;

    let axum_cancel_token = cancellation_token.clone();
    let server = tokio::spawn(async move {
        tracing::info!(
            "starting axum server on {}",
            tcp_listener
                .local_addr()
                .map(|x| x.to_string())
                .unwrap_or(String::from("invalid addr"))
        );
        let axum_shutdown_signal = axum_cancel_token.clone();
        let axum_result = axum::serve(tcp_listener, key_gen_router)
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

    tracing::info!("waiting for shutdown of services (max wait time {max_wait_time_shutdown:?})..");

    match tokio::time::timeout(max_wait_time_shutdown, async move {
        tokio::join!(server, key_gen_task.join())
    })
    .await
    {
        Ok(_) => tracing::info!("successfully finished shutdown in time"),
        Err(_) => {
            is_graceful_shutdown.store(false, Ordering::Relaxed);
            tracing::warn!("could not finish shutdown in time")
        }
    }

    tracing::info!("good night!");
    if is_graceful_shutdown.load(Ordering::Relaxed) {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}
