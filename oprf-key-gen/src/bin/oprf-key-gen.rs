//! OPRF Key Gen Binary
//!
//! This is the main entry point for the OPRF node service.
//! It initializes tracing, metrics, and starts the service with configuration
//! from command-line arguments or environment variables.

use std::{process::ExitCode, sync::Arc};

use clap::Parser;
use eyre::Context;
use nodes_common::StartedServices;
use taceo_oprf_key_gen::{
    config::{Environment, OprfKeyGenConfig},
    secret_manager::postgres::{PostgresSecretManager, PostgresSecretManagerArgs},
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
        PostgresSecretManager::init(PostgresSecretManagerArgs {
            connection_string: config.db_connection_string.clone(),
            schema: config.db_schema.clone(),
            max_connections: config.max_db_connections,
            acquire_timeout: config.db_acquire_timeout,
            max_retries: config.db_max_retries,
            retry_delay: config.db_retry_delay,
            aws_config,
            wallet_private_key_secret_id: config.wallet_private_key_secret_id.clone(),
        })
        .await
        .context("while starting postgres secret-manager")?,
    );

    let (cancellation_token, _) =
        nodes_common::spawn_shutdown_task(nodes_common::default_shutdown_signal());

    // Clone the values we need afterwards as well
    let bind_addr = config.bind_addr;
    let max_wait_time_shutdown = config.max_wait_time_shutdown;

    let (key_gen_router, key_gen_task) = taceo_oprf_key_gen::start(
        config,
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

    let result = match tokio::time::timeout(max_wait_time_shutdown, async move {
        let (axum_result, key_gen_result) = tokio::join!(server, key_gen_task.join());
        axum_result??;
        key_gen_result?;
        eyre::Ok(())
    })
    .await
    {
        Ok(Ok(_)) => {
            tracing::info!("successfully finished shutdown in time");
            Ok(ExitCode::SUCCESS)
        }
        Ok(Err(err)) => {
            tracing::error!("key-gen encountered an error: {err:?}");
            Ok(ExitCode::FAILURE)
        }
        Err(_) => {
            tracing::warn!("could not finish shutdown in time");
            Ok(ExitCode::FAILURE)
        }
    };
    tracing::info!("good night!");
    result
}
