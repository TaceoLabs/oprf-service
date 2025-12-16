//! OPRF Service Binary
//!
//! This is the main entry point for the OPRF node service.
//! It initializes tracing, metrics, and starts the service with configuration
//! from command-line arguments or environment variables.

use std::{process::ExitCode, sync::Arc};

use clap::Parser;
use oprf_service::{config::Environment, secret_manager::aws::AwsSecretManager};
use taceo_oprf_service_example::config::ExampleOprfNodeConfig;

#[tokio::main]
async fn main() -> eyre::Result<ExitCode> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let tracing_config = nodes_observability::TracingConfig::try_from_env()?;
    let _tracing_handle = nodes_observability::initialize_tracing(&tracing_config)?;
    oprf_service::metrics::describe_metrics();

    tracing::info!("{}", nodes_common::version_info!());

    let config = ExampleOprfNodeConfig::parse();

    let aws_config = match config.service_config.environment {
        Environment::Prod => aws_config::load_from_env().await,
        Environment::Dev => nodes_common::localstack_aws_config().await,
    };

    // Load the AWS secret manager.
    let secret_manager = Arc::new(
        AwsSecretManager::init(aws_config, &config.service_config.rp_secret_id_prefix).await,
    );

    let result = taceo_oprf_service_example::start(
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
