// #![deny(missing_docs)]
//! # TODO
//! This example project shall help projects incorporate at TACEO:Oprf. Explain in detail what implementations need to do to build their flavor.
use std::sync::Arc;

use crate::{auth::ExampleOprfRequestAuthenticator, config::ExampleOprfNodeConfig};
use oprf_service::{StartedServices, secret_manager::SecretManagerService};

pub(crate) mod auth;
pub mod config;

pub async fn start(
    config: ExampleOprfNodeConfig,
    secret_manager: SecretManagerService,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> eyre::Result<()> {
    tracing::info!("starting oprf-service with config: {config:#?}");
    let service_config = config.service_config;
    let cancellation_token = nodes_common::spawn_shutdown_task(shutdown_signal);

    tracing::info!("init oprf request auth service..");
    let oprf_req_auth_service = Arc::new(ExampleOprfRequestAuthenticator);

    tracing::info!("init oprf service..");
    let (oprf_service_router, key_event_watcher) = oprf_service::init(
        service_config,
        secret_manager,
        oprf_req_auth_service,
        StartedServices::default(),
        cancellation_token.clone(),
    )
    .await?;

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

    Ok(())
}
