#![deny(missing_docs)]
#![deny(clippy::all, clippy::pedantic)]
#![deny(
    clippy::allow_attributes_without_reason,
    clippy::assertions_on_result_states,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::iter_over_hash_type,
    clippy::let_underscore_must_use,
    clippy::missing_assert_message,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_safety_comment,
    clippy::unwrap_used
)]
#![allow(
    clippy::cast_precision_loss,
    reason = "we must use f64 due to API limitations for metrics"
)]
//! This crate provides the core functionality of a node for TACEO:OPRF.
//!
//! When implementing a concrete instantiation of TACEO:OPRF, projects use this composable library to build their flavor of the distributed OPRF protocol. The main entry point for implementations is the [`OprfServiceBuilder`].
//! It performs the necessary initialization of the OPRF node, including connecting to the Ethereum network, loading cryptographic secrets, and spawning background tasks to monitor key events.
//! With the [`OprfServiceBuilder::module`] method, implementations can add multiple OPRF modules, each with its own authentication mechanism.
//! Finally, the [`OprfServiceBuilder::build`] method returns an `axum::Router` that should be incorporated into a larger `axum` server that provides project-based functionality for authentication and a `JoinHandle` for the key event watcher task.
//!
//! If internal services of the OPRF service encounter an error, the provided `CancellationToken` will be cancelled, allowing the hosting application to handle the shutdown process gracefully.
//! Additionally, the `CancellationToken` can be cancelled externally to signal the OPRF service to stop its operations.
//!
//! To ensure a graceful shutdown, the hosting application should await the `JoinHandle` returned by the `OprfServiceBuilder::build` method after cancelling the `CancellationToken`.
//! This ensures that all background tasks are properly terminated before the application exits.
//!
//! For OPRF modules, implementations must provide their project-specific authentication. For that, this library exposes the [`oprf_types::api::OprfRequestAuthenticator`] trait. A call to `[OprfServiceBuilder::module]` expects an [`OprfRequestAuthService`], which is a dyn object of `OprfRequestAuthenticator`.
//!
//! The general workflow is as follows:
//! 1) End-users initiate a session at $n$ nodes.
//!    - the specified OPRF module of the OPRF service receives the request.
//!    - the module router calls [`oprf_types::api::OprfRequestAuthenticator::authenticate`] of the provided authentication implementation. This can be anything from no verification to providing credentials.
//!    - the node creates a session identified by a UUID and sends a commitment back to the user.
//! 2) As soon as end-users have opened $t$ sessions, they compute challenges for the answering nodes.
//!    - the router answers the challenge and deletes all information containing the sessions.
//!
//! For details on the OPRF protocol, see the [design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf).
//!
//! Clients will connect via web-sockets to the OPRF node. Axum supports both HTTP/1.1 and HTTP/2.0 web-socket connections, therefore we accept connections with `any`.
//!
//! If you want to enable HTTP/2.0, you either have to do it by hand or by calling `axum::serve`, which enabled HTTP/2.0 by default. Have a look at [Axum's HTTP2.0 example](https://github.com/tokio-rs/axum/blob/aeff16e91af6fa76efffdee8f3e5f464b458785b/examples/websockets-http2/src/main.rs#L57).

use crate::api::oprf::OprfModuleState;
use crate::metrics::{METRICS_ID_I_AM_ALIVE, METRICS_ID_NODE_SESSIONS_OPEN};
use crate::services::key_event_watcher::KeyEventWatcherTaskArgs;
use crate::services::open_sessions::OpenSessions;
use crate::services::oprf_key_material_store::OprfKeyMaterialStore;
use crate::{config::OprfNodeServiceConfig, services::secret_manager::SecretManagerService};
use axum::Router;
use eyre::Context as _;
use http::StatusCode;
use oprf_types::api::OprfRequestAuthService;
use oprf_types::chain::OprfKeyRegistry;
use oprf_types::crypto::PartyId;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

pub(crate) mod api;
pub mod config;
pub mod metrics;
pub(crate) mod services;

#[cfg(test)]
mod tests;

pub use nodes_common::Environment;
pub use nodes_common::StartedServices;
pub use nodes_common::web3;
pub use semver::VersionReq;
pub use services::oprf_key_material_store;
pub use services::secret_manager;

/// [`OprfServiceBuilder`] to initialize a `OprfService` with multiple [`OprfRequestAuthService`]s.
pub struct OprfServiceBuilder {
    config: OprfNodeServiceConfig,
    root: Router,
    api: Router,
    key_event_watcher: tokio::task::JoinHandle<Result<(), eyre::Error>>,
    open_sessions: OpenSessions,
    oprf_key_material_store: OprfKeyMaterialStore,
    party_id: PartyId,
    threshold: usize,
}

impl OprfServiceBuilder {
    /// Initializes the OPRF node service.
    ///
    /// Connects to the configured blockchain RPC endpoint, loads the node
    /// identity and cryptographic material, and starts the background tasks
    /// required for the service to operate.
    ///
    /// During initialization the service:
    /// - Connects to the Ethereum RPC provider.
    /// - Loads the node address from the secret manager.
    /// - Fetches the party ID and threshold from the `OprfKeyRegistry` contract.
    /// - Loads the OPRF key material from the secret manager.
    /// - Starts a refresh task that periodically reloads key material.
    /// - Spawns the `key_event_watcher` task which listens for registry events
    ///   and updates the local key material store.
    /// - Initializes the Axum router exposing the node API.
    ///
    /// # Errors
    /// Returns an error if the RPC connection fails, if loading secrets fails,
    /// or if reading required data from the contract fails.
    pub async fn init(
        config: OprfNodeServiceConfig,
        secret_manager: SecretManagerService,
        rpc_provider: web3::RpcProvider,
        started_services: StartedServices,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<Self> {
        ::metrics::gauge!(METRICS_ID_NODE_SESSIONS_OPEN).set(0);

        tracing::info!("loading address from secret-manager..");
        let address = secret_manager
            .load_address()
            .await
            .context("while loading address")?;

        tracing::info!("loading party id with address {address}..");
        let contract = OprfKeyRegistry::new(config.oprf_key_registry_contract, rpc_provider.http());
        let party_id = PartyId(
            contract
                .getPartyIdForParticipant(address)
                .call()
                .await
                .context("while loading party id")?
                .try_into()?,
        );
        tracing::info!("we are party id: {party_id}");

        let threshold = usize::from(
            contract
                .threshold()
                .call()
                .await
                .context("while loading threshold")?,
        );

        tracing::info!("init OPRF material-store..");
        let oprf_key_material_store = OprfKeyMaterialStore::new(
            secret_manager
                .load_secrets()
                .await
                .context("while loading secrets from secret-manager")?,
        );

        tracing::info!("spawning key event watcher..");
        let key_event_watcher = tokio::spawn({
            let rpc_provider = rpc_provider.clone();
            let contract_address = config.oprf_key_registry_contract;
            let cancellation_token = cancellation_token.clone();
            services::key_event_watcher::key_event_watcher_task(KeyEventWatcherTaskArgs {
                rpc_provider,
                contract_address,
                secret_manager,
                oprf_key_material_store: oprf_key_material_store.clone(),
                get_oprf_key_material_timeout: config.get_oprf_key_material_timeout,
                start_block: config.start_block,
                started: started_services.new_service(),
                cancellation_token,
            })
        });

        tracing::info!("init oprf-service...");
        let version_str = nodes_common::version_info!();
        let root = Router::new()
            .merge(nodes_common::api::routes_with_services(
                started_services.clone(),
                version_str,
            ))
            .merge(api::info::routes(oprf_key_material_store.clone(), address));

        tokio::task::spawn({
            let cancellation_token = cancellation_token.clone();
            let mut interval = tokio::time::interval(config.i_am_alive_interval);
            async move {
                tracing::info!("starting i am alive task");
                loop {
                    tokio::select! {
                       _ = interval.tick() => {
                            if started_services.all_started() {
                                ::metrics::counter!(METRICS_ID_I_AM_ALIVE).increment(1);
                            }
                       },
                       () = cancellation_token.cancelled() => {
                           break;
                       }
                    }
                }
                tracing::info!("shutting down i am alive task");
            }
        });

        Ok(Self {
            config,
            open_sessions: OpenSessions::default(),
            root,
            api: Router::new(),
            key_event_watcher,
            oprf_key_material_store,
            party_id,
            threshold,
        })
    }

    /// Add a new `OprfRequestAuthService` module with the given `path`.
    ///
    /// Each module represents a distinct OPRF service that can handle requests
    /// authenticated using the provided `OprfRequestAuthService`.
    ///
    /// # Parameters
    ///
    /// - `path`: The URL path where the OPRF module will be accessible (`/api/{path}`).
    /// - `service`: An instance of `OprfRequestAuthService` that will handle authentication for this module.
    #[must_use]
    pub fn module<RequestAuth: for<'de> Deserialize<'de> + Send + 'static>(
        mut self,
        path: &str,
        service: OprfRequestAuthService<RequestAuth>,
    ) -> Self {
        let args = Router::new().merge(self.api).nest(
            path,
            api::oprf::routes(OprfModuleState {
                party_id: self.party_id,
                threshold: self.threshold,
                oprf_material_store: self.oprf_key_material_store.clone(),
                req_auth_service: service,
                version_req: self.config.version_req.clone(),
                max_message_size: self.config.ws_max_message_size,
                max_connection_lifetime: self.config.session_lifetime,
                open_sessions: self.open_sessions.clone(),
            }),
        );
        self.api = args;
        self
    }

    /// Build the `axum` [`Router`] with all added oprf modules.
    ///
    /// # Returns
    ///
    /// Returns a tuple containing:
    /// - An Axum `Router` instance with the configured REST API routes.
    /// - A `JoinHandle` for the key event watcher task.
    ///
    /// # Panics
    ///
    /// - If no oprf modules were added
    pub fn build(self) -> (axum::Router, tokio::task::JoinHandle<eyre::Result<()>>) {
        assert!(self.api.has_routes(), "Needs at least 1 oprf-module");
        (
            self.root
                .nest("/api", self.api)
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    self.config.http_request_timeout,
                ))
                .layer(TraceLayer::new_for_http()),
            self.key_event_watcher,
        )
    }
}
