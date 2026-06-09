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
//! It loads node information (party ID, address) from the secret manager and initializes a cache-backed key material store.
//! With the [`OprfServiceBuilder::module`] method, implementations can add multiple OPRF modules, each with its own authentication mechanism.
//! Finally, the [`OprfServiceBuilder::build`] method returns an `axum::Router` that should be incorporated into a larger `axum` server that provides project-based functionality for authentication.
//!
//! If internal services of the OPRF service encounter an error, the provided `CancellationToken` will be cancelled, allowing the hosting application to handle the shutdown process gracefully.
//! Additionally, the `CancellationToken` can be cancelled externally to signal the OPRF service to stop its operations.
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

use std::fmt;
use std::num::NonZeroU16;

use crate::api::oprf::OprfModuleState;
use crate::services::open_sessions::OpenSessions;
use crate::services::oprf_key_material_store::OprfKeyMaterialStore;
use crate::{config::OprfNodeServiceConfig, services::secret_manager::SecretManagerService};
use axum::Router;
use axum::extract::MatchedPath;
use eyre::Context;
use http::{HeaderMap, HeaderName, Method, StatusCode};
use oprf_types::api::OprfRequestAuthService;
use oprf_types::crypto::PartyId;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{MakeSpan, TraceLayer};

pub(crate) mod api;
pub mod config;
pub mod metrics;
pub(crate) mod services;

#[cfg(test)]
mod tests;

pub use nodes_common::{Environment, StartedServices, web3};
pub use semver::VersionReq;
pub use services::secret_manager;

/// [`OprfServiceBuilder`] to initialize a `OprfService` with multiple [`OprfRequestAuthService`]s.
///
/// Beyond the OPRF modules added via [`OprfServiceBuilder::module`], the builder always exposes a
/// set of read-only info routes at the root (not under `/api`):
/// - `GET /health`
/// - `GET /version`
/// - `GET /wallet`
/// - `GET /oprf_pub/{id}`
///
/// CORS for those info routes is **opt-in**: call [`OprfServiceBuilder::cors_for_info`] before
/// [`OprfServiceBuilder::build`] to allow cross-origin `GET` requests from any origin.
pub struct OprfServiceBuilder {
    config: OprfNodeServiceConfig,
    info_routes: Router,
    api: Router,
    open_sessions: OpenSessions,
    oprf_key_material_store: OprfKeyMaterialStore,
    party_id: PartyId,
    threshold: NonZeroU16,
}

impl OprfServiceBuilder {
    /// Initializes the OPRF node service.
    ///
    /// During initialization the service:
    /// - Loads node information (party ID, address) from the secret manager.
    /// - Initializes the cache-backed OPRF key material store.
    /// - Initializes the Axum router exposing the node API.
    ///
    /// # Errors
    /// Returns an error if loading node information from the secret manager fails.
    pub async fn init(
        config: OprfNodeServiceConfig,
        secret_manager: SecretManagerService,
        started_services: StartedServices,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<Self> {
        tracing::info!("loading node-information from secret-manager..");
        let node_information = secret_manager
            .load_node_information()
            .await
            .context("while loading node information")?;

        tracing::info!("node information: {node_information:#?}");

        tracing::info!("init OPRF material-store..");
        let oprf_key_material_store = OprfKeyMaterialStore::new(
            secret_manager,
            config.store_max_capacity,
            config.store_ttl,
            config.store_tti,
        );

        tracing::info!("init oprf-service...");

        let version_str = nodes_common::version_info!();
        let info_route = Router::new()
            .merge(nodes_common::api::routes_with_services(
                started_services.clone(),
                version_str,
            ))
            .merge(api::info::routes(
                oprf_key_material_store.clone(),
                node_information.address(),
            ));

        tokio::task::spawn({
            let cancellation_token = cancellation_token.clone();
            let mut interval = tokio::time::interval(config.i_am_alive_interval);
            async move {
                tracing::info!("starting i am alive task");
                loop {
                    tokio::select! {
                       _ = interval.tick() => {
                            if started_services.all_started() {
                                metrics::health::inc_i_am_alive();
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
            open_sessions: OpenSessions::new(),
            info_routes: info_route,
            api: Router::new(),
            oprf_key_material_store,
            party_id: node_information.party_id(),
            threshold: node_information.threshold(),
            config,
        })
    }

    /// Adds a CORS layer for the `info` routes.
    ///
    /// This CORS layer uses the default values from [`CorsLayer`](https://docs.rs/tower-http/latest/tower_http/cors/struct.CorsLayer.html) and
    /// explicitly sets allow-methods to `GET` and a wild-card for allowed origins.
    ///
    /// The layer is applied only to the info routes (served at the root, not under `/api`).
    #[must_use]
    pub fn cors_for_info(mut self) -> Self {
        let cors = CorsLayer::new()
            .allow_methods([Method::GET])
            .allow_origin(AllowOrigin::any());
        self.info_routes = self.info_routes.layer(cors);
        self
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
    /// # Panics
    ///
    /// - If no oprf modules were added
    pub fn build(self) -> axum::Router {
        assert!(self.api.has_routes(), "Needs at least 1 oprf-module");
        // setup the dedicated HTTP trace layer for the auth modules
        let auth_modules = self
            .api
            .layer(TraceLayer::new_for_http().make_span_with(OprfAuthModulesMakeSpan));

        Router::new()
            .merge(self.info_routes)
            .nest("/api", auth_modules)
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                self.config.http_request_timeout,
            ))
    }
}

#[derive(Clone, Copy)]
struct OprfAuthModulesMakeSpan;

struct FilteredHeaders<'a>(&'a HeaderMap);

const ALLOWED_HEADERS: &[HeaderName] = &[
    http::header::HOST,
    http::header::ORIGIN,
    http::header::USER_AGENT,
];

impl fmt::Debug for FilteredHeaders<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (name, value) in self.0 {
            if ALLOWED_HEADERS.contains(name) {
                map.entry(&name, &value);
            }
        }
        map.finish()
    }
}

impl<B> MakeSpan<B> for OprfAuthModulesMakeSpan {
    fn make_span(&mut self, request: &http::Request<B>) -> tracing::Span {
        let matched_path = request
            .extensions()
            .get::<MatchedPath>()
            .map_or_else(|| request.uri().path(), MatchedPath::as_str);
        tracing::info_span!(
            "oprf_request",
            request_id = tracing::field::Empty,
            oprf_key_id = tracing::field::Empty,
            client_version = tracing::field::Empty,
            method = %request.method(),
            path = %matched_path,
            version = ?request.version(),
            headers = ?FilteredHeaders(request.headers()),
        )
    }
}
