#![deny(missing_docs)]
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
//!    - the module router calls [`oprf_types::api::OprfRequestAuthenticator::verify`] of the provided authentication implementation. This can be anything from no verification to providing credentials.
//!    - the node creates a session identified by a UUID and sends a commitment back to the user.
//! 2) As soon as end-users have opened $t$ sessions, they compute challenges for the answering nodes.
//!    - the router answers the challenge and deletes all information containing the sessions.
//!
//! For details on the OPRF protocol, see the [design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf).
//!
//! Clients will connect via web-sockets to the OPRF node. Axum supports both HTTP/1.1 and HTTP/2.0 web-socket connections, therefore we accept connections with `any`.
//!
//! If you want to enable HTTP/2.0, you either have to do it by hand or by calling `axum::serve`, which enabled HTTP/2.0 by default. Have a look at [Axum's HTTP2.0 example](https://github.com/tokio-rs/axum/blob/aeff16e91af6fa76efffdee8f3e5f464b458785b/examples/websockets-http2/src/main.rs#L57).

use crate::api::oprf::OprfArgs;
use crate::metrics::METRICS_ID_NODE_SESSIONS_OPEN;
use crate::services::key_event_watcher::KeyEventWatcherTaskArgs;
use crate::services::open_sessions::OpenSessions;
use crate::services::oprf_key_material_store::OprfKeyMaterialStore;
use crate::{config::OprfNodeConfig, services::secret_manager::SecretManagerService};
use alloy::providers::{Provider as _, ProviderBuilder, WsConnect};
use axum::Router;
use eyre::Context as _;
use oprf_types::api::OprfRequestAuthService;
use oprf_types::chain::OprfKeyRegistry;
use oprf_types::crypto::PartyId;
use secrecy::ExposeSecret as _;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tower_http::trace::TraceLayer;

pub(crate) mod api;
pub mod config;
pub mod metrics;
pub(crate) mod services;

pub use services::StartedServices;
pub use services::oprf_key_material_store;
pub use services::secret_manager;

/// [`OprfServiceBuilder`] to initialize a `OprfService` with multiple [`OprfRequestAuthService`]s.
pub struct OprfServiceBuilder {
    config: OprfNodeConfig,
    root: Router,
    api: Router,
    key_event_watcher: tokio::task::JoinHandle<Result<(), eyre::Error>>,
    open_sessions: OpenSessions,
    oprf_key_material_store: OprfKeyMaterialStore,
    party_id: PartyId,
    threshold: usize,
}

impl OprfServiceBuilder {
    /// Initializes the OPRF service.
    ///
    /// This function sets up the necessary components and services required for the OPRF node
    /// to operate. It performs the following steps:
    ///
    /// 1. Loads or generates the Ethereum wallet private key from the secret manager.
    /// 2. Initializes the Ethereum RPC provider using the wallet and the provided WebSocket RPC URL.
    /// 3. Loads the party ID from the OPRF key registry contract.
    /// 4. Loads cryptographic secrets from the secret manager.
    /// 5. Initializes the distributed logarithm (DLog) secret generation service using the key generation material.
    /// 6. Spawns a task to watch for key events from the OPRF key registry contract and updates the secret manager accordingly.
    /// 7. Initializes the OPRF service, to which multiple OPRF modules can be added.
    /// 8. Sets up the Axum-based REST API routes for the OPRF service.
    pub async fn init(
        config: OprfNodeConfig,
        secret_manager: SecretManagerService,
        mut started_services: StartedServices,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<Self> {
        ::metrics::gauge!(METRICS_ID_NODE_SESSIONS_OPEN).set(0);
        tracing::info!("init rpc provider..");
        let ws = WsConnect::new(config.chain_ws_rpc_url.expose_secret());
        let provider = ProviderBuilder::new()
            .connect_ws(ws)
            .await
            .context("while connecting to RPC")?
            .erased();

        tracing::info!("loading address from secret-manager..");
        let address = secret_manager
            .load_address()
            .await
            .context("while loading address")?;

        tracing::info!("loading party id with address {address}..");
        let contract = OprfKeyRegistry::new(config.oprf_key_registry_contract, provider.clone());
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
        let oprf_key_material_store = secret_manager
            .load_secrets()
            .await
            .context("while loading secrets from secret-manager")?;

        tracing::info!("spawning key event watcher..");
        let key_event_watcher = tokio::spawn({
            let provider = provider.clone();
            let contract_address = config.oprf_key_registry_contract;
            let cancellation_token = cancellation_token.clone();
            services::key_event_watcher::key_event_watcher_task(KeyEventWatcherTaskArgs {
                provider,
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
        let root = Router::new()
            .merge(api::health::routes(started_services.clone()))
            .merge(api::info::routes(
                oprf_key_material_store.clone(),
                address,
                config.region.clone(),
            ));

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
    pub fn module<
        RequestAuth: for<'de> Deserialize<'de> + Send + 'static,
        RequestAuthError: Send + 'static + std::error::Error,
    >(
        mut self,
        path: &str,
        service: OprfRequestAuthService<RequestAuth, RequestAuthError>,
    ) -> Self {
        let args = Router::new().merge(self.api).nest(
            path,
            api::oprf::routes(OprfArgs {
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
        if !self.api.has_routes() {
            panic!("add at least 1 oprf module");
        }
        (
            self.root
                .nest("/api", self.api)
                .layer(TraceLayer::new_for_http()),
            self.key_event_watcher,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fmt, sync::Arc};

    use alloy::uint;
    use ark_ff::UniformRand as _;

    use async_trait::async_trait;
    use axum_extra::headers::Header as _;
    use axum_test::{TestServer, TestWebSocket};
    use http::StatusCode;
    use oprf_core::{
        ddlog_equality::shamir::{DLogCommitmentsShamir, DLogProofShareShamir, DLogShareShamir},
        oprf::BlindingFactor,
    };
    use oprf_types::{
        OprfKeyId, ShareEpoch,
        api::{OprfRequest, OprfRequestAuthenticator, OprfResponse},
        crypto::{OprfKeyMaterial, OprfPublicKey},
    };
    use semver::VersionReq;
    use uuid::Uuid;

    use crate::{
        api::oprf::ProtocolVersion, oprf_key_material_store::OprfKeyMaterialStore,
        services::open_sessions::OpenSessions,
    };

    use super::*;

    /// An implementation of `OprfRequestAuthenticator` that performs no authentication.
    pub struct WithoutAuthentication;

    /// Error type for [`WithoutAuthentication`]. Will never be constructed during ordinary flow.
    #[derive(Debug, Clone, Copy)]
    pub struct WithoutAuthenticationError;

    impl fmt::Display for WithoutAuthenticationError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("you failed the no-authentication authentication")
        }
    }

    impl std::error::Error for WithoutAuthenticationError {}

    #[async_trait]
    impl OprfRequestAuthenticator for WithoutAuthentication {
        type RequestAuth = ();
        type RequestAuthError = WithoutAuthenticationError;

        async fn verify(
            &self,
            _req: &OprfRequest<Self::RequestAuth>,
        ) -> Result<(), Self::RequestAuthError> {
            Ok(())
        }
    }

    struct TestOprfNode {
        websocket: TestWebSocket,
        websocket_session_reuse: TestWebSocket,
    }

    impl TestOprfNode {
        async fn send_oprf_request(&mut self, req: &OprfRequest<()>) {
            let oprf_req = serde_json::to_string(req).expect("can serialize");
            self.websocket.send_text(&oprf_req).await;
        }

        async fn receive_oprf_response(&mut self) -> OprfResponse {
            let oprf_res = self.websocket.receive_text().await;
            serde_json::from_str::<OprfResponse>(&oprf_res).expect("can deserialize")
        }

        async fn send_challenge_request(&mut self, req: &DLogCommitmentsShamir) {
            let challenge_req = serde_json::to_string(req).expect("can serialize");
            self.websocket.send_text(&challenge_req).await;
        }

        async fn receive_challenge_response(&mut self) -> DLogProofShareShamir {
            let challenge_res = self.websocket.receive_text().await;
            serde_json::from_str::<DLogProofShareShamir>(&challenge_res).expect("can deserialize")
        }
    }

    async fn test_setup() -> (
        TestOprfNode,
        OprfRequest<()>,
        DLogCommitmentsShamir,
        TestServer,
    ) {
        let mut rng = rand::thread_rng();
        let oprf_key_id = OprfKeyId::new(uint!(0_U160));
        let request_id = Uuid::new_v4();
        let blinding_factor = BlindingFactor::rand(&mut rng);
        let query = ark_babyjubjub::Fq::rand(&mut rng);

        let blinded_request = oprf_core::oprf::client::blind_query(query, blinding_factor.clone());
        let oprf_req = OprfRequest {
            request_id,
            blinded_query: blinded_request.blinded_query(),
            oprf_key_id,
            auth: (),
        };
        let challenge_req = DLogCommitmentsShamir::new(
            ark_babyjubjub::EdwardsAffine::rand(&mut rng),
            ark_babyjubjub::EdwardsAffine::rand(&mut rng),
            ark_babyjubjub::EdwardsAffine::rand(&mut rng),
            ark_babyjubjub::EdwardsAffine::rand(&mut rng),
            ark_babyjubjub::EdwardsAffine::rand(&mut rng),
            vec![0, 1],
        );
        let oprf_material_store = OprfKeyMaterialStore::new(HashMap::from([(
            oprf_key_id,
            OprfKeyMaterial::new(
                DLogShareShamir::from(ark_babyjubjub::Fr::rand(&mut rng)),
                OprfPublicKey::new(ark_babyjubjub::EdwardsAffine::default()),
                ShareEpoch::default(),
            ),
        )]));
        let router = api::oprf::routes(api::oprf::OprfArgs {
            party_id: PartyId(0),
            threshold: 2,
            oprf_material_store,
            open_sessions: OpenSessions::default(),
            req_auth_service: Arc::new(WithoutAuthentication),
            version_req: VersionReq::parse("=1.3.101").expect("Works"),
            max_message_size: 1024 * 1024,
            max_connection_lifetime: std::time::Duration::from_secs(60),
        });
        let server = TestServer::builder()
            .http_transport()
            .build(router)
            .expect("failed to build test server");
        let websocket = server
            .get_websocket("/oprf")
            .add_header(ProtocolVersion::name(), "1.3.101")
            .await
            .into_websocket()
            .await;
        let websocket_session_reuse = server
            .get_websocket("/oprf")
            .add_header(ProtocolVersion::name(), "1.3.101")
            .await
            .into_websocket()
            .await;

        (
            TestOprfNode {
                websocket,
                websocket_session_reuse,
            },
            oprf_req,
            challenge_req,
            server,
        )
    }

    #[tokio::test]
    async fn init_and_challenge() -> eyre::Result<()> {
        let (mut node, oprf_req, challenge_req, _) = test_setup().await;
        node.send_oprf_request(&oprf_req).await;
        node.receive_oprf_response().await;
        node.send_challenge_request(&challenge_req).await;
        node.receive_challenge_response().await;
        Ok(())
    }

    #[tokio::test]
    async fn wrong_client_version() -> eyre::Result<()> {
        let (_, _, _, server) = test_setup().await;
        let invalid_request = server
            .get_websocket("/oprf")
            .add_header(ProtocolVersion::name(), "2.0.0")
            .await;
        assert_eq!(invalid_request.status_code(), StatusCode::BAD_REQUEST);
        invalid_request.assert_text("invalid version, expected: =1.3.101");
        Ok(())
    }

    #[tokio::test]
    async fn no_protocol_version_header() -> eyre::Result<()> {
        let (_, _, _, server) = test_setup().await;
        let invalid_request = server.get_websocket("/oprf").await;
        assert_eq!(invalid_request.status_code(), StatusCode::BAD_REQUEST);
        invalid_request.assert_text("Header of type `x-taceo-oprf-protocol-version` was missing");
        Ok(())
    }

    #[tokio::test]
    async fn init_unknown_oprf_key_id() -> eyre::Result<()> {
        let (mut node, mut oprf_req, _, _) = test_setup().await;
        oprf_req.oprf_key_id = OprfKeyId::new(uint!(1_U160));
        node.send_oprf_request(&oprf_req).await;
        node.websocket
            .assert_receive_text("unknown OPRF key id: 1")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn init_session_reuse() -> eyre::Result<()> {
        let (mut node, oprf_req, _, _) = test_setup().await;
        node.send_oprf_request(&oprf_req).await;
        node.websocket_session_reuse
            .send_text(serde_json::to_string(&oprf_req)?)
            .await;
        node.websocket_session_reuse
            .assert_receive_text(format!("session {} already exists", oprf_req.request_id))
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn init_bad_blinded_query() -> eyre::Result<()> {
        let (mut node, mut oprf_req, _, _) = test_setup().await;
        oprf_req.blinded_query = ark_babyjubjub::EdwardsAffine::zero();
        node.send_oprf_request(&oprf_req).await;
        node.websocket
            .assert_receive_text("blinded query must not be identity")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn init_bad_request() -> eyre::Result<()> {
        let (mut node, _, _, _) = test_setup().await;
        node.websocket.send_text("{ \"foo\": 1 }").await;
        node.websocket
            .assert_receive_text("missing field `request_id` at line 1 column 12")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn challenge_without_init() -> eyre::Result<()> {
        let (mut node, _, challenge_req, _) = test_setup().await;
        node.send_challenge_request(&challenge_req).await;
        node.websocket
            .assert_receive_text_contains("missing field `request_id`")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn challenge_bad_contributing_parties() -> eyre::Result<()> {
        let mut rng = rand::thread_rng();
        let (mut node, oprf_req, _, _) = test_setup().await;
        node.send_oprf_request(&oprf_req).await;
        node.receive_oprf_response().await;
        let challenge_req = DLogCommitmentsShamir::new(
            ark_babyjubjub::EdwardsAffine::rand(&mut rng),
            ark_babyjubjub::EdwardsAffine::rand(&mut rng),
            ark_babyjubjub::EdwardsAffine::rand(&mut rng),
            ark_babyjubjub::EdwardsAffine::rand(&mut rng),
            ark_babyjubjub::EdwardsAffine::rand(&mut rng),
            vec![42],
        );
        node.send_challenge_request(&challenge_req).await;
        node.websocket
            .assert_receive_text("expected 2 contributing parties but got 1")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn challenge_bad_not_a_contributing_party() -> eyre::Result<()> {
        let mut rng = rand::thread_rng();
        let (mut node, oprf_req, _, _) = test_setup().await;
        node.send_oprf_request(&oprf_req).await;
        node.receive_oprf_response().await;
        let challenge_req = DLogCommitmentsShamir::new(
            ark_babyjubjub::EdwardsAffine::rand(&mut rng),
            ark_babyjubjub::EdwardsAffine::rand(&mut rng),
            ark_babyjubjub::EdwardsAffine::rand(&mut rng),
            ark_babyjubjub::EdwardsAffine::rand(&mut rng),
            ark_babyjubjub::EdwardsAffine::rand(&mut rng),
            vec![2, 3], // parties 0 and 1 with coeffs 1 and 2
        );
        node.send_challenge_request(&challenge_req).await;
        node.websocket
            .assert_receive_text("contributing parties does not contain my coefficient (1)")
            .await;
        Ok(())
    }
}
