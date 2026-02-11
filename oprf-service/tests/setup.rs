use core::fmt;
use std::{sync::Arc, time::Duration};

use ark_ff::UniformRand as _;
use async_trait::async_trait;
use axum_test::{TestServer, TestWebSocket};
use http::StatusCode;
use nodes_common::StartedServices;
use oprf_core::ddlog_equality::shamir::{DLogCommitmentsShamir, DLogProofShareShamir};
use oprf_core::oprf::BlindingFactor;
use oprf_test_utils::{
    PEER_PRIVATE_KEYS, TEST_TIMEOUT, TestSetup, oprf_node_test_secret_manager,
    test_secret_manager::TestSecretManager,
};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    api::{OprfPublicKeyWithEpoch, OprfRequest, OprfRequestAuthenticator, OprfResponse},
    crypto::OprfPublicKey,
};
use rand::{CryptoRng, Rng};
use secrecy::SecretString;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use taceo_oprf_service::{
    OprfServiceBuilder,
    config::{Environment, OprfNodeConfig},
};
use tokio_util::sync::CancellationToken;
use tungstenite::protocol::CloseFrame;
use uuid::Uuid;

pub const OPRF_KEY_ID: u32 = 42;
pub const TEST_PROTOCOL_VERSION: &str = "1.3.101";

oprf_node_test_secret_manager!(taceo_oprf_service::secret_manager, NodeTestSecretManager);

#[derive(Clone, Copy, Debug)]
pub enum WireFormat {
    Json,
    Cbor,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ConfigurableTestRequestAuth(pub OprfKeyId);

#[derive(Debug, thiserror::Error)]
#[allow(unused)]
pub enum TestError {
    #[error("invalid")]
    Invalid,
}
pub struct ConfigurableTestAuthenticator;

#[async_trait]
impl OprfRequestAuthenticator for ConfigurableTestAuthenticator {
    type RequestAuth = ConfigurableTestRequestAuth;
    type RequestAuthError = TestError;

    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, Self::RequestAuthError> {
        let ConfigurableTestRequestAuth(oprf_key_id) = &request.auth;
        if *oprf_key_id == OprfKeyId::from(OPRF_KEY_ID) {
            Ok(*oprf_key_id)
        } else {
            Err(TestError::Invalid)
        }
    }
}

pub struct TestNode {
    pub party_id: usize,
    pub secret_manager: Arc<TestSecretManager>,
    pub server: Arc<TestServer>,
    pub started_services: StartedServices,
    pub key_event_watcher_task: tokio::task::JoinHandle<eyre::Result<()>>,
    pub cancellation_token: CancellationToken,
}

impl fmt::Debug for TestNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestNode")
            .field("party_id", &self.party_id)
            .finish()
    }
}

impl TestNode {
    async fn create_websocket(&self) -> TestWebSocket {
        self.server
            .get_websocket("/api/test/oprf")
            .add_header(
                oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
                TEST_PROTOCOL_VERSION,
            )
            .await
            .into_websocket()
            .await
    }

    pub async fn start_with_secret_manager(
        party_id: usize,
        setup: &TestSetup,
        secret_manager: Arc<TestSecretManager>,
    ) -> eyre::Result<Self> {
        let TestSetup {
            anvil,
            provider: _,
            oprf_key_registry,
            cancellation_token,
            setup: _,
        } = setup;
        assert!(party_id < 5, "can only spawn 5 nodes");

        let config = OprfNodeConfig {
            environment: Environment::Dev,
            oprf_key_registry_contract: *oprf_key_registry,
            chain_ws_rpc_url: anvil.ws_endpoint().into(),
            ws_max_message_size: 1024 * 1024,
            session_lifetime: Duration::from_secs(10),
            reload_key_material_interval: Duration::from_secs(3600),
            get_oprf_key_material_timeout: Duration::from_secs(60),
            start_block: None,
            version_req: "1.0.0".parse().unwrap(),
            region: "EU".to_owned(),
            db_connection_string: SecretString::from("connection-string"),
            db_max_connections: 1.try_into().unwrap(),
            db_schema: "schema".to_owned(),
            db_acquire_timeout: Duration::from_secs(2),
            db_retry_delay: Duration::from_secs(1),
            db_max_retries: 30.try_into().expect("Is non zero"),
        };

        let child_token = cancellation_token.child_token();

        let started_services = StartedServices::new();
        let (service, key_event_watcher_task) = OprfServiceBuilder::init(
            config,
            Arc::new(NodeTestSecretManager(Arc::clone(&secret_manager))),
            started_services.clone(),
            child_token.clone(),
        )
        .await?
        .module("/test", Arc::new(ConfigurableTestAuthenticator))
        .build();
        let server = TestServer::builder()
            .http_transport()
            .build(service)
            .expect("Can build test-server");
        Ok(TestNode {
            secret_manager,
            cancellation_token: child_token,
            key_event_watcher_task,
            started_services,
            server: Arc::new(server),
            party_id,
        })
    }

    pub async fn start(party_id: usize, setup: &TestSetup) -> eyre::Result<Self> {
        Self::start_with_key(party_id, setup, OPRF_KEY_ID).await
    }

    pub async fn start_with_key(
        party_id: usize,
        setup: &TestSetup,
        oprf_key_id: u32,
    ) -> eyre::Result<Self> {
        let secret_manager = Arc::new(TestSecretManager::new(PEER_PRIVATE_KEYS[party_id]));
        let key_id = OprfKeyId::from(oprf_key_id);
        secret_manager.add_random_key_material_with_id(key_id, &mut rand::thread_rng());
        Self::start_with_secret_manager(party_id, setup, secret_manager).await
    }

    pub async fn happy_path(&self, format: WireFormat) {
        let mut rng = rand::thread_rng();
        let mut ws = self.send_success_init_request(format, &mut rng).await;
        ws_send(&mut ws, &random_challenge(&mut rng, vec![1, 2]), format).await;
        // Can deserialize
        let _response = ws_recv::<DLogProofShareShamir>(&mut ws, format).await;
    }

    pub async fn has_key(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        should_key: OprfPublicKey,
    ) -> eyre::Result<()> {
        let server = Arc::clone(&self.server);
        let is_key = tokio::time::timeout(TEST_TIMEOUT, async move {
            let url = format!("/oprf_pub/{oprf_key_id}");
            loop {
                let response = server.get(&url).await.text();
                if let Ok(response) = serde_json::from_str::<OprfPublicKeyWithEpoch>(&response)
                    && response.epoch == epoch
                {
                    break response.key;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await?;
        assert_eq!(is_key, should_key);
        Ok(())
    }
    pub async fn doesnt_have_key(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        let server = Arc::clone(&self.server);
        tokio::time::timeout(TEST_TIMEOUT, async move {
            let url = format!("/oprf_pub/{oprf_key_id}");
            loop {
                if server.get(&url).await.status_code() == StatusCode::NOT_FOUND {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await?;
        Ok(())
    }

    pub async fn send_success_init_request<R: Rng + CryptoRng>(
        &self,
        format: WireFormat,
        rng: &mut R,
    ) -> TestWebSocket {
        let mut websocket = self.send_request(request(rng), format).await;
        // just deserialize to see that the response was correct
        let resp: OprfResponse = match format {
            WireFormat::Json => websocket.receive_json().await,
            WireFormat::Cbor => ciborium::from_reader(websocket.receive_bytes().await.as_ref())
                .expect("Can deserialize Cbor"),
        };
        assert_eq!(
            resp.party_id.0,
            u16::try_from(self.party_id).expect("Fits into u16")
        );
        let should_oprf_public_key = self
            .secret_manager
            .get_key_material(OprfKeyId::from(OPRF_KEY_ID))
            .expect("Is there")
            .public_key_with_epoch();
        assert_eq!(resp.oprf_pub_key_with_epoch, should_oprf_public_key);
        websocket
    }

    pub async fn send_request(
        &self,
        oprf_req: OprfRequest<ConfigurableTestRequestAuth>,
        format: WireFormat,
    ) -> TestWebSocket {
        let mut websocket = self.create_websocket().await;
        ws_send(&mut websocket, &oprf_req, format).await;
        websocket
    }

    pub async fn init_expect_error<T: Serialize>(
        &self,
        oprf_req: T,
        format: WireFormat,
        should_close_frame: CloseFrame,
    ) {
        let mut websocket = self.create_websocket().await;
        ws_send(&mut websocket, &oprf_req, format).await;
        let is_message = websocket.receive_message().await;
        assert_close_frame(is_message, should_close_frame);
    }

    pub async fn challenge_expect_error<T: Serialize>(
        &self,
        websocket: &mut TestWebSocket,
        oprf_req: T,
        format: WireFormat,
        should_close_frame: CloseFrame,
    ) {
        ws_send(websocket, &oprf_req, format).await;
        let is_message = websocket.receive_message().await;
        assert_close_frame(is_message, should_close_frame);
    }
}

pub fn assert_close_frame(is_message: tungstenite::Message, should_close_frame: CloseFrame) {
    match is_message {
        tungstenite::Message::Close(Some(is_close_frame)) => {
            assert_eq!(is_close_frame, should_close_frame)
        }
        _ => panic!("unexpected message - expected CloseFrame"),
    }
}

pub fn request<R: Rng + CryptoRng>(rng: &mut R) -> OprfRequest<ConfigurableTestRequestAuth> {
    request_with_id(OprfKeyId::from(OPRF_KEY_ID), rng)
}

pub fn request_with_id<R: Rng + CryptoRng>(
    oprf_key_id: OprfKeyId,
    rng: &mut R,
) -> OprfRequest<ConfigurableTestRequestAuth> {
    let blinding_factor = BlindingFactor::rand(rng);
    let query = ark_babyjubjub::Fq::rand(rng);
    let blinded_request = oprf_core::oprf::client::blind_query(query, blinding_factor.clone());
    OprfRequest {
        request_id: Uuid::new_v4(),
        blinded_query: blinded_request.blinded_query(),
        auth: ConfigurableTestRequestAuth(oprf_key_id),
    }
}

pub async fn ws_send<T: Serialize>(ws: &mut TestWebSocket, value: &T, format: WireFormat) {
    match format {
        WireFormat::Json => {
            ws.send_json(value).await;
        }
        WireFormat::Cbor => {
            let mut buf = Vec::new();
            ciborium::into_writer(&value, &mut buf).expect("Can serialize response");
            ws.send_message(tungstenite::Message::Binary(buf.into()))
                .await;
        }
    }
}

pub async fn ws_recv<T: DeserializeOwned>(ws: &mut TestWebSocket, format: WireFormat) -> T {
    match format {
        WireFormat::Json => ws.receive_json().await,
        WireFormat::Cbor => {
            ciborium::from_reader(ws.receive_bytes().await.as_ref()).expect("Can deserialize")
        }
    }
}

pub fn random_challenge<R: Rng + CryptoRng>(
    rng: &mut R,
    contributing_parties: Vec<u16>,
) -> DLogCommitmentsShamir {
    DLogCommitmentsShamir::new(
        ark_babyjubjub::EdwardsAffine::rand(rng),
        ark_babyjubjub::EdwardsAffine::rand(rng),
        ark_babyjubjub::EdwardsAffine::rand(rng),
        ark_babyjubjub::EdwardsAffine::rand(rng),
        ark_babyjubjub::EdwardsAffine::rand(rng),
        contributing_parties,
    )
}
