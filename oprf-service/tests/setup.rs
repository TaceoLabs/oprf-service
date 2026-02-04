use core::fmt;
use std::{sync::Arc, time::Duration};

use ark_ff::UniformRand as _;
use async_trait::async_trait;
use axum_test::TestServer;
use http::StatusCode;
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
use serde::{Deserialize, Serialize};
use taceo_oprf_service::{
    OprfServiceBuilder, StartedServices,
    config::{Environment, OprfNodeConfig},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

oprf_node_test_secret_manager!(
    taceo_oprf_service::secret_manager::SecretManager,
    NodeTestSecretManager
);

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ConfigurableTestRequestAuth;

#[derive(Debug, thiserror::Error)]
#[allow(unused)]
pub(crate) enum TestError {
    #[error("invalid")]
    Invalid,
}
pub(crate) struct ConfigurableTestAuthenticator;

#[async_trait]
impl OprfRequestAuthenticator for ConfigurableTestAuthenticator {
    type RequestAuth = ConfigurableTestRequestAuth;
    type RequestAuthError = TestError;

    async fn verify(
        &self,
        _request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<(), Self::RequestAuthError> {
        Ok(())
    }
}

pub struct TestNode {
    pub party_id: usize,
    pub secret_manager: Arc<TestSecretManager>,
    pub server: Arc<TestServer>,
    pub _cancellation_token: CancellationToken,
}

impl fmt::Debug for TestNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestNode")
            .field("party_id", &self.party_id)
            .finish()
    }
}

impl TestNode {
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
            get_oprf_key_material_timeout: Duration::from_secs(60),
            start_block: None,
            version_req: "1.0.0".parse().unwrap(),
            region: "EU".to_owned(),
            db_connection_string: SecretString::from("connection-string"),
            db_max_connections: 1.try_into().unwrap(),
            db_schema: "schema".to_owned(),
        };

        let child_token = cancellation_token.child_token();

        let (service, _) = OprfServiceBuilder::init(
            config,
            Arc::new(NodeTestSecretManager(Arc::clone(&secret_manager))),
            StartedServices::new(),
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
            _cancellation_token: child_token,
            server: Arc::new(server),
            party_id,
        })
    }

    pub async fn start(party_id: usize, setup: &TestSetup) -> eyre::Result<Self> {
        Self::start_with_secret_manager(
            party_id,
            setup,
            Arc::new(TestSecretManager::new(PEER_PRIVATE_KEYS[party_id])),
        )
        .await
    }

    pub async fn _start_three(test_setup: &TestSetup) -> eyre::Result<[Self; 3]> {
        let (node0, node1, node2) = tokio::join!(
            Self::start(0, test_setup),
            Self::start(1, test_setup),
            Self::start(2, test_setup)
        );
        Ok([node0?, node1?, node2?])
    }

    pub async fn _start_five(test_setup: &TestSetup) -> eyre::Result<[Self; 5]> {
        let (node0, node1, node2, node3, node4) = tokio::join!(
            Self::start(0, test_setup),
            Self::start(1, test_setup),
            Self::start(2, test_setup),
            Self::start(3, test_setup),
            Self::start(4, test_setup)
        );
        Ok([node0?, node1?, node2?, node3?, node4?])
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

    pub async fn init_request<R: Rng + CryptoRng>(
        &self,
        oprf_key_id: OprfKeyId,
        rng: &mut R,
    ) -> OprfResponse {
        let blinding_factor = BlindingFactor::rand(rng);
        let query = ark_babyjubjub::Fq::rand(rng);
        let blinded_request = oprf_core::oprf::client::blind_query(query, blinding_factor.clone());
        let oprf_req = OprfRequest {
            request_id: Uuid::new_v4(),
            blinded_query: blinded_request.blinded_query(),
            oprf_key_id,
            auth: (),
        };
        let mut websocket = self
            .server
            .get_websocket("/api/test/oprf")
            .add_header(
                oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
                "1.3.101",
            )
            .await
            .into_websocket()
            .await;
        websocket.send_json(&oprf_req).await;
        websocket.receive_json().await
    }

    pub async fn oprf_expect_error<R: Rng + CryptoRng>(
        &self,
        oprf_key_id: OprfKeyId,
        msg: String,
        rng: &mut R,
    ) {
        let blinding_factor = BlindingFactor::rand(rng);
        let query = ark_babyjubjub::Fq::rand(rng);
        let blinded_request = oprf_core::oprf::client::blind_query(query, blinding_factor.clone());
        let oprf_req = OprfRequest {
            request_id: Uuid::new_v4(),
            blinded_query: blinded_request.blinded_query(),
            oprf_key_id,
            auth: (),
        };
        let mut websocket = self
            .server
            .get_websocket("/api/test/oprf")
            .add_header(
                oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
                "1.3.101",
            )
            .await
            .into_websocket()
            .await;
        websocket.send_json(&oprf_req).await;
        websocket.assert_receive_text(msg).await;
    }
}
