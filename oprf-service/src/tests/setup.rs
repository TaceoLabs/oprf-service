use core::fmt;
use std::num::NonZeroU32;
use std::{sync::Arc, time::Duration};

use ark_ff::UniformRand as _;
use ark_serialize::CanonicalSerialize;
use async_trait::async_trait;
use axum_test::{TestServer, TestWebSocket};
use eyre::Context as _;
use http::StatusCode;
use nodes_common::postgres::{CreateSchema, PostgresConfig};
use nodes_common::{Environment, StartedServices};
use oprf_core::ddlog_equality::shamir::{
    DLogCommitmentsShamir, DLogProofShareShamir, DLogShareShamir,
};
use oprf_core::oprf::BlindingFactor;
use oprf_test_utils::OPRF_PEER_ADDRESS_0;
use oprf_test_utils::{TEST_TIMEOUT, TestSetup};
use oprf_types::api::OprfRequestAuthenticatorError;
use oprf_types::crypto::PartyId;
use oprf_types::service::NodeInformation;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    api::{OprfPublicKeyWithEpoch, OprfRequest, OprfRequestAuthenticator, OprfResponse},
    crypto::OprfPublicKey,
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sqlx::PgPool;
use sqlx::migrate::Migrator;
use tungstenite::protocol::CloseFrame;
use uuid::Uuid;

use crate::secret_manager::SecretManager;
use crate::secret_manager::postgres::PostgresSecretManager;
use crate::{OprfServiceBuilder, config::OprfNodeServiceConfig};

pub const OPRF_KEY_ID: u32 = 42;
pub const TEST_PROTOCOL_VERSION: &str = "1.3.101";
pub const INVALID_AUTH_CODE: u16 = 4500;
pub const INVALID_AUTH_MSG: &str = "invalid auth";

pub const MIGRATOR: Migrator = sqlx::migrate!("../oprf-key-gen/migrations");

#[derive(Clone, Copy, Debug)]
pub enum WireFormat {
    Json,
    Cbor,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ConfigurableTestRequestAuth(pub OprfKeyId);

pub struct ConfigurableTestAuthenticator;

#[async_trait]
impl OprfRequestAuthenticator for ConfigurableTestAuthenticator {
    type RequestAuth = ConfigurableTestRequestAuth;

    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
        let ConfigurableTestRequestAuth(oprf_key_id) = &request.auth;
        if *oprf_key_id == OprfKeyId::from(OPRF_KEY_ID) {
            Ok(*oprf_key_id)
        } else {
            Err(OprfRequestAuthenticatorError::with_message(
                INVALID_AUTH_CODE,
                oprf_types::close_frame_message!(INVALID_AUTH_MSG),
            ))
        }
    }
}

pub struct TestNode {
    pub party_id: usize,
    pub secret_manager: Arc<PostgresSecretManager>,
    pub server: Arc<TestServer>,
    pub started_services: StartedServices,
    pub pool: PgPool,
}

impl fmt::Debug for TestNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestNode")
            .field("party_id", &self.party_id)
            .finish_non_exhaustive()
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

    pub fn start_with_secret_manager(
        party_id: usize,
        setup: &TestSetup,
        pool: PgPool,
        secret_manager: PostgresSecretManager,
    ) -> Self {
        let TestSetup {
            provider: _,
            cancellation_token,
            ..
        } = setup;
        assert!(party_id < 5, "can only spawn 5 nodes");

        let mut config = OprfNodeServiceConfig::with_default_values(
            Environment::Dev,
            "1.0.0".parse().expect("Valid VersionReq"),
        );
        config.session_lifetime = Duration::from_secs(10);

        let child_token = cancellation_token.child_token();

        let started_services = StartedServices::new();
        let secret_manager = Arc::new(secret_manager);
        let service = OprfServiceBuilder::init(
            config,
            secret_manager.clone(),
            started_services.clone(),
            &NodeInformation::new(
                PartyId(u16::try_from(party_id).expect("party id must be u16")),
                OPRF_PEER_ADDRESS_0.to_string(),
                setup.setup.threshold(),
            ),
            child_token.clone(),
        )
        .module("/test", Arc::new(ConfigurableTestAuthenticator))
        .build();
        let server = TestServer::builder()
            .http_transport()
            .build(service)
            .expect("Can build test-server");
        TestNode {
            secret_manager,
            started_services,
            server: Arc::new(server),
            party_id,
            pool,
        }
    }

    pub async fn start(party_id: usize, setup: &TestSetup) -> eyre::Result<Self> {
        Self::start_with_key(party_id, setup, OPRF_KEY_ID).await
    }

    pub async fn start_with_key(
        party_id: usize,
        setup: &TestSetup,
        oprf_key_id: u32,
    ) -> eyre::Result<Self> {
        let connection_string = oprf_test_utils::shared_postgres_testcontainer().await?;
        let schema = oprf_test_utils::next_test_schema();
        let mut postgres_config =
            PostgresConfig::with_default_values(connection_string.into(), schema);
        // set low max_connections because many parallel tests connect to the same testcontainer
        postgres_config.max_connections = NonZeroU32::new(1).expect("1 is non-zero");
        let secret_manager = PostgresSecretManager::init(&postgres_config).await?;
        // need to create the schema and run migrations here, normally key-gen would do it.
        let pool = nodes_common::postgres::pg_pool_with_schema(&postgres_config, CreateSchema::Yes)
            .await?;
        MIGRATOR.run(&pool).await?;
        let test_node = Self::start_with_secret_manager(party_id, setup, pool, secret_manager);
        let key_id = OprfKeyId::from(oprf_key_id);
        test_node
            .add_random_key_material_with_id(key_id, &mut rand::thread_rng())
            .await?;
        Ok(test_node)
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
            .get_oprf_key_material(OprfKeyId::from(OPRF_KEY_ID))
            .await
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
        should_close_frame: &CloseFrame,
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
        should_close_frame: &CloseFrame,
    ) {
        ws_send(websocket, &oprf_req, format).await;
        let is_message = websocket.receive_message().await;
        assert_close_frame(is_message, should_close_frame);
    }

    pub async fn add_random_key_material_with_id_epoch<R: Rng + CryptoRng>(
        &self,
        key_id: OprfKeyId,
        epoch: ShareEpoch,
        rng: &mut R,
    ) -> eyre::Result<()> {
        let share = DLogShareShamir::from(ark_babyjubjub::Fr::rand(rng));
        let public_key = OprfPublicKey::new(rng.r#gen());
        sqlx::query(
            "
                INSERT INTO shares (id, share, epoch, public_key)
                VALUES ($1, $2, $3, $4)
            ",
        )
        .bind(key_id.to_le_bytes())
        .bind(to_db_ark_serialize_uncompressed(&share).as_slice())
        // Postgres lacks u32; cast to i64 to satisfy SQLx type mapping
        .bind(i64::from(epoch))
        .bind(to_db_ark_serialize_uncompressed(&public_key).as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn add_random_key_material_with_id<R: Rng + CryptoRng>(
        &self,
        key_id: OprfKeyId,
        rng: &mut R,
    ) -> eyre::Result<()> {
        self.add_random_key_material_with_id_epoch(key_id, ShareEpoch::default(), rng)
            .await
    }

    pub async fn delete_key_material(&self, key_id: OprfKeyId) -> eyre::Result<()> {
        let success = sqlx::query(
            "
                UPDATE shares
                SET
                    share = NULL,
                    deleted = true
                WHERE id = $1
            ",
        )
        .bind(key_id.to_le_bytes())
        .execute(&self.pool)
        .await
        .context("while deleting key material in DB")?;
        if success.rows_affected() == 1 {
            Ok(())
        } else {
            Err(eyre::eyre!("No row found to delete for key_id {key_id:?}"))
        }
    }
}

#[inline]
fn to_db_ark_serialize_uncompressed<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(t.uncompressed_size());
    t.serialize_uncompressed(&mut bytes).expect("Can serialize");
    bytes
}

pub async fn wait_until_started(started_services: &StartedServices) -> eyre::Result<()> {
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if started_services.all_started() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    Ok(())
}

pub fn assert_close_frame(is_message: tungstenite::Message, should_close_frame: &CloseFrame) {
    match is_message {
        tungstenite::Message::Close(Some(is_close_frame)) => {
            assert_eq!(is_close_frame, *should_close_frame);
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
    let blinded_request = oprf_core::oprf::client::blind_query(query, blinding_factor);
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
