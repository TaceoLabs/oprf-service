use core::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU16;
use std::{sync::Arc, time::Duration};

use alloy::primitives::Address;
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_ff::UniformRand as _;
use async_trait::async_trait;
use axum_test::{TestServer, TestWebSocket, http};
use http::{StatusCode, Uri};
use nodes_common::{Environment, StartedServices, postgres::CreateSchema};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sqlx::{PgPool, migrate::Migrator};
use taceo_oprf::client::Connector;
use taceo_oprf::core::{
    ddlog_equality::shamir::{DLogCommitmentsShamir, DLogProofShareShamir, DLogShareShamir},
    oprf::BlindingFactor,
};
use taceo_oprf::service::{
    OprfServiceBuilder,
    config::OprfNodeServiceConfig,
    secret_manager::{SecretManager as _, postgres::PostgresSecretManager},
};
use taceo_oprf::types::{
    OprfKeyId, ShareEpoch,
    api::{
        OprfPublicKeyWithEpoch, OprfRequest, OprfRequestAuthenticator,
        OprfRequestAuthenticatorError, OprfResponse,
    },
    async_trait,
    crypto::{OprfPublicKey, PartyId},
    service::NodeInformation,
};
use tungstenite::protocol::CloseFrame;
use uuid::Uuid;

use crate::TEST_TIMEOUT;
use crate::setup::DeploySetup;

pub const OPRF_KEY_ID: u32 = 42;
pub const INVALID_AUTH_CODE: u16 = 4500;
pub const INVALID_AUTH_MSG: &str = "invalid auth";

/// Placeholder wallet address for nodes started via [`TestNode::start`]. These
/// nodes run standalone without an Anvil chain, so there's no real signing
/// wallet to source an address from.
pub const PLACEHOLDER_WALLET_ADDRESS: Address = Address::ZERO;

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
                taceo_oprf::types::close_frame_message!(INVALID_AUTH_MSG),
            ))
        }
    }
}

pub struct TestNode {
    pub party_id: usize,
    pub secret_manager: Arc<taceo_oprf::service::secret_manager::postgres::PostgresSecretManager>,
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
                taceo_oprf::types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
                taceo_oprf::client::VERSION,
            )
            .await
            .into_websocket()
            .await
    }

    /// Starts a test node with the given `secret_manager` and binds it to the specified `bind_port`.
    ///
    /// If `services` is provided, it will be used as the delegate services for the node.
    /// If `services` is `None`, request to `/delegate` will fail.
    pub fn start_with_secret_manager(
        party_id: usize,
        pool: PgPool,
        bind_port: u16,
        services: Option<Vec<Uri>>,
        secret_manager: PostgresSecretManager,
        session_lifetime: Duration,
        threshold: NonZeroU16,
    ) -> Self {
        assert!(party_id < 5, "can only spawn 5 nodes");

        let mut config = OprfNodeServiceConfig::with_default_values(
            Environment::Dev,
            taceo_oprf::client::VERSION.parse().expect("valid semver"),
        );
        config.session_lifetime = session_lifetime;

        let started_services = StartedServices::new();
        let secret_manager = Arc::new(secret_manager);
        let service = OprfServiceBuilder::init(
            config,
            secret_manager.clone(),
            started_services.clone(),
            &NodeInformation::new(
                PartyId(u16::try_from(party_id).expect("party id must be u16")),
                PLACEHOLDER_WALLET_ADDRESS.to_string(),
                threshold,
            ),
            nodes_common::version_info!(),
        )
        .module_with_delegate(
            "/test",
            Arc::new(ConfigurableTestAuthenticator),
            services.unwrap_or_default(), // we dont care about delegate if services is None
            Connector::Plain,
        )
        .build();
        let server = TestServer::builder()
            .http_transport_with_ip_port(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), Some(bind_port))
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

    pub async fn start() -> eyre::Result<Self> {
        Self::start_with_session_lifetime(Duration::from_secs(10)).await
    }

    pub async fn start_with_session_lifetime(session_lifetime: Duration) -> eyre::Result<Self> {
        let (pool, secret_manager) = migrated_pool_and_secret_manager().await?;
        let port = nodes_common::test_utils::random_port()?;
        let test_node = Self::start_with_secret_manager(
            0,
            pool,
            port,
            None,
            secret_manager,
            session_lifetime,
            NonZeroU16::try_from(2).expect("2 is non-zero"),
        );
        let key_id = OprfKeyId::from(OPRF_KEY_ID);
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
                tokio::time::sleep(Duration::from_millis(100)).await;
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
                tokio::time::sleep(Duration::from_millis(100)).await;
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
        self.add_key_material_with_id_epoch_and_share(key_id, epoch, share, public_key)
            .await
    }

    pub async fn add_key_material_with_id_epoch_and_share(
        &self,
        key_id: OprfKeyId,
        epoch: ShareEpoch,
        share: DLogShareShamir,
        public_key: OprfPublicKey,
    ) -> eyre::Result<()> {
        crate::setup::insert_key_material(&self.pool, key_id, epoch, share, public_key).await
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
        crate::setup::delete_key_material(&self.pool, key_id).await
    }
}

/// Creates a fresh schema, migrated pool, and initialized secret manager against the shared
/// testcontainer. Shared by [`TestNode::start`] and [`start_nodes_for_delegate`].
async fn migrated_pool_and_secret_manager() -> eyre::Result<(PgPool, PostgresSecretManager)> {
    let postgres_config = crate::test_postgres_config().await?;
    let secret_manager = PostgresSecretManager::init(&postgres_config).await?;
    // need to create the schema and run migrations here, normally key-gen would do it.
    let pool =
        nodes_common::postgres::pg_pool_with_schema(&postgres_config, CreateSchema::Yes).await?;
    MIGRATOR.run(&pool).await?;
    Ok((pool, secret_manager))
}

/// Generates `n` Shamir shares (for party indices `1..=n`, matching [`PartyId`]'s
/// `party_id + 1` coefficient convention) of a single random secret, of degree `threshold - 1`,
/// together with the corresponding OPRF public key. Used to give a cluster of real nodes
/// consistent key material so a genuine threshold protocol run across them succeeds.
fn generate_shamir_shares<R: Rng + CryptoRng>(
    threshold: usize,
    n: usize,
    rng: &mut R,
) -> (OprfPublicKey, Vec<DLogShareShamir>) {
    let poly: Vec<ark_babyjubjub::Fr> = (0..threshold)
        .map(|_| ark_babyjubjub::Fr::rand(rng))
        .collect();
    let public_key =
        OprfPublicKey::new((ark_babyjubjub::EdwardsAffine::generator() * poly[0]).into_affine());
    let shares = (1..=n)
        .map(|x| {
            DLogShareShamir::from(taceo_oprf::core::shamir::evaluate_poly(
                &poly,
                ark_babyjubjub::Fr::from(x as u64),
            ))
        })
        .collect();
    (public_key, shares)
}

/// Starts a cluster of `n` real, network-bound nodes (`n` and the threshold taken from
/// `setup.setup`), each holding a consistent Shamir share of the same OPRF key, and each
/// exposing both the normal `/oprf` websocket route and the `/delegate` HTTP route pointed
/// at the whole cluster (including itself). Any of the returned nodes can be used to drive
/// the delegate OPRF flow.
pub async fn start_nodes_for_delegate(
    setup: DeploySetup,
    key_id: OprfKeyId,
) -> eyre::Result<Vec<TestNode>> {
    let n = setup.num_peers();
    let threshold = usize::from(u16::from(setup.threshold()));
    let ports: Vec<u16> = (0..n)
        .map(|_| nodes_common::test_utils::random_port().expect("Can find random port"))
        .collect();
    let base_urls: Vec<String> = ports
        .iter()
        .map(|port| format!("http://127.0.0.1:{port}"))
        .collect();
    let services = taceo_oprf::client::to_oprf_uri_many(&base_urls, "test")?;

    let epoch = ShareEpoch::default();
    let (public_key, shares) = generate_shamir_shares(threshold, n, &mut rand::thread_rng());

    let mut nodes = Vec::with_capacity(n);
    for (party_id, port) in ports.into_iter().enumerate() {
        let (pool, secret_manager) = migrated_pool_and_secret_manager().await?;

        let node = TestNode::start_with_secret_manager(
            party_id,
            pool,
            port,
            Some(services.clone()),
            secret_manager,
            Duration::from_secs(10),
            setup.threshold(),
        );
        node.add_key_material_with_id_epoch_and_share(
            key_id,
            epoch,
            shares[party_id].clone(),
            public_key,
        )
        .await?;
        nodes.push(node);
    }
    Ok(nodes)
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
    let blinded_request = taceo_oprf::core::oprf::client::blind_query(query, blinding_factor);
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
