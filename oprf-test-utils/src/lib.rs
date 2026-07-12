use std::time::Duration;

#[cfg(feature = "deploy-anvil")]
pub mod deploy_anvil;
mod oprf_key_registry;
mod secret_manager;
#[cfg(feature = "deploy-anvil")]
pub mod setup;

use ark_serialize::CanonicalSerialize;
#[cfg(feature = "deploy-anvil")]
pub use deploy_anvil::*;
#[cfg(feature = "deploy-anvil")]
pub use setup::*;

pub use oprf_key_registry::*;

#[cfg(feature = "postgres-test-container")]
pub use secret_manager::postgres::*;

#[cfg(feature = "ci")]
pub const TEST_TIMEOUT: Duration = Duration::from_secs(120);
#[cfg(not(feature = "ci"))]
pub const TEST_TIMEOUT: Duration = Duration::from_secs(20);

#[inline]
fn to_db_ark_serialize_uncompressed<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(t.uncompressed_size());
    t.serialize_uncompressed(&mut bytes).expect("Can serialize");
    bytes
}
pub mod key_gen_setup {

    use std::fmt;
    use std::num::{NonZeroU16, NonZeroU32, NonZeroUsize};
    use std::sync::Arc;
    use std::time::Duration;

    use crate::{DeploySetup, TestSetup, to_db_ark_serialize_uncompressed};
    use crate::{PEER_PRIVATE_KEYS, TEST_TIMEOUT};
    use ark_ff::UniformRand as _;
    use ark_serialize::CanonicalDeserialize as _;
    use axum_test::TestServer;
    use eyre::Context as _;
    use nodes_common::postgres::{CreateSchema, PostgresConfig};
    use nodes_common::web3::HttpRpcProviderConfig;
    use nodes_common::{Environment, StartedServices};
    use oprf_core::ddlog_equality::shamir::DLogShareShamir;
    use oprf_key_gen::KeyGenTasks;
    use oprf_key_gen::config::{OprfKeyGenServiceConfig, OprfKeyGenServiceConfigMandatoryValues};
    use oprf_key_gen::postgres::PostgresDb;
    use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
    use rand::{CryptoRng, Rng};
    use sqlx::PgPool;
    use tokio_util::sync::CancellationToken;

    pub struct TestKeyGen {
        pub party_id: usize,
        pub secret_manager: oprf_key_gen::postgres::PostgresDb,
        pub server: TestServer,
        pub key_gen_task: KeyGenTasks,
        pub started_services: StartedServices,
        pub cancellation_token: CancellationToken,
        pub pool: PgPool,
    }

    impl fmt::Debug for TestKeyGen {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TestKeyGen")
                .field("party_id", &self.party_id)
                .finish_non_exhaustive()
        }
    }

    impl TestKeyGen {
        pub async fn start_with_secret_manager(
            party_id: usize,
            test_setup: &TestSetup,
            secret_manager: PostgresDb,
            pool: PgPool,
        ) -> eyre::Result<Self> {
            let TestSetup {
                anvil,
                oprf_key_registry,
                cancellation_token,
                setup,
                ..
            } = test_setup;

            assert!(party_id < 5, "can only spawn 5 key-gens");
            let private_key = PEER_PRIVATE_KEYS[party_id];
            let child_token = cancellation_token.child_token();
            let (expected_threshold, expected_num_peers) = match test_setup.setup {
                DeploySetup::TwoThree => (2, 3),
                DeploySetup::ThreeFive => (3, 5),
            };

            let mut config = OprfKeyGenServiceConfig::with_default_values(
                OprfKeyGenServiceConfigMandatoryValues {
                    environment: Environment::Dev,
                    oprf_key_registry_contract: *oprf_key_registry,
                    wallet_private_key: private_key.into(),
                    zkey_path: setup.key_gen_path(),
                    witness_graph_path: setup.witness_path(),
                    expected_threshold: NonZeroU16::new(expected_threshold).expect("Is non-zero"),
                    expected_num_peers: NonZeroU16::new(expected_num_peers).expect("Is non-zero"),
                    rpc_provider_config: HttpRpcProviderConfig::with_default_values([
                        anvil.endpoint_url()
                    ])
                    .expect("Can build provider"),
                    ws_rpc_url: anvil.ws_endpoint().into(),
                },
            );

            config.confirmations_for_transaction = 0;
            config.rpc_provider_config.chain_id = Some(31_337);
            config.event_stream_config.confirmations_after_sync_block =
                NonZeroUsize::new(2).expect("2 is non-zero");
            config.cursor_checkpoint_interval = Duration::from_secs(2);

            let started_services = StartedServices::new();
            let sm_service: oprf_key_gen::secret_manager::SecretManagerService =
                Arc::new(secret_manager.clone());
            let cursor_service: oprf_key_gen::event_cursor_store::ChainCursorService =
                Arc::new(secret_manager.clone());
            let (router, key_gen_task) = oprf_key_gen::start(
                config,
                sm_service,
                cursor_service,
                started_services.clone(),
                child_token.clone(),
            )
            .await?;
            let server = TestServer::builder()
                .http_transport()
                .build(router)
                .expect("works");
            Ok(Self {
                party_id,
                secret_manager,
                server,
                key_gen_task,
                started_services,
                cancellation_token: child_token,
                pool,
            })
        }

        pub async fn start(party_id: usize, test_setup: &TestSetup) -> eyre::Result<Self> {
            let connection_string =
                nodes_common::test_utils::shared_postgres_testcontainer().await?;
            let schema = nodes_common::test_utils::next_test_schema();
            let mut postgres_config =
                PostgresConfig::with_default_values(connection_string.into(), schema);
            // set low max_connections because many parallel tests connect to the same testcontainer
            postgres_config.max_connections = NonZeroU32::new(1).expect("1 is non-zero");
            let secret_manager = PostgresDb::init(&postgres_config).await?;
            let pool =
                nodes_common::postgres::pg_pool_with_schema(&postgres_config, CreateSchema::No)
                    .await?;
            TestKeyGen::start_with_secret_manager(party_id, test_setup, secret_manager, pool).await
        }

        pub async fn start_three(test_setup: &TestSetup) -> eyre::Result<[Self; 3]> {
            let (keygen0, keygen1, keygen2) = tokio::join!(
                Self::start(0, test_setup),
                Self::start(1, test_setup),
                Self::start(2, test_setup)
            );
            Ok([keygen0?, keygen1?, keygen2?])
        }

        pub async fn start_five(test_setup: &TestSetup) -> eyre::Result<[Self; 5]> {
            let (keygen0, keygen1, keygen2, keygen3, keygen4) = tokio::join!(
                Self::start(0, test_setup),
                Self::start(1, test_setup),
                Self::start(2, test_setup),
                Self::start(3, test_setup),
                Self::start(4, test_setup)
            );
            Ok([keygen0?, keygen1?, keygen2?, keygen3?, keygen4?])
        }

        pub async fn shutdown(self) -> eyre::Result<(usize, PgPool, PostgresDb)> {
            let fut = async move {
                self.cancellation_token.cancel();
                self.key_gen_task.join().await?;
                Ok((self.party_id, self.pool, self.secret_manager))
            };
            tokio::time::timeout(TEST_TIMEOUT, fut)
                .await
                .context("Cannot shutdown in time")?
        }

        pub async fn restart(self, test_setup: &TestSetup) -> eyre::Result<TestKeyGen> {
            let restart_fut = async {
                let (party_id, pool, secret_manager) = self.shutdown().await?;
                TestKeyGen::start_with_secret_manager(party_id, test_setup, secret_manager, pool)
                    .await
            };
            tokio::time::timeout(TEST_TIMEOUT, restart_fut)
                .await
                .context("Cannot restart in time")?
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
            .bind(i64::from(epoch))
            .bind(to_db_ark_serialize_uncompressed(&public_key).as_slice())
            .execute(&self.pool)
            .await?;
            Ok(())
        }

        pub async fn add_random_key_material<R: Rng + CryptoRng>(
            &self,
            rng: &mut R,
        ) -> eyre::Result<OprfKeyId> {
            let oprf_key_id = OprfKeyId::from(rng.r#gen::<usize>());
            self.add_random_key_material_with_id_epoch(oprf_key_id, ShareEpoch::default(), rng)
                .await?;
            Ok(oprf_key_id)
        }

        pub async fn has_key_material(&self, key_id: OprfKeyId) -> eyre::Result<bool> {
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM shares WHERE id = $1 AND deleted = false")
                    .bind(key_id.to_le_bytes())
                    .fetch_one(&self.pool)
                    .await?;
            Ok(count > 0)
        }

        pub async fn is_key_id_not_stored(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
            let pool = self.pool.clone();
            tokio::time::timeout(TEST_TIMEOUT, async move {
                loop {
                    let count: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM shares WHERE id = $1 AND deleted = false",
                    )
                    .bind(oprf_key_id.to_le_bytes())
                    .fetch_one(&pool)
                    .await
                    .expect("can query count");
                    if count == 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            })
            .await?;
            Ok(())
        }

        pub async fn clear(&self) -> eyre::Result<()> {
            sqlx::query("DELETE FROM shares WHERE deleted = false")
                .execute(&self.pool)
                .await?;
            Ok(())
        }
    }

    async fn poll_key_in_pool(
        pool: PgPool,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> eyre::Result<OprfPublicKey> {
        let public_key = tokio::time::timeout(TEST_TIMEOUT, async move {
            loop {
                let maybe_bytes: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT public_key FROM shares WHERE id = $1 AND epoch = $2 AND deleted = false",
            )
            .bind(oprf_key_id.to_le_bytes())
            .bind(i64::from(epoch))
            .fetch_optional(&pool)
            .await
            .ok()
            .flatten();
                if let Some(bytes) = maybe_bytes
                    && let Ok(pk) =
                        OprfPublicKey::deserialize_uncompressed_unchecked(bytes.as_slice())
                {
                    break pk;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
        .await?;
        Ok(public_key)
    }

    pub mod keygen_asserts {
        use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
        use tokio::task::JoinSet;

        use super::TestKeyGen;

        pub async fn all_have_key(
            instances: &[TestKeyGen],
            oprf_key_id: OprfKeyId,
            epoch: ShareEpoch,
        ) -> eyre::Result<OprfPublicKey> {
            let mut keys = instances
                .iter()
                .map(|instance| {
                    let pool = instance.pool.clone();
                    async move { super::poll_key_in_pool(pool, oprf_key_id, epoch).await }
                })
                .collect::<JoinSet<_>>()
                .join_all()
                .await
                .into_iter()
                .collect::<eyre::Result<Vec<_>>>()?;
            assert_eq!(keys.len(), instances.len());
            let oprf_public_key = keys.pop().expect("is there");
            assert!(keys.into_iter().all(|key| key == oprf_public_key));
            Ok(oprf_public_key)
        }
    }
}

pub mod node_setup {

    use core::fmt;
    use std::net::{IpAddr, Ipv4Addr};
    use std::num::{NonZeroU16, NonZeroU32};
    use std::{sync::Arc, time::Duration};

    use ark_ec::{AffineRepr as _, CurveGroup as _};
    use ark_ff::UniformRand as _;
    use ark_serialize::CanonicalSerialize;
    use async_trait::async_trait;
    use axum_test::{TestServer, TestWebSocket, http};
    use eyre::Context as _;
    use http::{StatusCode, Uri};
    use nodes_common::postgres::{CreateSchema, PostgresConfig};
    use nodes_common::{Environment, StartedServices};
    use oprf_client::Connector;
    use oprf_core::ddlog_equality::shamir::{
        DLogCommitmentsShamir, DLogProofShareShamir, DLogShareShamir,
    };
    use oprf_core::oprf::BlindingFactor;
    use oprf_service::OprfServiceBuilder;
    use oprf_service::config::OprfNodeServiceConfig;
    use oprf_service::secret_manager::SecretManager as _;
    use oprf_service::secret_manager::postgres::PostgresSecretManager;
    use oprf_types::api::OprfRequestAuthenticatorError;
    use oprf_types::async_trait;
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

    use crate::{OPRF_PEER_ADDRESS_0, TEST_TIMEOUT, TestSetup};

    pub const OPRF_KEY_ID: u32 = 42;
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
        pub secret_manager: Arc<oprf_service::secret_manager::postgres::PostgresSecretManager>,
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
                    oprf_client::VERSION,
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
        ) -> Self {
            assert!(party_id < 5, "can only spawn 5 nodes");

            let mut config = OprfNodeServiceConfig::with_default_values(
                Environment::Dev,
                oprf_client::VERSION.parse().expect("valid semver"),
            );
            config.session_lifetime = Duration::from_secs(10);

            let started_services = StartedServices::new();
            let secret_manager = Arc::new(secret_manager);
            let service = OprfServiceBuilder::init(
                config,
                secret_manager.clone(),
                started_services.clone(),
                &NodeInformation::new(
                    PartyId(u16::try_from(party_id).expect("party id must be u16")),
                    OPRF_PEER_ADDRESS_0.to_string(),
                    NonZeroU16::try_from(2).expect("2 is non-zero"),
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
            let connection_string =
                nodes_common::test_utils::shared_postgres_testcontainer().await?;
            let schema = nodes_common::test_utils::next_test_schema();
            let mut postgres_config =
                PostgresConfig::with_default_values(connection_string.into(), schema);
            // set low max_connections because many parallel tests connect to the same testcontainer
            postgres_config.max_connections = NonZeroU32::new(1).expect("1 is non-zero");
            let secret_manager = PostgresSecretManager::init(&postgres_config).await?;
            // need to create the schema and run migrations here, normally key-gen would do it.
            let pool =
                nodes_common::postgres::pg_pool_with_schema(&postgres_config, CreateSchema::Yes)
                    .await?;
            MIGRATOR.run(&pool).await?;
            let port = nodes_common::test_utils::random_port()?;
            let test_node = Self::start_with_secret_manager(1, pool, port, None, secret_manager);
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
            self.add_key_material_with_id_epoch_and_share(key_id, epoch, share, public_key)
                .await
        }

        /// Inserts a specific (non-random) share and public key for `key_id`. Used to give
        /// multiple nodes consistent Shamir shares of the same secret, e.g. via
        /// [`generate_shamir_shares`], so that a real threshold protocol run across them succeeds.
        pub async fn add_key_material_with_id_epoch_and_share(
            &self,
            key_id: OprfKeyId,
            epoch: ShareEpoch,
            share: DLogShareShamir,
            public_key: OprfPublicKey,
        ) -> eyre::Result<()> {
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
        let public_key = OprfPublicKey::new(
            (ark_babyjubjub::EdwardsAffine::generator() * poly[0]).into_affine(),
        );
        let shares = (1..=n)
            .map(|x| {
                DLogShareShamir::from(oprf_core::shamir::evaluate_poly(
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
        connection_string: &str,
        setup: &TestSetup,
        key_id: OprfKeyId,
    ) -> eyre::Result<Vec<TestNode>> {
        let n = setup.setup.addresses().len();
        let threshold = usize::from(u16::from(setup.setup.threshold()));
        let ports: Vec<u16> = (0..n)
            .map(|_| nodes_common::test_utils::random_port().expect("Can find random port"))
            .collect();
        let base_urls: Vec<String> = ports
            .iter()
            .map(|port| format!("http://127.0.0.1:{port}"))
            .collect();
        let services = oprf_client::to_oprf_uri_many(&base_urls, "test")?;

        let epoch = ShareEpoch::default();
        let (public_key, shares) = generate_shamir_shares(threshold, n, &mut rand::thread_rng());

        let mut nodes = Vec::with_capacity(n);
        for (party_id, port) in ports.into_iter().enumerate() {
            let schema = nodes_common::test_utils::next_test_schema();
            let mut postgres_config =
                PostgresConfig::with_default_values(connection_string.into(), schema);
            // set low max_connections because many parallel tests connect to the same testcontainer
            postgres_config.max_connections = NonZeroU32::new(1).expect("1 is non-zero");
            let secret_manager = PostgresSecretManager::init(&postgres_config).await?;
            let pool =
                nodes_common::postgres::pg_pool_with_schema(&postgres_config, CreateSchema::Yes)
                    .await?;
            MIGRATOR.run(&pool).await?;

            let node = TestNode::start_with_secret_manager(
                party_id,
                pool,
                port,
                Some(services.clone()),
                secret_manager,
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
}
