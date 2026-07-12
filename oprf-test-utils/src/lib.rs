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
