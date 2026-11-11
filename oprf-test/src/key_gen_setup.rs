use std::fmt;
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::time::Duration;

use crate::TEST_TIMEOUT;
use crate::setup::TestSetup;
use crate::setup::{DeploySetup, MineStrategy};
use alloy::primitives::Address;
use ark_ff::UniformRand as _;
use ark_serialize::CanonicalDeserialize as _;
use axum_test::TestServer;
use eyre::Context as _;
use nodes_common::postgres::{CreateSchema, PostgresConfig};
use nodes_common::test_utils::SharedPostgres;
use nodes_common::web3::HttpRpcProviderConfig;
use nodes_common::web3::event_stream::SkipBackfill;
use nodes_common::{Environment, StartedServices};
use oprf_key_gen::KeyGenTasks;
use oprf_key_gen::config::{OprfKeyGenServiceConfig, OprfKeyGenServiceConfigMandatoryValues};
use oprf_key_gen::postgres::{PostgresDb, StorageSettings};
use oprf_store::format::StorageFormat;
use rand::{CryptoRng, Rng};
use sqlx::PgPool;
use taceo_oprf::core::ddlog_equality::shamir::DLogShareShamir;
use taceo_oprf::types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use tokio_util::sync::CancellationToken;

pub struct TestKeyGenConfig {
    pub party_id: usize,
    pub explicit_backfill_block: Option<NonZeroU64>,
    /// The storage formats key-gen reads and writes; defaults to `direct` only.
    storage: StorageSettings,
    /// The party whose in-memory KMS key-gen uses; `None` uses its own party's.
    kms_party: Option<usize>,
    /// Database of a previously shut down key-gen, reused on restart.
    db: Option<KeyGenDb>,
}

impl TestKeyGenConfig {
    pub fn new(party_id: usize) -> Self {
        Self {
            party_id,
            explicit_backfill_block: None,
            storage: direct_only(),
            kms_party: None,
            db: None,
        }
    }

    /// Uses the in-memory KMS of party `kms_party` (same ARN and master key) instead of the own
    /// party's, so that several parties can share one KMS key.
    #[must_use]
    pub fn with_kms_of(mut self, kms_party: usize) -> Self {
        self.kms_party = Some(kms_party);
        self
    }

    /// Reads rows stored in `allowed` and writes new values as `write`.
    ///
    /// If `envelopeV1` is involved, the key-gen gets the in-memory KMS of its party
    /// ([`crate::party_dek_wrapper`]), or of the party set by [`TestKeyGenConfig::with_kms_of`]. Applied to the config returned by
    /// [`TestKeyGen::shutdown`], the next start builds a new [`PostgresDb`] with these settings on
    /// the same schema, which runs the storage upgrade of key-gen's startup again.
    #[must_use]
    pub fn with_storage(mut self, allowed: &[StorageFormat], write: StorageFormat) -> Self {
        self.storage = StorageSettings {
            allowed: allowed.to_vec(),
            write,
        };
        self
    }

    #[must_use]
    pub fn with_explicit_backfill_block(mut self, block: NonZeroU64) -> Self {
        self.explicit_backfill_block = Some(block);
        self
    }
}

fn direct_only() -> StorageSettings {
    StorageSettings {
        allowed: vec![StorageFormat::Direct],
        write: StorageFormat::Direct,
    }
}

fn involves_envelope(storage: &StorageSettings) -> bool {
    storage.write == StorageFormat::EnvelopeV1
        || storage.allowed.contains(&StorageFormat::EnvelopeV1)
}

struct KeyGenDb {
    secret_manager: PostgresDb,
    /// The settings `secret_manager` was built with.
    storage: StorageSettings,
    postgres_config: PostgresConfig,
    pool: PgPool,
    pg: Arc<SharedPostgres>,
}

impl KeyGenDb {
    async fn new(kms_party: usize, storage: StorageSettings) -> eyre::Result<Self> {
        let (postgres_config, pg) = crate::test_postgres_config().await?;
        let secret_manager =
            Self::secret_manager(&postgres_config, kms_party, storage.clone()).await?;
        let pool =
            nodes_common::postgres::pg_pool_with_schema(&postgres_config, CreateSchema::No).await?;
        Ok(Self {
            secret_manager,
            storage,
            postgres_config,
            pool,
            pg,
        })
    }

    async fn secret_manager(
        postgres_config: &PostgresConfig,
        kms_party: usize,
        storage: StorageSettings,
    ) -> eyre::Result<PostgresDb> {
        let wrapper = involves_envelope(&storage).then(|| crate::party_dek_wrapper(kms_party));
        PostgresDb::init(postgres_config, storage, wrapper).await
    }

    /// Keeps the database, but builds a new [`PostgresDb`] if `storage` changed: the storage
    /// policy of a prepared instance is fixed.
    async fn with_storage(
        mut self,
        kms_party: usize,
        storage: StorageSettings,
    ) -> eyre::Result<Self> {
        if self.storage != storage {
            self.secret_manager =
                Self::secret_manager(&self.postgres_config, kms_party, storage.clone()).await?;
            self.storage = storage;
        }
        Ok(self)
    }
}

pub struct TestKeyGen {
    pub party_id: usize,
    pub secret_manager: oprf_key_gen::postgres::PostgresDb,
    pub server: TestServer,
    pub key_gen_task: KeyGenTasks,
    pub started_services: StartedServices,
    pub cancellation_token: CancellationToken,
    pub pool: PgPool,
    /// The database config of this key-gen (its own schema).
    pub postgres_config: PostgresConfig,
    /// The `OprfKeyRegistry` contract this key-gen watches.
    pub oprf_key_registry: Address,
    storage: StorageSettings,
    /// The party whose in-memory KMS this key-gen uses.
    pub(crate) kms_party: usize,
    pub(crate) pg: Arc<SharedPostgres>,
}

impl fmt::Debug for TestKeyGen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestKeyGen")
            .field("party_id", &self.party_id)
            .finish_non_exhaustive()
    }
}

impl TestKeyGen {
    pub async fn start(test_setup: &TestSetup, config: TestKeyGenConfig) -> eyre::Result<Self> {
        let TestKeyGenConfig {
            party_id,
            explicit_backfill_block,
            storage,
            kms_party,
            db,
        } = config;
        let kms_party = kms_party.unwrap_or(party_id);
        let KeyGenDb {
            secret_manager,
            storage,
            postgres_config,
            pool,
            pg,
        } = match db {
            Some(db) => db.with_storage(kms_party, storage).await?,
            None => KeyGenDb::new(kms_party, storage).await?,
        };
        let TestSetup {
            anvil,
            oprf_key_registry,
            cancellation_token,
            setup,
            mine_strategy,
            ..
        } = test_setup;

        assert!(party_id < 5, "can only spawn 5 key-gens");
        let private_key = test_setup.peer_private_keys[party_id].as_str();
        let child_token = cancellation_token.child_token();
        let (expected_threshold, expected_num_peers) = match test_setup.setup {
            DeploySetup::TwoThree => (2, 3),
            DeploySetup::ThreeFive => (3, 5),
        };

        let mut config =
            OprfKeyGenServiceConfig::with_default_values(OprfKeyGenServiceConfigMandatoryValues {
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
            });

        config.confirmations_for_transaction = 0;
        config.rpc_provider_config.chain_id = Some(crate::TEST_CHAIN_ID);
        config.allowed_storage_formats.clone_from(&storage.allowed);
        config.storage_write_format = storage.write;
        if involves_envelope(&storage) {
            config.kms_key_arn = Some(crate::party_kms_key_arn(kms_party));
        }
        config.validate_storage()?;
        config.event_stream_config.confirmations_after_sync_block =
            NonZeroUsize::new(2).expect("2 is non-zero");
        // backfill only works with interval mining
        config.event_stream_config.skip_backfill =
            SkipBackfill::from(*mine_strategy == MineStrategy::Auto);
        config.cursor_checkpoint_interval = Duration::from_secs(2);
        config.explicit_backfill_block = explicit_backfill_block;

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
        let server = TestServer::builder().http_transport().build(router);
        // Ensure the event watcher's live log subscription is active before
        // returning. Under auto-mining, backfill is skipped, so any chain
        // event emitted before this node subscribes would otherwise be lost.
        crate::wait_until_started(&started_services).await?;
        Ok(Self {
            party_id,
            secret_manager,
            server,
            key_gen_task,
            started_services,
            cancellation_token: child_token,
            pool,
            postgres_config,
            oprf_key_registry: *oprf_key_registry,
            storage,
            kms_party,
            pg,
        })
    }

    pub async fn start_three(test_setup: &TestSetup) -> eyre::Result<[Self; 3]> {
        let (keygen0, keygen1, keygen2) = tokio::join!(
            Self::start(test_setup, TestKeyGenConfig::new(0)),
            Self::start(test_setup, TestKeyGenConfig::new(1)),
            Self::start(test_setup, TestKeyGenConfig::new(2))
        );
        Ok([keygen0?, keygen1?, keygen2?])
    }

    pub async fn start_five(test_setup: &TestSetup) -> eyre::Result<[Self; 5]> {
        let (keygen0, keygen1, keygen2, keygen3, keygen4) = tokio::join!(
            Self::start(test_setup, TestKeyGenConfig::new(0)),
            Self::start(test_setup, TestKeyGenConfig::new(1)),
            Self::start(test_setup, TestKeyGenConfig::new(2)),
            Self::start(test_setup, TestKeyGenConfig::new(3)),
            Self::start(test_setup, TestKeyGenConfig::new(4))
        );
        Ok([keygen0?, keygen1?, keygen2?, keygen3?, keygen4?])
    }

    pub async fn shutdown(self) -> eyre::Result<TestKeyGenConfig> {
        let fut = async move {
            self.cancellation_token.cancel();
            self.key_gen_task.join().await?;
            Ok(TestKeyGenConfig {
                party_id: self.party_id,
                explicit_backfill_block: None,
                storage: self.storage.clone(),
                kms_party: Some(self.kms_party),
                db: Some(KeyGenDb {
                    secret_manager: self.secret_manager,
                    storage: self.storage,
                    postgres_config: self.postgres_config,
                    pool: self.pool,
                    pg: self.pg,
                }),
            })
        };
        tokio::time::timeout(TEST_TIMEOUT, fut)
            .await
            .context("Cannot shutdown in time")?
    }

    pub async fn restart(self, test_setup: &TestSetup) -> eyre::Result<TestKeyGen> {
        let restart_fut = async {
            let config = self.shutdown().await?;
            TestKeyGen::start(test_setup, config).await
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
        crate::setup::insert_key_material(&self.pool, key_id, epoch, share, public_key).await
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
                tokio::time::sleep(Duration::from_millis(100)).await;
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
                && let Ok(pk) = OprfPublicKey::deserialize_uncompressed_unchecked(bytes.as_slice())
            {
                break pk;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await?;
    Ok(public_key)
}

pub mod keygen_asserts {
    use taceo_oprf::types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
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
