//! Postgres backend for the OPRF key-gen service.
//!
//! This module provides [`PostgresDb`], a single Postgres-backed store that implements both
//! [`SecretManager`] and [`ChainCursorStorage`] on one shared [`sqlx::PgPool`].
//!
//! - [`SecretManager`]: persists the node wallet address, in-progress key-gen state,
//!   pending shares, and finalized shares so the service can resume protocol rounds across
//!   process restarts.
//! - [`ChainCursorStorage`]: persists the `(block, log_index)` cursor used by the
//!   `key_event_watcher` service to resume event-log backfill after a restart.
//!
//! The schema is managed by the embedded migrations of [`oprf_store::MIGRATOR`], applied automatically
//! during [`PostgresDb::init`].

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use async_trait::async_trait;
use backon::ConstantBackoff;
use eyre::Context;
use nodes_common::{
    postgres::{CreateSchema, PostgresConfig},
    web3::event_stream::ChainCursor,
};
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_store::{
    DekWrapper, EnvelopeError, StorageCrypto,
    aad::{AadContext, Kind, RowId},
    codec,
    data_keys::{self, DataKeyError},
    format::StorageFormat,
};
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey, service::NodeInformation};
use sqlx::{Acquire, PgExecutor, PgPool, Row as _};
use tracing::instrument;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    config::EnvelopeMode,
    metrics,
    secret_manager::{
        self, KeyGenIntermediateValues, SecretManager, SecretManagerError, StorageReport,
    },
    services::event_cursor_store::ChainCursorStorage,
};

type Result<T> = std::result::Result<T, PostgresDbError>;

/// How secret columns are stored, with the wrapper of the data keys if `envelopeV1` is used.
#[derive(Clone)]
#[allow(
    clippy::exhaustive_enums,
    reason = "constructed by callers; mirrors `StorageConfig`"
)]
pub enum Storage {
    /// Reads and writes `direct` only.
    Direct,
    /// Reads `envelopeV1`; what else is read and what is written depends on `mode`.
    Envelope {
        /// The formats read and written.
        mode: EnvelopeMode,
        /// Wraps the data keys.
        wrapper: Arc<dyn DekWrapper>,
    },
}

impl std::fmt::Debug for Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => f.write_str("Direct"),
            Self::Envelope { mode, wrapper } => f
                .debug_struct("Envelope")
                .field("mode", mode)
                .field("kms_key_arn", &wrapper.key_arn())
                .finish(),
        }
    }
}

/// Postgres-backed store implementing both [`SecretManager`] and [`ChainCursorStorage`] on a shared `PgPool`.
#[derive(Clone)]
pub struct PostgresDb {
    pool: PgPool,
    max_retries: NonZeroUsize,
    retry_delay: Duration,
    /// The storage policy.
    crypto: Arc<StorageCrypto>,
    /// The configured storage.
    storage: Storage,
}

impl std::fmt::Debug for PostgresDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresDb")
            .field("pool", &self.pool)
            .field("max_retries", &self.max_retries)
            .field("retry_delay", &self.retry_delay)
            .field("crypto", &self.crypto)
            .field("storage", &self.storage)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PostgresDbError {
    #[error("Intermediates NOT stored for {0}/{1} - stuck")]
    MissingIntermediates(OprfKeyId, ShareEpoch),
    #[error("Refusing to overwrite newer share")]
    RefusingToRollbackEpoch,
    #[error(transparent)]
    DbError(#[from] sqlx::Error),
    #[error(transparent)]
    Store(oprf_store::StoreError),
    #[error(transparent)]
    Envelope(EnvelopeError),
    #[error(transparent)]
    DataKey(#[from] DataKeyError),
    #[error("internal error: {0:?}")]
    Internal(#[from] eyre::Report),
}

impl From<oprf_store::StoreError> for PostgresDbError {
    fn from(value: oprf_store::StoreError) -> Self {
        match value {
            // Keep database errors on the `DbError` path so that transient errors are retried
            // and constraint violations are mapped.
            oprf_store::StoreError::Db(error) => Self::DbError(error),
            oprf_store::StoreError::Envelope(error) => Self::Envelope(error),
            other => Self::Store(other),
        }
    }
}

impl From<EnvelopeError> for PostgresDbError {
    fn from(value: EnvelopeError) -> Self {
        Self::Envelope(value)
    }
}

/// Builds the connection pool, ensures the configured schema exists and runs all pending
/// migrations.
async fn connect(db_config: &PostgresConfig) -> eyre::Result<PgPool> {
    tracing::info!("init PgPool with schema: {}", db_config.schema);
    let pool = nodes_common::postgres::pg_pool_with_schema(db_config, CreateSchema::Yes)
        .await
        .context("while creating pool")?;
    // We create the pool eagerly, so running migrations here should not hit pool-acquire retries.
    tracing::trace!("potentially running migrations..");
    oprf_store::MIGRATOR
        .run(&pool)
        .await
        .context("while running migrations")?;
    Ok(pool)
}

/// Builds the storage policy from the settings, creating the first data key if `envelopeV1` is
/// written and none exists.
async fn build_crypto(pool: &PgPool, storage: &Storage, ctx: AadContext) -> Result<StorageCrypto> {
    let Storage::Envelope { mode, wrapper } = storage else {
        return Ok(StorageCrypto::new(&[StorageFormat::Direct], ctx, vec![])
            .with_write(oprf_store::WriteTarget::Direct)?);
    };
    let wrapper = wrapper.as_ref();
    let writes_envelope = mode.write() == StorageFormat::EnvelopeV1;
    if writes_envelope && data_keys::current_id(pool).await?.is_none() {
        let dek = data_keys::create(pool, wrapper).await?;
        tracing::info!(data_key_id = %dek.id(), "created the first data key");
    }
    let deks = data_keys::load_all(pool, wrapper).await?;
    let target = if writes_envelope {
        let current = data_keys::current_id(pool)
            .await?
            .ok_or_else(|| eyre::eyre!("no data key exists to write envelopeV1 under"))?;
        oprf_store::WriteTarget::EnvelopeV1(current)
    } else {
        oprf_store::WriteTarget::Direct
    };
    tracing::info!(data_keys = deks.len(), ?target, "loaded data keys");
    Ok(StorageCrypto::new(mode.allowed(), ctx, deks).with_write(target)?)
}

impl PostgresDb {
    /// Initializes a [`PostgresDb`]: builds the connection pool, ensures the configured schema
    /// exists, runs all pending migrations, stores `node_information` and prepares the storage
    /// of secrets, bound to that node.
    ///
    /// `storage` names the formats secret columns are read and written in. Preparing loads (and
    /// if needed creates) the data keys and upgrades `direct` rows if both formats are read and
    /// `envelopeV1` is written.
    ///
    /// # Errors
    /// Returns an error if creating the database pool or running the migrations fails, or if a
    /// database or KMS operation fails or a data key cannot be loaded while preparing.
    #[instrument(level = "info", skip_all)]
    pub async fn init(
        db_config: &PostgresConfig,
        storage: Storage,
        node_information: NodeInformation,
    ) -> eyre::Result<Self> {
        let (db, _) = Self::init_with_report(db_config, storage, node_information).await?;
        Ok(db)
    }

    /// [`PostgresDb::init`], also returning what preparing the storage found and did.
    async fn init_with_report(
        db_config: &PostgresConfig,
        storage: Storage,
        node_information: NodeInformation,
    ) -> eyre::Result<(Self, StorageReport)> {
        let pool = connect(db_config).await?;
        let ctx = AadContext {
            party_id: node_information.party_id(),
            threshold: node_information.threshold(),
        };
        let crypto = build_crypto(&pool, &storage, ctx)
            .await
            .context("while loading the data keys")?;
        let db = Self {
            pool,
            max_retries: db_config.max_retries,
            retry_delay: db_config.retry_delay,
            crypto: Arc::new(crypto),
            storage,
        };
        db.store_node_information(node_information)
            .await
            .context("while storing node information")?;
        let report = db
            .upgrade_and_report()
            .await
            .context("while upgrading stored rows")?;
        Ok((db, report))
    }

    #[inline]
    fn backoff_strategy(&self) -> ConstantBackoff {
        oprf_store::retry::backoff(self.max_retries, self.retry_delay)
    }

    async fn with_retry<F, Fut, T>(&self, op_name: &str, f: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        oprf_store::retry::with_retry(op_name, self.backoff_strategy(), is_retryable_error, f).await
    }
}

#[async_trait]
impl ChainCursorStorage for PostgresDb {
    /// Loads the `ChainEventCursor` for backfill.
    #[instrument(level = "info", skip_all)]
    #[allow(
        clippy::cast_sign_loss,
        reason = "We serialize the u64 as i64 due sqlx limitations. We deserialize it then to u64 which is ok"
    )]
    async fn load_chain_cursor(&self) -> eyre::Result<ChainCursor> {
        tracing::trace!("loading chain event cursor...");
        let get_chain_cursor = || async {
            let row = sqlx::query(
                "
                    SELECT block, idx
                    FROM chain_cursor
                ",
            )
            .fetch_one(&self.pool)
            .await?;
            let block = row.get::<i64, _>(0) as u64;
            let index = row.get::<i64, _>(1) as u64;
            Ok(ChainCursor::new(block, index))
        };
        Ok(self
            .with_retry("load-chain-cursor", get_chain_cursor)
            .await?)
    }

    #[instrument(level = "info", skip_all, fields(chain_cursor=%chain_cursor))]
    #[allow(
        clippy::cast_possible_wrap,
        reason = "We serialize the u64 as i64 because of sqlx limitations."
    )]
    async fn store_chain_cursor(&self, chain_cursor: ChainCursor) -> eyre::Result<()> {
        tracing::trace!("trying to store chain cursor...");
        let store_chain_cursor = || async {
            Ok(sqlx::query(
                "
                    UPDATE chain_cursor
                    SET block = $1, idx = $2
                    WHERE id = TRUE
                      AND ($1 > block OR ($1 = block AND $2 > idx));
                ",
            )
            .bind(chain_cursor.block() as i64)
            .bind(chain_cursor.index() as i64)
            .execute(&self.pool)
            .await?
            .rows_affected())
        };
        let rows_affected = self
            .with_retry("store-chain-cursor", store_chain_cursor)
            .await?;
        if rows_affected == 0 {
            tracing::info!("did not update chain-event cursor - refusing to rollback");
        } else {
            metrics::chain_events::record_current_block(chain_cursor);
        }
        Ok(())
    }
}

impl From<PostgresDbError> for SecretManagerError {
    fn from(value: PostgresDbError) -> Self {
        match value {
            PostgresDbError::MissingIntermediates(oprf_key_id, share_epoch) => {
                Self::MissingIntermediates(oprf_key_id, share_epoch)
            }
            PostgresDbError::RefusingToRollbackEpoch => Self::RefusingToRollbackEpoch,
            PostgresDbError::DbError(error) => {
                if let Some(error) = error.as_database_error()
                    && error.is_check_violation()
                    && error.constraint() == Some("deleted_share_null")
                {
                    // we tried to store on deleted share
                    Self::StoreOnDeletedShare
                } else {
                    Self::Internal(eyre::Report::from(error))
                }
            }
            PostgresDbError::Store(error) => Self::Internal(eyre::Report::from(error)),
            PostgresDbError::Envelope(error) => Self::StorageFormat(error),
            PostgresDbError::DataKey(error) => Self::Internal(eyre::Report::from(error)),
            PostgresDbError::Internal(report) => Self::Internal(report),
        }
    }
}

impl PostgresDb {
    /// Upgrades `direct` rows if both formats are read and `envelopeV1` is written, and reports
    /// the stored formats.
    async fn upgrade_and_report(&self) -> Result<StorageReport> {
        let crypto = self.crypto.as_ref();
        // Only rows key-gen may read are upgraded: if `direct` is not allowed, a `direct` row may
        // have been planted, and sealing it would make it readable. Such rows stay as they are
        // and are counted as disallowed below.
        let runs_upgrade = matches!(
            self.storage,
            Storage::Envelope {
                mode: EnvelopeMode::WriteEnvelope,
                ..
            }
        );
        let upgraded = if runs_upgrade {
            upgrade::upgrade_all(&self.pool, crypto, upgrade::BATCH_SIZE).await?
        } else {
            0
        };
        let counts = upgrade::count_formats(&self.pool, crypto).await?;
        let report = StorageReport::new(upgraded, counts.direct, counts.disallowed);
        tracing::info!(
            upgraded,
            remaining_direct = counts.direct,
            envelope_v1 = counts.envelope_v1,
            disallowed = counts.disallowed,
            "storage prepared"
        );
        if runs_upgrade && counts.direct > 0 {
            tracing::warn!(
                remaining_direct = counts.direct,
                "direct rows were not upgraded because they changed concurrently - a restart retries them"
            );
        }
        if counts.disallowed > 0 {
            tracing::warn!(
                disallowed = counts.disallowed,
                "rows are stored in a format that is not allowed - reading them fails"
            );
        }
        Ok(report)
    }

    #[instrument(level = "info", skip(self))]
    async fn store_node_information(&self, node_information: NodeInformation) -> Result<()> {
        tracing::trace!("storing node information...");
        let store_address = || async {
            sqlx::query(
                "
                INSERT INTO node_information (id, eth_address, party_id, threshold)
                VALUES (TRUE, $1, $2, $3)
                ON CONFLICT (id)
                DO UPDATE SET
                    eth_address = EXCLUDED.eth_address,
                    party_id = EXCLUDED.party_id,
                    threshold = EXCLUDED.threshold
            ",
            )
            .bind(node_information.address())
            .bind(i32::from(node_information.party_id().into_inner()))
            .bind(i32::from(node_information.threshold().get()))
            .execute(&self.pool)
            .await?;
            Ok(())
        };
        self.with_retry("store-node-information", store_address)
            .await?;
        tracing::debug!("successfully stored node-information");
        Ok(())
    }
}

#[async_trait]
impl SecretManager for PostgresDb {
    #[instrument(level = "info", skip(self))]
    async fn get_share_by_epoch(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> secret_manager::Result<Option<DLogShareShamir>> {
        tracing::trace!("loading share...");
        let crypto = self.crypto.as_ref();
        let get_share = || Self::get_share_by_epoch_inner(crypto, oprf_key_id, epoch, &self.pool);
        Ok(self.with_retry("get-share-by-epoch", get_share).await?)
    }

    #[instrument(level = "info", skip(self))]
    async fn delete_oprf_key_material(&self, oprf_key_id: OprfKeyId) -> secret_manager::Result<()> {
        tracing::trace!("trying to delete key-material..");

        let delete_transaction = || async {
            let mut tx = self.pool.begin().await?;
            let conn = tx.acquire().await?;
            // use standard isolation level: READ COMMITTED
            sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                .execute(&mut *conn)
                .await?;
            // Soft-delete finalized shares for this key.
            let deleted_shares = Self::soft_delete_shares_inner(oprf_key_id, &mut *tx).await?;
            // Remove any remaining in-progress state for this key.
            let deleted_intermediates =
                Self::delete_intermediates_inner(oprf_key_id, &mut *tx).await?;
            tx.commit().await?;
            tracing::trace!(
                "deleted {deleted_shares} shares +  {deleted_intermediates} intermediates from postgres"
            );
            Ok(())
        };

        Ok(self
            .with_retry("delete-oprf-key-material", delete_transaction)
            .await?)
    }

    #[instrument(level = "info", skip_all, fields(oprf_key_id=%oprf_key_id))]
    async fn try_store_keygen_intermediates(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        intermediate: KeyGenIntermediateValues,
    ) -> secret_manager::Result<KeyGenIntermediateValues> {
        tracing::trace!("trying to store intermediates...");
        let crypto = self.crypto.as_ref();
        let row = RowId {
            kind: Kind::Intermediates,
            oprf_key_id,
            epoch: pending_epoch,
        };
        let sealed = crypto
            .seal(&row, &codec::to_bytes(&intermediate))
            .map_err(PostgresDbError::from)?;
        let store_intermediates = || async {
            // On conflict the stored row is returned unchanged, possibly in another format.
            let (stored, format, data_key_id): (Vec<u8>, String, Option<Uuid>) = sqlx::query_as(
                "
                INSERT INTO in_progress_keygens
                    (id, pending_epoch, intermediates, storage_format, data_key_id)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (id, pending_epoch) DO UPDATE
                SET intermediates = in_progress_keygens.intermediates
                RETURNING intermediates, storage_format, data_key_id;
            ",
            )
            .bind(oprf_key_id.to_le_bytes())
            // Postgres lacks u32; cast to i64 to satisfy SQLx type mapping
            .bind(i64::from(pending_epoch))
            .bind(sealed.bytes.as_slice())
            .bind(sealed.format.as_str())
            .bind(sealed.data_key_id)
            .fetch_one(&self.pool)
            .await?;
            let stored = Zeroizing::new(stored);
            let plaintext = crypto.open(&format, data_key_id, &row, &stored)?;
            Ok(codec::from_bytes(&plaintext)?)
        };

        Ok(self
            .with_retry("store-keygen-intermediates", store_intermediates)
            .await?)
    }

    #[instrument(level = "info", skip_all, fields(oprf_key_id=%oprf_key_id))]
    async fn fetch_keygen_intermediates(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
    ) -> secret_manager::Result<KeyGenIntermediateValues> {
        tracing::trace!("trying to fetch intermediates...");
        let crypto = self.crypto.as_ref();
        let row = RowId {
            kind: Kind::Intermediates,
            oprf_key_id,
            epoch: pending_epoch,
        };

        let fetch_keygen = || async {
            let Some((stored, format, data_key_id)): Option<(Vec<u8>, String, Option<Uuid>)> =
                sqlx::query_as(
                    "
                SELECT intermediates, storage_format, data_key_id
                FROM in_progress_keygens
                WHERE id = $1
                  AND pending_epoch = $2;
            ",
                )
                .bind(oprf_key_id.to_le_bytes())
                // Postgres lacks u32; cast to i64 to satisfy SQLx type mapping
                .bind(i64::from(pending_epoch))
                .fetch_optional(&self.pool)
                .await?
            else {
                return Ok(None);
            };
            let stored = Zeroizing::new(stored);
            let plaintext = crypto.open(&format, data_key_id, &row, &stored)?;
            Ok(Some(codec::from_bytes(&plaintext)?))
        };

        Ok(self
            .with_retry("fetch-keygen-intermediates", fetch_keygen)
            .await?
            .ok_or_else(|| PostgresDbError::MissingIntermediates(oprf_key_id, pending_epoch))?)
    }

    #[instrument(level = "info", skip(self))]
    async fn abort_keygen(&self, oprf_key_id: OprfKeyId) -> secret_manager::Result<()> {
        tracing::trace!("trying to abort key-gen...");

        let abort_keygen = || Self::delete_intermediates_inner(oprf_key_id, &self.pool);
        let rows_deleted = self.with_retry("abort-keygen", abort_keygen).await?;

        tracing::debug!("aborted {rows_deleted} key-gens from postgres");
        Ok(())
    }

    #[instrument(level = "info", skip_all, fields(oprf_key_id=%oprf_key_id))]
    async fn store_pending_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> secret_manager::Result<()> {
        tracing::trace!("store pending dlog-share..");
        let crypto = self.crypto.as_ref();
        let row = RowId {
            kind: Kind::PendingShare,
            oprf_key_id,
            epoch: pending_epoch,
        };
        let plaintext = codec::to_bytes(&share);
        let store_pending = || async {
            // use standard isolation level: READ COMMITTED
            let mut tx = self.pool.begin().await?;
            // The pending share is stored in the format and under the data key of its row.
            let target: Option<(String, Option<Uuid>)> = sqlx::query_as(
                "
                    SELECT storage_format, data_key_id
                    FROM in_progress_keygens
                    WHERE id = $1
                      AND pending_epoch = $2
                    FOR UPDATE;
                ",
            )
            .bind(oprf_key_id.to_le_bytes())
            // Postgres lacks u32; cast to i64 to satisfy SQLx type mapping
            .bind(i64::from(pending_epoch))
            .fetch_optional(&mut *tx)
            .await?;
            let Some((format, data_key_id)) = target else {
                return Err(PostgresDbError::MissingIntermediates(
                    oprf_key_id,
                    pending_epoch,
                ));
            };
            let sealed = crypto.seal_as(format.parse()?, data_key_id, &row, &plaintext)?;
            sqlx::query(
                "
                    UPDATE in_progress_keygens
                    SET pending_share = $3, storage_format = $4, data_key_id = $5
                    WHERE id = $1
                      AND pending_epoch = $2;
                ",
            )
            .bind(oprf_key_id.to_le_bytes())
            // Postgres lacks u32; cast to i64 to satisfy SQLx type mapping
            .bind(i64::from(pending_epoch))
            .bind(sealed.bytes.as_slice())
            .bind(sealed.format.as_str())
            .bind(sealed.data_key_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        };
        match self
            .with_retry("store-pending-dlog-share", store_pending)
            .await
        {
            Ok(()) => {
                tracing::debug!("successfully stored pending dlog share");
                Ok(())
            }
            Err(PostgresDbError::MissingIntermediates(oprf_key_id, pending_epoch)) => {
                tracing::warn!(
                    "cannot store pending share because no matching intermediates exist"
                );
                Err(SecretManagerError::MissingIntermediates(
                    oprf_key_id,
                    pending_epoch,
                ))
            }
            Err(error) => Err(error.into()),
        }
    }

    #[instrument(level = "info", skip_all, fields(oprf_key_id=%oprf_key_id, epoch=%epoch))]
    async fn confirm_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        public_key: OprfPublicKey,
    ) -> secret_manager::Result<()> {
        tracing::trace!("storing share...");
        let crypto = self.crypto.as_ref();

        let confirm_dlog_share = || async {
            let mut tx = self.pool.begin().await?;
            let conn = tx.acquire().await?;
            // Use SERIALIZABLE isolation level — the strongest available — to prevent any
            // concurrent reads or writes from affecting this transaction. It is essential
            // that this transaction operates on fresh data. On retry, we check whether
            // another transaction already completed this work via get_share_by_epoch_inner
            // and short-circuit if so.
            sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                .execute(&mut *conn)
                .await?;
            // check if we already stored this share - maybe we had to redo this operation so that it is idempotent
            if Self::get_share_by_epoch_inner(crypto, oprf_key_id, epoch, &mut *conn)
                .await?
                .is_some()
            {
                tracing::warn!("already have this share stored - delete intermediates");
                Self::delete_intermediates_inner(oprf_key_id, &mut *conn).await?;
                tx.commit().await?;
                return Ok(());
            }
            let pending_share =
                Self::fetch_pending_share_inner(crypto, oprf_key_id, epoch, &mut *conn)
                    .await?
                    .ok_or_else(|| PostgresDbError::MissingIntermediates(oprf_key_id, epoch))?;

            let rows_affected = Self::store_confirmed_dlog_share_inner(
                crypto,
                oprf_key_id,
                epoch,
                &public_key,
                &pending_share,
                &mut *conn,
            )
            .await?;
            if rows_affected != 1 {
                return Err(PostgresDbError::RefusingToRollbackEpoch);
            }
            Self::delete_intermediates_inner(oprf_key_id, &mut *conn).await?;
            tx.commit().await?;
            Ok(())
        };
        Ok(self
            .with_retry("confirm-dlog-share", confirm_dlog_share)
            .await?)
    }
}

impl PostgresDb {
    async fn get_share_by_epoch_inner(
        crypto: &StorageCrypto,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        conn: impl PgExecutor<'_>,
    ) -> Result<Option<DLogShareShamir>> {
        let Some(row) = oprf_store::shares::fetch(conn, oprf_key_id).await? else {
            return Ok(None);
        };
        if row.is_deleted() || row.epoch()? != epoch {
            return Ok(None);
        }
        Ok(Some(row.open(crypto)?.share))
    }

    async fn soft_delete_shares_inner(
        oprf_key_id: OprfKeyId,
        conn: impl PgExecutor<'_>,
    ) -> Result<u64> {
        Ok(sqlx::query(
            "
                UPDATE shares
                SET
                    share = NULL,
                    deleted = true
                WHERE id = $1;
            ",
        )
        .bind(oprf_key_id.to_le_bytes())
        .execute(conn)
        .await?
        .rows_affected())
    }

    /// Reads and opens the pending share; `None` if there is no row or no pending share.
    async fn fetch_pending_share_inner(
        crypto: &StorageCrypto,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        conn: impl PgExecutor<'_>,
    ) -> Result<Option<DLogShareShamir>> {
        let row: Option<(Option<Vec<u8>>, String, Option<Uuid>)> = sqlx::query_as(
            "
                SELECT pending_share, storage_format, data_key_id
                FROM in_progress_keygens
                WHERE id = $1
                  AND pending_epoch = $2;
            ",
        )
        .bind(oprf_key_id.to_le_bytes())
        // Postgres lacks u32; cast to i64 to satisfy SQLx type mapping
        .bind(i64::from(pending_epoch))
        .fetch_optional(conn)
        .await?;
        let Some((Some(stored), format, data_key_id)) = row else {
            return Ok(None);
        };
        let stored = Zeroizing::new(stored);
        let row = RowId {
            kind: Kind::PendingShare,
            oprf_key_id,
            epoch: pending_epoch,
        };
        let plaintext = crypto.open(&format, data_key_id, &row, &stored)?;
        Ok(Some(codec::from_bytes(&plaintext)?))
    }

    /// Seals `share` in the write format and stores it as the confirmed share.
    async fn store_confirmed_dlog_share_inner(
        crypto: &StorageCrypto,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        public_key: &OprfPublicKey,
        share: &DLogShareShamir,
        conn: impl PgExecutor<'_>,
    ) -> Result<u64> {
        let row = RowId {
            kind: Kind::Share(*public_key),
            oprf_key_id,
            epoch: pending_epoch,
        };
        let sealed = crypto.seal(&row, &codec::to_bytes(share))?;
        Ok(sqlx::query(
            "
                INSERT INTO shares (id, share, epoch, public_key, storage_format, data_key_id)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (id)
                DO UPDATE SET
                    share = EXCLUDED.share,
                    epoch = EXCLUDED.epoch,
                    public_key = EXCLUDED.public_key,
                    storage_format = EXCLUDED.storage_format,
                    data_key_id = EXCLUDED.data_key_id
                WHERE
                    shares.epoch < EXCLUDED.epoch;
            ",
        )
        .bind(oprf_key_id.to_le_bytes())
        .bind(sealed.bytes.as_slice())
        // Postgres lacks u32; cast to i64 to satisfy SQLx type mapping
        .bind(i64::from(pending_epoch))
        .bind(codec::to_bytes(public_key).as_slice())
        .bind(sealed.format.as_str())
        .bind(sealed.data_key_id)
        .execute(conn)
        .await?
        .rows_affected())
    }

    async fn delete_intermediates_inner(
        oprf_key_id: OprfKeyId,
        conn: impl PgExecutor<'_>,
    ) -> Result<u64> {
        Ok(sqlx::query(
            "
                DELETE FROM in_progress_keygens
                WHERE id = $1;
            ",
        )
        .bind(oprf_key_id.to_le_bytes())
        .execute(conn)
        .await?
        .rows_affected())
    }
}

#[inline]
fn is_retryable_error(e: &PostgresDbError) -> bool {
    match e {
        PostgresDbError::DbError(err) => oprf_store::retry::is_transient_or_conflict(err),
        _ => false,
    }
}

#[cfg(test)]
pub(crate) mod tests;
mod upgrade;
