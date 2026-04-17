//! This module provides an implementation of [`SecretManager`] using a Postgres database to store shares.
//!
//! The node wallet address, in-progress key-gen state, pending shares, and finalized shares are
//! persisted in Postgres so the service can resume protocol rounds across process restarts.

use std::num::NonZeroUsize;
use std::time::Duration;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use async_trait::async_trait;
use backon::BackoffBuilder;
use backon::ConstantBackoff;
use backon::ConstantBuilder;
use backon::Retryable;
use eyre::Context;
use nodes_common::postgres::{CreateSchema, PostgresConfig};
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use sqlx::Acquire;
use sqlx::PgExecutor;
use sqlx::PgPool;
use tracing::instrument;

use crate::secret_manager::SecretManager;
use crate::secret_manager::SecretManagerError;
use crate::services::secret_gen::KeyGenIntermediateValues;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
enum PostgresSecretManagerError {
    #[error("Intermediates NOT stored for {0}/{1} - stuck")]
    MissingIntermediates(OprfKeyId, ShareEpoch),
    #[error("Refusing to overwrite newer share")]
    RefusingToRollbackEpoch,
    #[error(transparent)]
    DbError(#[from] sqlx::Error),
    #[error(transparent)]
    Internal(#[from] eyre::Report),
}

impl From<PostgresSecretManagerError> for super::SecretManagerError {
    fn from(value: PostgresSecretManagerError) -> Self {
        match value {
            PostgresSecretManagerError::MissingIntermediates(oprf_key_id, share_epoch) => {
                Self::MissingIntermediates(oprf_key_id, share_epoch)
            }
            PostgresSecretManagerError::RefusingToRollbackEpoch => Self::RefusingToRollbackEpoch,
            PostgresSecretManagerError::DbError(error) => {
                if let Some(error) = error.as_database_error()
                    && error.is_check_violation()
                {
                    // we tried to store on deleted share
                    Self::StoreOnDeletedShare
                } else {
                    Self::Internal(eyre::Report::from(error))
                }
            }
            PostgresSecretManagerError::Internal(report) => Self::Internal(report),
        }
    }
}

type Result<T> = std::result::Result<T, PostgresSecretManagerError>;

/// The postgres secret manager wrapping a `PgPool`.
#[derive(Debug)]
pub struct PostgresSecretManager {
    pool: PgPool,
    max_retries: NonZeroUsize,
    retry_delay: Duration,
}

impl PostgresSecretManager {
    /// Initializes the `PostgresSecretManager`.
    ///
    /// Creates the Postgres connection pool, ensures the configured schema exists, and runs all pending database migrations.
    ///
    /// # Errors
    /// Returns an error if creating the database pool fails, or if running the migrations fails.
    #[instrument(level = "debug", skip_all)]
    pub async fn init(db_config: &PostgresConfig) -> eyre::Result<Self> {
        tracing::debug!("init PgPool with schema: {}", db_config.schema);
        let pool = nodes_common::postgres::pg_pool_with_schema(db_config, CreateSchema::Yes)
            .await
            .context("while creating pool")?;
        // We create the pool eagerly, so running migrations here should not hit pool-acquire retries.
        tracing::debug!("potentially running migrations..");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("while running migrations")?;

        Ok(Self {
            pool,
            max_retries: db_config.max_retries,
            retry_delay: db_config.retry_delay,
        })
    }
}

#[async_trait]
impl SecretManager for PostgresSecretManager {
    #[instrument(level = "info", skip(self))]
    async fn store_wallet_address(&self, address: String) -> super::Result<()> {
        tracing::trace!("storing wallet address...");
        let store_address = || async {
            sqlx::query(
                "
                INSERT INTO evm_address (id, address)
                VALUES (TRUE, $1)
                ON CONFLICT (id)
                DO UPDATE SET address = EXCLUDED.address
            ",
            )
            .bind(&address)
            .execute(&self.pool)
            .await?;
            Ok(())
        };
        self.with_retry("store-wallet-address", store_address)
            .await?;
        tracing::trace!("successfully stored address");
        Ok(())
    }

    #[instrument(level = "debug", skip(self))]
    async fn get_share_by_epoch(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> super::Result<Option<DLogShareShamir>> {
        tracing::trace!("loading share...");
        let get_share = || Self::get_share_by_epoch_inner(oprf_key_id, epoch, &self.pool);
        Ok(self.with_retry("get-share-by-epoch", get_share).await?)
    }

    #[instrument(level = "debug", skip(self))]
    async fn delete_oprf_key_material(&self, oprf_key_id: OprfKeyId) -> super::Result<()> {
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

    #[instrument(level = "debug", skip_all, fields(oprf_key_id=%oprf_key_id))]
    async fn try_store_keygen_intermediates(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        intermediate: KeyGenIntermediateValues,
    ) -> super::Result<KeyGenIntermediateValues> {
        tracing::trace!("trying to store intermediates...");
        let store_intermediates = || async {
            sqlx::query_scalar(
                "
                INSERT INTO in_progress_keygens (id, pending_epoch, intermediates)
                VALUES ($1, $2, $3)
                ON CONFLICT (id, pending_epoch) DO UPDATE
                SET intermediates = in_progress_keygens.intermediates
                RETURNING intermediates;
            ",
            )
            .bind(oprf_key_id.to_le_bytes())
            // Postgres lacks u32; cast to i64 to satisfy SQLx type mapping
            .bind(i64::from(pending_epoch))
            .bind(to_db_ark_serialize_uncompressed(&intermediate).as_slice())
            .fetch_one(&self.pool)
            .await
            .map(from_db_ark_serialize_uncompressed)?
        };

        Ok(self
            .with_retry("store-keygen-intermediates", store_intermediates)
            .await?)
    }

    #[instrument(level = "debug", skip_all, fields(oprf_key_id=%oprf_key_id))]
    async fn fetch_keygen_intermediates(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
    ) -> super::Result<Option<KeyGenIntermediateValues>> {
        tracing::trace!("trying to fetch intermediates...");

        let fetch_keygen = || async {
            sqlx::query_scalar(
                "
                SELECT intermediates
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
            .map(from_db_ark_serialize_uncompressed)
            .transpose()
        };

        let maybe_intermediates = self
            .with_retry("fetch-keygen-intermediates", fetch_keygen)
            .await?;

        if maybe_intermediates.is_some() {
            tracing::trace!("found intermediates!");
        } else {
            tracing::trace!("Cannot find intermediates for requested key and epoch");
        }
        Ok(maybe_intermediates)
    }

    #[instrument(level = "debug", skip(self))]
    async fn abort_keygen(&self, oprf_key_id: OprfKeyId) -> super::Result<()> {
        tracing::trace!("trying to abort key-gen...");

        let abort_keygen = || Self::delete_intermediates_inner(oprf_key_id, &self.pool);
        let rows_deleted = self.with_retry("abort-keygen", abort_keygen).await?;

        tracing::trace!("aborted {rows_deleted} key-gens from postgres");
        Ok(())
    }

    #[instrument(level = "debug", skip_all, fields(oprf_key_id=%oprf_key_id))]
    async fn store_pending_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> super::Result<()> {
        tracing::trace!("store pending dlog-share..");
        let store_pending = || async {
            Ok(sqlx::query(
                "
                    UPDATE in_progress_keygens
                    SET pending_share = $3
                    WHERE id = $1
                      AND pending_epoch = $2;
                ",
            )
            .bind(oprf_key_id.to_le_bytes())
            // Postgres lacks u32; cast to i64 to satisfy SQLx type mapping
            .bind(i64::from(pending_epoch))
            .bind(to_db_ark_serialize_uncompressed(&share).as_slice())
            .execute(&self.pool)
            .await?
            .rows_affected())
        };
        let rows_affected = self
            .with_retry("store-pending-dlog-share", store_pending)
            .await?;

        if rows_affected == 1 {
            tracing::trace!("successfully stored pending dlog share");
            Ok(())
        } else {
            tracing::warn!("cannot store pending share because no matching intermediates exist");
            Err(SecretManagerError::MissingIntermediates(
                oprf_key_id,
                pending_epoch,
            ))
        }
    }

    #[instrument(level = "debug", skip_all, fields(oprf_key_id=%oprf_key_id, epoch=%epoch))]
    async fn confirm_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        public_key: OprfPublicKey,
    ) -> super::Result<()> {
        tracing::trace!("storing share...");

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
            if Self::get_share_by_epoch_inner(oprf_key_id, epoch, &mut *conn)
                .await?
                .is_some()
            {
                tracing::debug!("already have this share stored - delete intermediates");
                Self::delete_intermediates_inner(oprf_key_id, &mut *conn).await?;
                tx.commit().await?;
                return Ok(());
            }
            let pending_share = Self::fetch_pending_share_inner(oprf_key_id, epoch, &mut *conn)
                .await?
                .ok_or_else(|| {
                    PostgresSecretManagerError::MissingIntermediates(oprf_key_id, epoch)
                })?;

            let rows_affected = Self::store_confirmed_dlog_share_inner(
                oprf_key_id,
                epoch,
                &public_key,
                &pending_share,
                &mut *conn,
            )
            .await?;
            if rows_affected != 1 {
                return Err(PostgresSecretManagerError::RefusingToRollbackEpoch);
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

impl PostgresSecretManager {
    #[inline]
    fn backoff_strategy(&self) -> ConstantBackoff {
        ConstantBuilder::new()
            .with_delay(self.retry_delay)
            .with_max_times(self.max_retries.get())
            .build()
    }

    async fn get_share_by_epoch_inner(
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        conn: impl PgExecutor<'_>,
    ) -> Result<Option<DLogShareShamir>> {
        sqlx::query_scalar(
            "
                SELECT share
                FROM shares
                WHERE id = $1 AND epoch = $2 AND deleted = false
            ",
        )
        .bind(oprf_key_id.to_le_bytes())
        // Postgres lacks u32; cast to i64 to satisfy SQLx type mapping
        .bind(i64::from(epoch))
        .fetch_optional(conn)
        .await?
        .map(from_db_ark_serialize_uncompressed)
        .transpose()
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

    async fn fetch_pending_share_inner(
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        conn: impl PgExecutor<'_>,
    ) -> Result<Option<DLogShareShamir>> {
        sqlx::query_scalar(
            "
                SELECT pending_share
                FROM in_progress_keygens
                WHERE id = $1
                  AND pending_epoch = $2;
            ",
        )
        .bind(oprf_key_id.to_le_bytes())
        // Postgres lacks u32; cast to i64 to satisfy SQLx type mapping
        .bind(i64::from(pending_epoch))
        .fetch_optional(conn)
        .await?
        .flatten()
        .map(from_db_ark_serialize_uncompressed)
        .transpose()
    }

    async fn store_confirmed_dlog_share_inner(
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        public_key: &OprfPublicKey,
        share: &DLogShareShamir,
        conn: impl PgExecutor<'_>,
    ) -> Result<u64> {
        Ok(sqlx::query(
            "
                INSERT INTO shares (id, share, epoch, public_key)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (id)
                DO UPDATE SET
                    share = EXCLUDED.share,
                    epoch = EXCLUDED.epoch,
                    public_key = EXCLUDED.public_key
                WHERE
                    shares.epoch < EXCLUDED.epoch;
            ",
        )
        .bind(oprf_key_id.to_le_bytes())
        .bind(to_db_ark_serialize_uncompressed(share).as_slice())
        // Postgres lacks u32; cast to i64 to satisfy SQLx type mapping
        .bind(i64::from(pending_epoch))
        .bind(to_db_ark_serialize_uncompressed(public_key).as_slice())
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

    async fn with_retry<F, Fut, T>(&self, op_name: &str, f: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        f.retry(self.backoff_strategy())
            .sleep(tokio::time::sleep)
            .when(is_retryable_error)
            .notify(|e, duration| {
                tracing::warn!("Retrying {op_name} in db: {e} after {duration:?}");
            })
            .await
    }
}

#[inline]
fn is_retryable_error(e: &PostgresSecretManagerError) -> bool {
    match e {
        PostgresSecretManagerError::DbError(err) => match err {
            // structural / driver-level errors
            sqlx::Error::PoolTimedOut
            | sqlx::Error::Io(_)
            | sqlx::Error::Tls(_)
            | sqlx::Error::Protocol(_)
            | sqlx::Error::AnyDriverError(_)
            | sqlx::Error::WorkerCrashed
            | sqlx::Error::BeginFailed => true,

            // serialization_failure and deadlock detected for transactions
            sqlx::Error::Database(db_err) => {
                matches!(db_err.code().as_deref(), Some("40001" | "40P01"))
            }

            _ => false,
        },

        _ => false,
    }
}

#[inline]
fn to_db_ark_serialize_uncompressed<T: CanonicalSerialize>(t: &T) -> zeroize::Zeroizing<Vec<u8>> {
    let mut bytes = Vec::with_capacity(t.uncompressed_size());
    t.serialize_uncompressed(&mut bytes).expect("Can serialize");
    zeroize::Zeroizing::from(bytes)
}

#[inline]
fn from_db_ark_serialize_uncompressed<T: CanonicalDeserialize>(b: Vec<u8>) -> Result<T> {
    T::deserialize_uncompressed(zeroize::Zeroizing::from(b).as_slice()).map_err(|e| {
        PostgresSecretManagerError::from(eyre::eyre!("Cannot deserialize bytes: DB not sane: {e}"))
    })
}

#[cfg(test)]
pub(crate) mod tests;
