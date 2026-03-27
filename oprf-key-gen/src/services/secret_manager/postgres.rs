//! This module provides an implementation of [`SecretManager`] using a Postgres database to store shares.
//!
//! The wallet private key is accepted directly at initialization and stored in memory. The associated address is written to the DB so that the accompanying OPRF-nodes can fetch it from there.

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
use sqlx::PgPool;
use tracing::instrument;

use crate::secret_manager::SecretManager;

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
        let pool = nodes_common::postgres::pg_pool_with_schema(db_config, CreateSchema::Yes)
            .await
            .context("while creating pool")?;
        // if we just got a fresh db pool, we have a valid connection, as we don't have connect_lazy, therefore this should not run into timeouts.
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
    async fn store_wallet_address(&self, address: String) -> eyre::Result<()> {
        let _query_res = (|| {
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
        })
        .retry(self.backoff_strategy())
        .sleep(tokio::time::sleep)
        .when(is_retryable_error)
        .notify(|e, duration| {
            tracing::warn!("Retrying inserting wallet address into db: {e:?} after {duration:?}");
        })
        .await
        .context("while storing address into DB")?;
        Ok(())
    }

    async fn ping(&self) -> eyre::Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .context("while pinging DB")?;
        Ok(())
    }

    async fn get_share_by_epoch(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> eyre::Result<Option<DLogShareShamir>> {
        tracing::trace!("loading share...");
        let maybe_share_bytes: Option<Vec<u8>> = (|| {
            sqlx::query_scalar(
                "
                    SELECT share
                    FROM shares
                    WHERE id = $1 AND epoch = $2 AND deleted = false
                ",
            )
            .bind(oprf_key_id.to_le_bytes())
            .bind(i64::from(epoch))
            .fetch_optional(&self.pool)
        })
        .retry(self.backoff_strategy())
        .sleep(tokio::time::sleep)
        .when(is_retryable_error)
        .notify(|e, duration| {
            tracing::warn!(
                "Retrying get_share_epoch {oprf_key_id} because timeout from db: {e:?} after {duration:?}"
            );
        })
        .await
        .with_context(||format!("while fetching share {oprf_key_id} with epoch {epoch}"))?;

        if let Some(share_bytes) = maybe_share_bytes {
            Ok(Some(
                DLogShareShamir::deserialize_uncompressed(share_bytes.as_slice())
                    .context("Cannot deserialize share: DB not sane")?,
            ))
        } else {
            tracing::trace!("Cannot find share for requested key and epoch");
            Ok(None)
        }
    }

    async fn remove_oprf_key_material(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        tracing::trace!("trying to delete key-material..");
        let rows_deleted = (|| {
            sqlx::query(
                "
                    UPDATE shares
                    SET
                        share = NULL,
                        deleted = true
                    WHERE id = $1
                ",
            )
            .bind(oprf_key_id.to_le_bytes())
            .execute(&self.pool)
        })
        .retry(self.backoff_strategy())
        .sleep(tokio::time::sleep)
        .when(is_retryable_error)
        .notify(|e, duration| {
            tracing::warn!("Retrying remove {oprf_key_id} in db: {e:?} after {duration:?}");
        })
        .await
        .with_context(|| format!("while deleting key-share {oprf_key_id}"))?
        .rows_affected();

        tracing::trace!("deleted {rows_deleted} secrets from postgres");
        Ok(())
    }

    async fn store_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        public_key: OprfPublicKey,
        epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> eyre::Result<()> {
        tracing::trace!("storing share...");

        let success = (|| {
            sqlx::query(
                "
                    INSERT INTO shares (id, share, epoch, public_key)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (id)
                    DO UPDATE SET
                        share = EXCLUDED.share,
                        epoch = EXCLUDED.epoch,
                        public_key = EXCLUDED.public_key
                    WHERE
                        shares.epoch < EXCLUDED.epoch AND
                        shares.deleted = false;
                ",
            )
            .bind(oprf_key_id.to_le_bytes())
            .bind(to_db_ark_serialize_uncompressed(&share))
            .bind(i64::from(epoch.into_inner())) // convert to larger i64 to preserve sign of epoch, we compare share.epoch and if we flip the sign this might break something
            .bind(to_db_ark_serialize_uncompressed(&public_key))
            .execute(&self.pool)
        })
        .retry(self.backoff_strategy())
        .sleep(tokio::time::sleep)
        .when(is_retryable_error)
        .notify(|e, duration| {
            tracing::warn!(
                "Retrying store DLogShare {oprf_key_id} in db: {e:?} after {duration:?}"
            );
        })
        .await
        .with_context(|| format!("while storing DLogShare {oprf_key_id}"))?;
        if success.rows_affected() == 0 {
            tracing::warn!(
                "Did not insert anything, maybe someone else stored something with later epoch?"
            );
        } else {
            tracing::trace!("successfully stored {oprf_key_id}");
        }
        Ok(())
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
}

#[inline]
fn is_retryable_error(e: &sqlx::Error) -> bool {
    matches!(
        e,
        sqlx::Error::PoolTimedOut
            | sqlx::Error::Io(_)
            | sqlx::Error::Tls(_)
            | sqlx::Error::Protocol(_)
            | sqlx::Error::AnyDriverError(_)
            | sqlx::Error::WorkerCrashed
    )
}

#[inline]
fn to_db_ark_serialize_uncompressed<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(t.uncompressed_size());
    t.serialize_uncompressed(&mut bytes).expect("Can serialize");
    bytes
}

#[cfg(test)]
mod tests;
