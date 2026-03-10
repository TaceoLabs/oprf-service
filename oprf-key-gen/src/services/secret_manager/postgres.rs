//! This module provides an implementation of [`SecretManager`] using a Postgres database to store shares and the AWS secret-manager to store the Ethereum private-key of the node provider.
//!
//! If the EVM private-key doesn't exist at the requested `secret-id`, it will create a new one and store it. Additionally, will store the associated address in the DB so that the accompanying OPRF-nodes can fetch the address from there.

use std::num::NonZeroUsize;
use std::time::Duration;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use alloy::signers::local::PrivateKeySigner;
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

use crate::secret_manager::{self, SecretManager};

/// The postgres secret manager wrapping a `PgPool`.
#[derive(Debug)]
pub struct PostgresSecretManager {
    pool: PgPool,
    aws_config: aws_config::SdkConfig,
    wallet_private_key_secret_id: String,
    max_retries: NonZeroUsize,
    retry_delay: Duration,
}

impl PostgresSecretManager {
    /// Initializes a `PostgresSecretManager` and potentially runs migrations if necessary.
    #[instrument(level = "info", skip_all)]
    pub async fn init(
        db_config: &PostgresConfig,
        aws_config: aws_config::SdkConfig,
        wallet_private_key_secret_id: &str,
    ) -> eyre::Result<Self> {
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
            wallet_private_key_secret_id: wallet_private_key_secret_id.to_owned(),
            aws_config,
            max_retries: db_config.max_retries,
            retry_delay: db_config.retry_delay,
        })
    }
}

#[async_trait]
impl SecretManager for PostgresSecretManager {
    #[instrument(level = "info", skip_all)]
    async fn load_or_insert_wallet_private_key(&self) -> eyre::Result<PrivateKeySigner> {
        // load or insert the key with the secret-manager
        // has internal backoff strategy, therefore we don't need to wrap this manually.
        let private_key = secret_manager::aws::load_or_insert_ethereum_private_key(
            &aws_sdk_secretsmanager::Client::new(&self.aws_config),
            &self.wallet_private_key_secret_id,
        )
        .await?;
        tracing::debug!("insert address into DB...");
        // insert address into postgres DB
        (|| {
            sqlx::query(
                r#"
                    INSERT INTO evm_address (id, address)
                    VALUES (TRUE, $1)
                    ON CONFLICT (id)
                    DO UPDATE SET address = EXCLUDED.address
                "#,
            )
            .bind(private_key.address().to_string())
            .execute(&self.pool)
        })
        .retry(self.backoff_strategy())
        .sleep(tokio::time::sleep)
        .when(is_retryable_error)
        .notify(|e, duration| {
            tracing::warn!("Retrying load or insert db: {e:?} after {duration:?}")
        })
        .await
        .context("while storing address into DB")?;
        tracing::info!("stored address in DB");
        Ok(private_key)
    }

    async fn ping(&self) -> eyre::Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .context("while pinging DB")?;
        Ok(())
    }

    #[instrument(level = "info", skip_all, fields(oprf_key_id, generated_epoch))]
    async fn get_share_by_epoch(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> eyre::Result<Option<DLogShareShamir>> {
        tracing::debug!("loading share...");
        let maybe_share_bytes: Option<Vec<u8>> = (|| {
            sqlx::query_scalar(
                r#"
                    SELECT share
                    FROM shares
                    WHERE id = $1 AND epoch = $2 AND deleted = false
                "#,
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
            )
        })
        .await
        .with_context(||format!("while fetching share {oprf_key_id} with epoch {epoch}"))?;

        if let Some(share_bytes) = maybe_share_bytes {
            Ok(Some(
                DLogShareShamir::deserialize_uncompressed(share_bytes.as_slice())
                    .context("Cannot deserialize share: DB not sane")?,
            ))
        } else {
            tracing::debug!("Cannot find share for requested key and epoch");
            Ok(None)
        }
    }

    #[instrument(level = "info", skip_all, fields(oprf_key_id))]
    async fn remove_oprf_key_material(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        tracing::debug!("trying to delete key-material..");
        let rows_deleted = (|| {
            sqlx::query(
                r#"
                    UPDATE shares
                    SET
                        share = NULL,
                        deleted = true
                    WHERE id = $1
                "#,
            )
            .bind(oprf_key_id.to_le_bytes())
            .execute(&self.pool)
        })
        .retry(self.backoff_strategy())
        .sleep(tokio::time::sleep)
        .when(is_retryable_error)
        .notify(|e, duration| {
            tracing::warn!("Retrying remove {oprf_key_id} in db: {e:?} after {duration:?}")
        })
        .await
        .with_context(|| format!("while deleting key-share {oprf_key_id}"))?
        .rows_affected();

        tracing::info!("deleted {rows_deleted} secrets from postgres");
        Ok(())
    }

    #[instrument(level = "info", skip_all, fields(oprf_key_id, epoch))]
    async fn store_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        public_key: OprfPublicKey,
        epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> eyre::Result<()> {
        tracing::info!("storing share...");

        let success = (|| {
            sqlx::query(
                r#"
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
                "#,
            )
            .bind(oprf_key_id.to_le_bytes())
            .bind(to_db_ark_serialize_uncompressed(share.clone()))
            .bind(i64::from(epoch.into_inner())) // convert to larger i64 to preserve sign of epoch, we compare share.epoch and if we flip the sign this might break something
            .bind(to_db_ark_serialize_uncompressed(public_key))
            .execute(&self.pool)
        })
        .retry(self.backoff_strategy())
        .sleep(tokio::time::sleep)
        .when(is_retryable_error)
        .notify(|e, duration| {
            tracing::warn!("Retrying store DLogShare {oprf_key_id} in db: {e:?} after {duration:?}")
        })
        .await
        .with_context(|| format!("while storing DLogShare {oprf_key_id}"))?;
        if success.rows_affected() == 0 {
            tracing::warn!(
                "Did not insert anything, maybe someone else stored something with later epoch?"
            )
        } else {
            tracing::info!("successfully stored {oprf_key_id}");
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
fn to_db_ark_serialize_uncompressed<T: CanonicalSerialize>(t: T) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(t.uncompressed_size());
    t.serialize_uncompressed(&mut bytes).expect("Can serialize");
    bytes
}

#[cfg(test)]
mod tests;
