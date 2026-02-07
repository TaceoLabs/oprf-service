//! This module provides an implementation of [`SecretManager`] using a Postgres database to store shares and the AWS secret-manager to store the Ethereum private-key of the node provider.
//!
//! If the EVM private-key doesn't exist at the requested `secret-id`, it will create a new one and store it. Additionally, will store the associated address in the DB so that the accompanying OPRF-nodes can fetch the address from there.

use std::num::NonZeroUsize;
use std::{num::NonZeroU32, time::Duration};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use alloy::signers::local::PrivateKeySigner;
use async_trait::async_trait;
use backon::BackoffBuilder;
use backon::ConstantBackoff;
use backon::ConstantBuilder;
use backon::Retryable;
use eyre::Context;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use secrecy::{ExposeSecret, SecretString};
use sqlx::{Executor as _, PgPool, postgres::PgPoolOptions};
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

/// The arguments for the [`PostgresSecretManager`].
pub struct PostgresSecretManagerArgs<'a> {
    /// Connection string for the database. Treat this as a secret.
    pub connection_string: &'a SecretString,
    /// Database schema to use. If it does not exist yet, the secret manager will create the schema automatically.
    pub schema: &'a str,
    /// Maximum number of connections in the connection pool.
    pub max_connections: NonZeroU32,
    /// Timeout for acquiring a new connection from the pool. If a connection is not established within this duration, a linear backoff strategy is started.
    pub acquire_timeout: Duration,
    /// The retries during the backoff strategy. DB is considered down, if cannot get connection after this amount of retries.
    pub max_retries: NonZeroUsize,
    /// Sleep duration between retries when connection acquisition from the pool times out.
    pub retry_delay: Duration,
    /// AWS SDK configuration used by the secret manager to load or create the Ethereum private key.
    pub aws_config: aws_config::SdkConfig,
    /// Secret ID used by the secret manager to fetch the Ethereum private key, or to store it if it does not already exist.
    pub wallet_private_key_secret_id: &'a str,
}

fn sanitize_identifier(input: &str) -> eyre::Result<()> {
    eyre::ensure!(!input.is_empty(), "Empty schema is not allowed");
    if input
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        Ok(())
    } else {
        Err(eyre::eyre!("Invalid SQL identifier"))
    }
}

fn schema_connect(schema: &str) -> eyre::Result<String> {
    sanitize_identifier(schema)?;
    Ok(format!(
        r#"
            CREATE SCHEMA IF NOT EXISTS "{schema}";
            SET search_path TO "{schema}";
        "#
    ))
}

impl PostgresSecretManager {
    /// Initializes a `PostgresSecretManager` and potentially runs migrations if necessary.
    #[instrument(level = "info", skip_all)]
    pub async fn init(args: PostgresSecretManagerArgs<'_>) -> eyre::Result<Self> {
        let PostgresSecretManagerArgs {
            connection_string,
            schema,
            max_connections,
            acquire_timeout,
            max_retries,
            retry_delay,
            aws_config,
            wallet_private_key_secret_id,
        } = args;
        tracing::info!("using schema: {schema}");
        let schema_connect = schema_connect(schema).context("while building schema string")?;
        let backoff_strategy = ConstantBuilder::new()
            .with_delay(retry_delay)
            .with_max_times(max_retries.get())
            .build();
        let pg_pool_options = PgPoolOptions::new()
            .max_connections(max_connections.get())
            .acquire_timeout(acquire_timeout)
            .after_connect(move |conn, _| {
                let schema_connect = schema_connect.clone();
                Box::pin(async move {
                    if let Err(e) = conn.execute(schema_connect.as_ref()).await {
                        tracing::error!("error in after_connect: {:?}", e);
                        return Err(e);
                    }
                    Ok(())
                })
            });
        // connect with constant backoff strategy
        let pool = (|| {
            pg_pool_options
                .clone()
                .connect(connection_string.expose_secret())
        })
        .retry(backoff_strategy)
        .sleep(tokio::time::sleep)
        .when(|e| matches!(e, sqlx::Error::PoolTimedOut))
        .notify(|e, duration| {
            tracing::warn!("Timeout while creating pool: {e:?} Retry after {duration:?}")
        })
        .await
        .context("while connecting to postgres DB")?;
        tracing::info!("running migrations...");
        // if we just got a fresh db pool, we have a valid connection, as we don't have connect_lazy, therefore this should not run into timeouts.
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("while running migrations")?;
        Ok(Self {
            pool,
            wallet_private_key_secret_id: wallet_private_key_secret_id.to_owned(),
            aws_config,
            max_retries,
            retry_delay,
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
        .when(|e| matches!(e, sqlx::Error::PoolTimedOut))
        .notify(|e, duration| {
            tracing::warn!("Retrying load or insert db: {e:?} after {duration:?}")
        })
        .await
        .context("while storing address into DB")?;
        tracing::info!("stored address in DB");
        Ok(private_key)
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
                WHERE id = $1 AND epoch = $2
            "#,
            )
            .bind(oprf_key_id.to_le_bytes())
            .bind(i64::from(epoch))
            .fetch_optional(&self.pool)
        })
        .retry(self.backoff_strategy())
        .sleep(tokio::time::sleep)
        .when(|e| matches!(e, sqlx::Error::PoolTimedOut))
        .notify(|e, duration| {
            tracing::warn!(
                "Retrying get_share_epoch {oprf_key_id} because timeout from db: {e:?} after {duration:?}"
            )
        })
        .await
        .context(format!("while fetching share {oprf_key_id} with epoch {epoch}"))?;

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
                DELETE FROM shares
                WHERE id = $1
            "#,
            )
            .bind(oprf_key_id.to_le_bytes())
            .execute(&self.pool)
        })
        .retry(self.backoff_strategy())
        .sleep(tokio::time::sleep)
        .when(|e| matches!(e, sqlx::Error::PoolTimedOut))
        .notify(|e, duration| {
            tracing::warn!("Retrying remove {oprf_key_id} in db: {e:?} after {duration:?}")
        })
        .await
        .context(format!("while deleting key-share {oprf_key_id}"))?
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

        (|| {
            sqlx::query(
                r#"
                INSERT INTO shares (id, share, epoch, public_key)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (id)
                DO UPDATE SET
                    share = EXCLUDED.share,
                    epoch = EXCLUDED.epoch,
                    public_key = EXCLUDED.public_key;
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
        .when(|e| matches!(e, sqlx::Error::PoolTimedOut))
        .notify(|e, duration| {
            tracing::warn!("Retrying store DLogShare {oprf_key_id} in db: {e:?} after {duration:?}")
        })
        .await
        .context(format!("while storing DLogShare {oprf_key_id}"))?;
        tracing::info!("successfully stored {oprf_key_id}");
        Ok(())
    }
}

impl PostgresSecretManager {
    #[inline(always)]
    fn backoff_strategy(&self) -> ConstantBackoff {
        ConstantBuilder::new()
            .with_delay(self.retry_delay)
            .with_max_times(self.max_retries.get())
            .build()
    }
}

#[inline(always)]
fn to_db_ark_serialize_uncompressed<T: CanonicalSerialize>(t: T) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(t.uncompressed_size());
    t.serialize_uncompressed(&mut bytes).expect("Can serialize");
    bytes
}

#[cfg(test)]
mod tests;
