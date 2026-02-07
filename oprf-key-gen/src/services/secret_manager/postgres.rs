//! This module provides an implementation of [`SecretManager`] using a Postgres database to store shares and the AWS secret-manager to store the Ethereum private-key of the node provider.
//!
//! If the EVM private-key doesn't exist at the requested `secret-id`, it will create a new one and store it. Additionally, will store the associated address in the DB so that the accompanying OPRF-nodes can fetch the address from there.

use std::{num::NonZeroU32, time::Duration};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use alloy::signers::local::PrivateKeySigner;
use async_trait::async_trait;
use backoff::ExponentialBackoff;
use eyre::Context;
use itertools::Itertools;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{OprfKeyId, ShareEpoch};
use secrecy::{ExposeSecret, SecretString};
use sqlx::{Executor as _, PgPool, postgres::PgPoolOptions};
use tracing::instrument;

use crate::secret_manager::{self, SecretManager, SecretManagerError, StoreDLogShare};

impl From<sqlx::Error> for SecretManagerError {
    fn from(value: sqlx::Error) -> Self {
        match value {
            sqlx::Error::PoolTimedOut => Self::Recoverable,
            err => SecretManagerError::NonRecoverable(eyre::eyre!(err)),
        }
    }
}

/// The postgres secret manager wrapping a `PgPool`.
#[derive(Debug)]
pub struct PostgresSecretManager {
    pool: PgPool,
    aws_config: aws_config::SdkConfig,
    wallet_private_key_secret_id: String,
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
    pub async fn init(
        connection_string: &SecretString,
        schema: &str,
        max_connections: NonZeroU32,
        acquire_timeout: Duration,
        aws_config: aws_config::SdkConfig,
        wallet_private_key_secret_id: &str,
    ) -> eyre::Result<Self> {
        tracing::debug!("building pool");
        // we only need one connection but as this will be used behind an Arc, we can't use PgConnection, as this needs a mutable reference to execute queries.
        tracing::info!("using schema: {schema}");
        let schema_connect = schema_connect(schema).context("while building schema string")?;
        let pool = PgPoolOptions::new()
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
            })
            .connect(connection_string.expose_secret())
            .await
            .context("while connecting to postgres DB")?;
        tracing::info!("running migrations...");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("while running migrations")?;
        Ok(Self {
            pool,
            wallet_private_key_secret_id: wallet_private_key_secret_id.to_owned(),
            aws_config,
        })
    }
}

#[async_trait]
impl SecretManager for PostgresSecretManager {
    #[instrument(level = "info", skip_all)]
    async fn load_or_insert_wallet_private_key(&self) -> eyre::Result<PrivateKeySigner> {
        // load or insert the key with the secret-manager
        let private_key = secret_manager::aws::load_or_insert_ethereum_private_key(
            &aws_sdk_secretsmanager::Client::new(&self.aws_config),
            &self.wallet_private_key_secret_id,
        )
        .await?;
        tracing::debug!("insert address into DB...");
        // insert address into postgres DB
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
        // we also need to implement exponential backoff here but reshare is not planed in the upcoming weeks, therefore we wait for the key-gen stability rewrite in version 1.1
        let maybe_share_bytes: Option<Vec<u8>> = sqlx::query_scalar(
            r#"
                SELECT share
                FROM shares
                WHERE id = $1 AND epoch = $2
            "#,
        )
        .bind(oprf_key_id.to_le_bytes())
        .bind(i64::from(epoch))
        .fetch_optional(&self.pool)
        .await
        .context("while fetching previous share")?;

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
    async fn remove_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> Result<(), SecretManagerError> {
        let backoff = ExponentialBackoff::default();
        let rows_deleted = backoff::future::retry(backoff, || async {
            let result = sqlx::query(
                r#"
                DELETE FROM shares
                WHERE id = $1
            "#,
            )
            .bind(oprf_key_id.to_le_bytes())
            .execute(&self.pool)
            .await;
            match result {
                Ok(success) => Ok(success.rows_affected()),
                Err(sqlx::Error::PoolTimedOut) => {
                    tracing::warn!("Ran into timeout while deleting key-material");
                    Err(backoff::Error::transient(sqlx::Error::PoolTimedOut))
                }
                Err(err) => Err(backoff::Error::Permanent(err)),
            }
        })
        .await?;
        tracing::info!("deleted {rows_deleted} secrets from postgres");
        Ok(())
    }

    #[instrument(level = "info", skip_all)]
    async fn remove_oprf_key_material_batch(&self, oprf_key_ids: &[OprfKeyId]) -> eyre::Result<()> {
        tracing::info!("Remove oprf key material batch: {}", oprf_key_ids.len());
        if oprf_key_ids.is_empty() {
            return Ok(());
        }
        let ids = oprf_key_ids.iter().map(|id| id.to_le_bytes()).collect_vec();

        let success = sqlx::query(
            r#"
                DELETE FROM shares
                WHERE id = ANY($1::bytea[])
            "#,
        )
        .bind(&ids)
        .execute(&self.pool)
        .await?;
        tracing::info!("Deleted {} rows", success.rows_affected());
        Ok(())
    }

    #[instrument(level = "info", skip_all, fields(store_dlog_share.oprf_key_id, store_dlog_share.epoch))]
    async fn store_dlog_share(
        &self,
        store_dlog_share: StoreDLogShare,
    ) -> Result<(), SecretManagerError> {
        let StoreDLogShare {
            oprf_key_id,
            public_key,
            epoch,
            share,
        } = store_dlog_share;
        tracing::info!("storing share...");
        let backoff = ExponentialBackoff::default();

        backoff::future::retry(backoff, || async {
            let query_result = sqlx::query(
                r#"
                    INSERT INTO shares (id, share, epoch, public_key)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (id)
                    DO UPDATE SET
                        share = EXCLUDED.share,
                        epoch = EXCLUDED.epoch,
                        public_key = EXCLUDED.public_key
                    WHERE shares.epoch < EXCLUDED.epoch;
                "#,
            )
            .bind(oprf_key_id.to_le_bytes())
            .bind(to_db_ark_serialize_uncompressed(share.clone()))
            .bind(i64::from(epoch.into_inner())) // convert to larger i64 to preserve sign of epoch, we compare share.epoch and if we flip the sign this might break something
            .bind(to_db_ark_serialize_uncompressed(public_key))
            .execute(&self.pool)
            .await;
            match query_result {
                Ok(success) => {
                    if success.rows_affected() == 0 {
                        tracing::warn!("Did not insert anything, maybe someone else stored something with later epoch?")
                    } else {
                        tracing::info!("Successfully stored share!");
                    }
                    Ok(())
                }
                Err(sqlx::Error::PoolTimedOut) => {
                    tracing::warn!("Ran into timeout while storing DLogShare");
                    Err(backoff::Error::transient(sqlx::Error::PoolTimedOut))
                }
                Err(err) => Err(backoff::Error::Permanent(err)),
            }
        })
        .await?;
        Ok(())
    }

    /// Stores a batch of OPRF secrets.
    ///
    /// _Attention_: Overwrites old shares!
    #[instrument(level = "info", skip_all)]
    async fn store_dlog_share_batch(
        &self,
        store_dlog_shares: Vec<StoreDLogShare>,
    ) -> eyre::Result<()> {
        tracing::info!("storing batch DLogShare {}..", store_dlog_shares.len());
        let mut ids = Vec::with_capacity(store_dlog_shares.len());
        let mut public_keys = Vec::with_capacity(store_dlog_shares.len());
        let mut epochs = Vec::with_capacity(store_dlog_shares.len());
        let mut shares = Vec::with_capacity(store_dlog_shares.len());
        for store_dlog_share in store_dlog_shares {
            ids.push(store_dlog_share.oprf_key_id.to_le_bytes());
            public_keys.push(to_db_ark_serialize_uncompressed(
                store_dlog_share.public_key,
            ));
            epochs.push(i64::from(store_dlog_share.epoch));
            shares.push(to_db_ark_serialize_uncompressed(store_dlog_share.share))
        }
        let result = sqlx::query(
            r#"
                INSERT INTO shares (id, share, epoch, public_key)
                SELECT *
                FROM UNNEST(
                    $1::bytea[],
                    $2::bytea[],
                    $3::bigint[],
                    $4::bytea[]
                )
                ON CONFLICT (id)
                DO UPDATE SET
                    share = EXCLUDED.share,
                    epoch = EXCLUDED.epoch,
                    public_key = EXCLUDED.public_key
                WHERE shares.epoch < EXCLUDED.epoch;
            "#,
        )
        .bind(&ids)
        .bind(&shares)
        .bind(&epochs)
        .bind(&public_keys)
        .execute(&self.pool)
        .await
        .context("while doing batch store")?;
        tracing::info!("Batch store updated {} rows", result.rows_affected());
        Ok(())
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
