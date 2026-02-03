//! This module provides an implementation of [`SecretManager`] using a Postgres database to store shares and the AWS secret-manager to store the Ethereum private-key of the node provider.
//!
//! If the EVM private-key doesn't exist at the requested `secret-id`, it will create a new one and store it. Additionally, will store the associated address in the DB so that the accompanying OPRF-nodes can fetch the address from there.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use alloy::signers::local::PrivateKeySigner;
use async_trait::async_trait;
use eyre::Context;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use secrecy::{ExposeSecret, SecretString};
use sqlx::{Executor as _, PgPool, postgres::PgPoolOptions};
use tracing::instrument;

use crate::secret_manager::{self, SecretManager};

/// The postgres secret manager wrapping a `PgPool`. As we don't want to have multiple connections, we set the `max_pool_size` to 1.
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
        aws_config: aws_config::SdkConfig,
        wallet_private_key_secret_id: &str,
    ) -> eyre::Result<Self> {
        tracing::debug!("building pool");
        // we only need one connection but as this will be used behind an Arc, we can't use PgConnection, as this needs a mutable reference to execute queries.
        tracing::info!("using schema: {schema}");
        let schema_connect = schema_connect(schema).context("while building schema string")?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
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
    async fn remove_oprf_key_material(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        let rows_deleted = sqlx::query(
            r#"
                DELETE FROM shares
                WHERE id = $1
            "#,
        )
        .bind(oprf_key_id.to_le_bytes())
        .execute(&self.pool)
        .await
        .context("while removing OPRF key-material")?
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
        .bind(to_db_ark_serialize_uncompressed(share))
        .bind(i64::from(epoch.into_inner())) // convert to larger i64 to preserve sign of epoch, we compare share.epoch and if we flip the sign this might break something
        .bind(to_db_ark_serialize_uncompressed(public_key))
        .execute(&self.pool)
        .await
        .context("while storing new DLogShare")?;
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
