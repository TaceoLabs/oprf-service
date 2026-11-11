//! This module provides an implementation of [`SecretManager`] using a Postgres database to store shares.
//!
//! Additionally, fetches the node-provider's Ethereum address from the DB.

use std::{num::NonZeroUsize, time::Duration};

use async_trait::async_trait;
use backon::Retryable as _;
use eyre::Context as _;
use nodes_common::postgres::{CreateSchema, PostgresConfig};
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    crypto::{OprfKeyMaterial, OprfPublicKey},
    service::NodeInformation,
};
use sqlx::PgPool;
use tracing::instrument;
use zeroize::ZeroizeOnDrop;

use crate::secret_manager::{SecretManager, SecretManagerError};

/// The postgres secret manager wrapping a `PgPool`.
#[derive(Debug)]
pub struct PostgresSecretManager {
    pool: PgPool,
    max_retries: NonZeroUsize,
    retry_delay: Duration,
}

#[derive(Debug, sqlx::FromRow, ZeroizeOnDrop)]
struct ShareRow {
    id: Vec<u8>,
    share: Option<Vec<u8>>,
    epoch: i64,
    public_key: Vec<u8>,
    deleted: bool,
}

impl PostgresSecretManager {
    /// Initializes the `PostgresSecretManager`.
    ///
    /// Connects to the Postgres database using the provided configuration. This version does **not** run migrations;
    /// it assumes the database is already set up.
    ///
    /// Stores the max retries and retry delay from the configuration for
    /// use in future database operations.
    ///
    /// # Errors
    /// Returns an error if the connection to the database fails.
    #[instrument(level = "debug", skip_all)]
    pub async fn init(config: &PostgresConfig) -> eyre::Result<Self> {
        tracing::debug!("init PgPool with schema: {}", config.schema);
        let pool = nodes_common::postgres::pg_pool_with_schema(config, CreateSchema::No)
            .await
            .context("while connecting to postgres DB")?;
        // we don't run migrations, we just read
        // TODO do we need to check version of the DB to fast crash if migrations don't match?
        Ok(Self {
            pool,
            max_retries: config.max_retries,
            retry_delay: config.retry_delay,
        })
    }
}

#[async_trait]
impl SecretManager for PostgresSecretManager {
    #[instrument(level = "debug", skip_all)]
    async fn load_node_information(&self) -> eyre::Result<NodeInformation> {
        let node_information: NodeInformation = (|| {
            sqlx::query_as(
                "SELECT eth_address,party_id,threshold FROM node_information WHERE id = TRUE",
            )
            .fetch_optional(&self.pool)
        })
        .retry(oprf_store::retry::backoff(
            self.max_retries,
            self.retry_delay,
        ))
        .sleep(tokio::time::sleep)
        .when(oprf_store::retry::is_transient)
        .notify(|err, duration| tracing::warn!(%err, "retrying load address after {duration:?}"))
        .await?
        .ok_or_else(|| {
            eyre::eyre!("Cannot get node information from DB, maybe key-gen needs to start")
        })?;
        Ok(node_information)
    }

    #[instrument(level = "debug", skip_all)]
    async fn get_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> Result<OprfKeyMaterial, SecretManagerError> {
        let maybe_row: Option<ShareRow> = (|| {
            sqlx::query_as(
                "
                    SELECT
                        id,
                        share,
                        epoch,
                        deleted,
                        public_key
                    FROM shares
                    WHERE id = $1
                ",
            )
            .bind(oprf_key_id.to_le_bytes())
            .fetch_optional(&self.pool)
        })
        .retry(oprf_store::retry::backoff(self.max_retries, self.retry_delay))
        .sleep(tokio::time::sleep)
        .when(oprf_store::retry::is_transient)
        .notify(|err, duration| {
            tracing::warn!(%err, "retrying get_oprf_key_material for {oprf_key_id} after {duration:?}");
        })
        .await
        .context("while fetching previous share")?;
        if let Some(row) = maybe_row {
            if row.deleted {
                tracing::trace!("requested deleted key-material");
                Err(SecretManagerError::DeletedOprfKeyId(oprf_key_id))
            } else {
                tracing::trace!("found key-material");
                let (_, key_material) = db_row_into_key_material(&row)?;
                Ok(key_material)
            }
        } else {
            tracing::trace!("Cannot find share for requested key and epoch");
            Err(SecretManagerError::UnknownOprfKeyId(oprf_key_id))
        }
    }
}

/// Converts a row from the DB to an [`OprfKeyId`] and an associated [`OprfKeyMaterial`].
///
/// This method assumes that the shares column is populated, otherwise it will return an error.
fn db_row_into_key_material(
    row: &ShareRow,
) -> Result<(OprfKeyId, OprfKeyMaterial), SecretManagerError> {
    let id = OprfKeyId::from_le_slice(&row.id);
    let share =
        oprf_store::codec::from_bytes::<DLogShareShamir>(row.share.as_ref().ok_or_else(|| {
            SecretManagerError::Internal(eyre::eyre!("share column is NONE for non deleted row"))
        })?)
        .map_err(|err| SecretManagerError::Internal(eyre::Report::from(err)))?;
    let epoch = ShareEpoch::new(
        row.epoch
            .try_into()
            .expect("DB epoch value out of valid u32 range"),
    );
    let oprf_public_key = oprf_store::codec::from_bytes::<OprfPublicKey>(&row.public_key)
        .map_err(|err| SecretManagerError::Internal(eyre::Report::from(err)))?;
    Ok((id, OprfKeyMaterial::new(share, oprf_public_key, epoch)))
}

#[cfg(test)]
mod tests;
