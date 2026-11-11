//! This module provides an implementation of [`SecretManager`] using a Postgres database to store shares.
//!
//! Additionally, fetches the node-provider's Ethereum address from the DB.

use std::{num::NonZeroUsize, time::Duration};

use async_trait::async_trait;
use eyre::Context as _;
use nodes_common::postgres::{CreateSchema, PostgresConfig};
use oprf_types::{OprfKeyId, crypto::OprfKeyMaterial, service::NodeInformation};
use sqlx::PgPool;
use tracing::instrument;

use crate::secret_manager::{SecretManager, SecretManagerError};

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

    /// Runs `op`, retrying transient database errors with the configured backoff.
    async fn with_retry<T, Fut, F>(&self, op_name: &str, op: F) -> Result<T, sqlx::Error>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, sqlx::Error>>,
    {
        oprf_store::retry::with_retry(
            op_name,
            oprf_store::retry::backoff(self.max_retries, self.retry_delay),
            oprf_store::retry::is_transient,
            op,
        )
        .await
    }
}

#[async_trait]
impl SecretManager for PostgresSecretManager {
    #[instrument(level = "debug", skip_all)]
    async fn load_node_information(&self) -> eyre::Result<NodeInformation> {
        let node_information: NodeInformation = self
            .with_retry("load address", || {
                sqlx::query_as(
                    "SELECT eth_address,party_id,threshold FROM node_information WHERE id = TRUE",
                )
                .fetch_optional(&self.pool)
            })
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
        let maybe_row = self
            .with_retry(&format!("get_oprf_key_material for {oprf_key_id}"), || {
                oprf_store::shares::fetch(&self.pool, oprf_key_id)
            })
            .await
            .context("while fetching previous share")?;
        let Some(row) = maybe_row else {
            tracing::trace!("Cannot find share for requested key and epoch");
            return Err(SecretManagerError::UnknownOprfKeyId(oprf_key_id));
        };
        if row.is_deleted() {
            tracing::trace!("requested deleted key-material");
            return Err(SecretManagerError::DeletedOprfKeyId(oprf_key_id));
        }
        tracing::trace!("found key-material");
        let stored = row
            .decode()
            .map_err(|err| SecretManagerError::Internal(eyre::Report::from(err)))?;
        Ok(OprfKeyMaterial::new(
            stored.share,
            stored.public_key,
            stored.epoch,
        ))
    }
}

#[cfg(test)]
mod tests;
