//! This module provides an implementation of [`SecretManager`] using a Postgres database to store shares.
//!
//! Additionally, fetches the node-provider's Ethereum address from the DB.

use std::{collections::HashMap, num::NonZeroUsize, time::Duration};

use alloy::primitives::Address;
use ark_serialize::CanonicalDeserialize;
use async_trait::async_trait;
use backon::{BackoffBuilder as _, ConstantBackoff, ConstantBuilder, Retryable as _};
use eyre::Context as _;
use nodes_common::postgres::{CreateSchema, PostgresConfig};
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    crypto::{OprfKeyMaterial, OprfPublicKey},
};
use secrecy::zeroize::ZeroizeOnDrop;
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

#[derive(Debug, sqlx::FromRow, ZeroizeOnDrop)]
struct ShareRow {
    id: Vec<u8>,
    share: Vec<u8>,
    epoch: i64,
    public_key: Vec<u8>,
}

impl From<ShareRow> for (OprfKeyId, OprfKeyMaterial) {
    fn from(value: ShareRow) -> Self {
        db_row_into_key_material(&value)
    }
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
    async fn load_address(&self) -> eyre::Result<Address> {
        let stored_address: String = (|| {
            sqlx::query_scalar("SELECT address FROM evm_address WHERE id = TRUE")
                .fetch_optional(&self.pool)
        })
        .retry(self.backoff_strategy())
        .sleep(tokio::time::sleep)
        .when(is_retryable_error)
        .notify(|e, duration| tracing::warn!("Retrying load address: {e:?} after {duration:?}"))
        .await?
        .ok_or_else(|| eyre::eyre!("Cannot get address from DB, maybe key-gen needs to start"))?;
        Address::parse_checksummed(stored_address, None).context("invalid address stored in DB")
    }

    #[instrument(level = "debug", skip_all)]
    async fn load_secrets(&self) -> eyre::Result<HashMap<OprfKeyId, OprfKeyMaterial>> {
        tracing::trace!("fetching all OPRF keys from DB..");
        let rows: Vec<ShareRow> = (|| {
            sqlx::query_as(
                "
                    SELECT
                        id,
                        share,
                        epoch,
                        public_key
                    FROM shares
                    WHERE deleted = false
                ",
            )
            .fetch_all(&self.pool)
        })
        .retry(self.backoff_strategy())
        .sleep(tokio::time::sleep)
        .when(is_retryable_error)
        .notify(|e, duration| tracing::warn!("Retrying load secrets: {e:?} after {duration:?}"))
        .await
        .context("while fetching all OPRF keys")?;
        tracing::trace!("loaded {} rows. parsing..", rows.len());
        let map = rows
            .iter()
            .map(db_row_into_key_material)
            .collect::<HashMap<_, _>>();
        tracing::trace!("successfully parsed {} OPRF entries", map.len());
        Ok(map)
    }

    #[instrument(level = "debug", skip_all)]
    async fn get_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> eyre::Result<Option<OprfKeyMaterial>> {
        let maybe_row: Option<ShareRow> = (|| {
            sqlx::query_as(
                "
                    SELECT
                        id,
                        share,
                        epoch,
                        public_key
                    FROM shares
                    WHERE id = $1 AND epoch = $2 AND deleted = false
                ",
            )
            .bind(oprf_key_id.to_le_bytes())
            .bind(i64::from(epoch.into_inner()))
            .fetch_optional(&self.pool)
        })
        .retry(self.backoff_strategy())
        .sleep(tokio::time::sleep)
        .when(is_retryable_error)
        .notify(|e, duration| {
            tracing::warn!(
                "Retrying get_oprf_key_material for {oprf_key_id}: {e:?} after {duration:?}"
            );
        })
        .await
        .context("while fetching previous share")?;
        if let Some(row) = maybe_row {
            tracing::trace!("found new key-material!");
            let (_, key_material) = db_row_into_key_material(&row);
            Ok(Some(key_material))
        } else {
            tracing::trace!("Cannot find share for requested key and epoch");
            Ok(None)
        }
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
fn from_db_ark_deserialize_uncompressed<T: CanonicalDeserialize>(b: impl AsRef<[u8]>) -> T {
    T::deserialize_uncompressed_unchecked(b.as_ref()).expect("DB is sane")
}

/// Converts a row from the DB to an [`OprfKeyId`] and an associated [`OprfKeyMaterial`]. This method will panic if the DB is not sane (i.e., has corrupted data stored).
fn db_row_into_key_material(row: &ShareRow) -> (OprfKeyId, OprfKeyMaterial) {
    let id = OprfKeyId::from_le_slice(&row.id);
    let share = from_db_ark_deserialize_uncompressed::<DLogShareShamir>(&row.share);
    let epoch = ShareEpoch::new(
        row.epoch
            .try_into()
            .expect("DB epoch value out of valid u32 range"),
    );
    let oprf_public_key = from_db_ark_deserialize_uncompressed::<OprfPublicKey>(&row.public_key);
    (id, OprfKeyMaterial::new(share, oprf_public_key, epoch))
}

#[cfg(test)]
mod tests;
