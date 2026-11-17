//! This module provides an implementation of [`SecretManager`] using a Postgres database to store shares.
//!
//! Additionally, fetches the node-provider's Ethereum address from the DB.
//!
//! Shares are read in the storage formats allowed by [`NodeStorageConfig`]. The
//! `storage_format` column of a row only describes the row; the configuration decides whether
//! the node reads it. A row in a format that is not allowed is refused, never read in another
//! format.

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use async_trait::async_trait;
use eyre::Context as _;
use nodes_common::postgres::{CreateSchema, PostgresConfig};
use oprf_store::{StorageCrypto, StoreError, aad::AadContext, data_keys};
use oprf_types::{OprfKeyId, crypto::OprfKeyMaterial, service::NodeInformation};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    metrics::storage::{self as storage_metrics, Rejection},
    secret_manager::{SecretManager, SecretManagerError},
};

pub use oprf_store::{
    DekWrapper, EnvelopeError, KeyArn, KmsConfig, WrappingKeyConfig, format::StorageFormat,
};

/// Which storage formats the node reads shares in.
///
/// Deserialized from these fields; a combination that is not valid fails to deserialize:
///
/// | Field                     | Default    |                                              |
/// |---------------------------|------------|----------------------------------------------|
/// | `allowed_storage_formats` | `[direct]` | Formats shares are read in; must not be empty. |
/// | `kms_key_arn`             | none       | Full ARN of the AWS KMS key wrapping the data keys. |
/// | `kms_endpoint`            | none       | Custom AWS KMS endpoint (e.g. for local testing). |
/// | `storage_master_key`      | none       | Master key wrapping the data keys locally, without AWS KMS: exactly 64 hex characters (32 bytes), the same key as configured for the key-gen of this party. |
///
/// If `envelopeV1` is allowed, exactly one of `kms_key_arn` and `storage_master_key` is required.
/// Whoever reads the master key and the database reads every share.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawNodeStorageConfig")]
#[allow(
    clippy::exhaustive_enums,
    reason = "consumers must handle every way shares are stored"
)]
pub enum NodeStorageConfig {
    /// Reads `direct` only; no wrapping key is used.
    #[default]
    Direct,
    /// Reads `envelopeV1`, and `direct` too if `read_direct` is set.
    Envelope {
        /// Whether `direct` rows are read as well.
        read_direct: bool,
        /// The key wrapping the data keys.
        key: WrappingKeyConfig,
    },
}

/// The fields [`NodeStorageConfig`] is deserialized from.
#[derive(Deserialize)]
struct RawNodeStorageConfig {
    #[serde(default = "default_allowed_storage_formats")]
    allowed_storage_formats: Vec<StorageFormat>,
    #[serde(default)]
    kms_key_arn: Option<String>,
    #[serde(default)]
    kms_endpoint: Option<String>,
    #[serde(default)]
    storage_master_key: Option<SecretString>,
}

fn default_allowed_storage_formats() -> Vec<StorageFormat> {
    vec![StorageFormat::Direct]
}

impl TryFrom<RawNodeStorageConfig> for NodeStorageConfig {
    type Error = eyre::Report;

    fn try_from(raw: RawNodeStorageConfig) -> eyre::Result<Self> {
        let allows = |format| raw.allowed_storage_formats.contains(&format);
        let read_direct = allows(StorageFormat::Direct);
        if !allows(StorageFormat::EnvelopeV1) {
            eyre::ensure!(read_direct, "allowed_storage_formats must not be empty");
            return Ok(Self::Direct);
        }
        let key = WrappingKeyConfig::parse(
            raw.kms_key_arn,
            raw.kms_endpoint,
            raw.storage_master_key
                .as_ref()
                .map(ExposeSecret::expose_secret),
        )?;
        Ok(Self::Envelope { read_direct, key })
    }
}

/// Which storage formats the node reads, with the wrapper of the data keys if `envelopeV1` is
/// read.
#[derive(Clone)]
#[allow(
    clippy::exhaustive_enums,
    reason = "constructed by callers; mirrors `NodeStorageConfig`"
)]
pub enum NodeStorage {
    /// Reads `direct` only.
    Direct,
    /// Reads `envelopeV1`, and `direct` too if `read_direct` is set.
    Envelope {
        /// Whether `direct` rows are read as well.
        read_direct: bool,
        /// Unwraps the data keys.
        wrapper: Arc<dyn DekWrapper>,
    },
}

/// The postgres secret manager wrapping a `PgPool`.
pub struct PostgresSecretManager {
    pool: PgPool,
    max_retries: NonZeroUsize,
    retry_delay: Duration,
    /// The read-only storage policy.
    crypto: StorageCrypto,
    /// Unwraps data keys; set exactly if `envelopeV1` is read.
    wrapper: Option<Arc<dyn DekWrapper>>,
    /// Serializes on-demand loads of data keys, so that concurrent requests for rows under a
    /// key that is not loaded yet cause one KMS call, not one each.
    load_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for PostgresSecretManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresSecretManager")
            .field("pool", &self.pool)
            .field("max_retries", &self.max_retries)
            .field("retry_delay", &self.retry_delay)
            .field("crypto", &self.crypto)
            .field(
                "wrapping_key_id",
                &self.wrapper.as_ref().map(|w| w.key_id()),
            )
            .finish_non_exhaustive()
    }
}

impl PostgresSecretManager {
    /// Initializes the `PostgresSecretManager`.
    ///
    /// Only if `envelopeV1` is read, creates the data key wrapper for the configured key and
    /// continues as [`PostgresSecretManager::init_with_storage`]. A node that only reads `direct`
    /// never touches AWS, and neither does one with a local master key.
    ///
    /// The AWS KMS wrapper needs the `aws-kms` feature. Without it, use a local master key or
    /// [`PostgresSecretManager::init_with_storage`] to read `envelopeV1` rows.
    ///
    /// # Errors
    /// Returns an error if `envelopeV1` is read with a KMS key and the `aws-kms` feature is not
    /// enabled. Otherwise see [`PostgresSecretManager::init_with_storage`].
    #[instrument(level = "debug", skip_all)]
    pub async fn init(config: &PostgresConfig, storage: &NodeStorageConfig) -> eyre::Result<Self> {
        let storage = match storage {
            NodeStorageConfig::Direct => NodeStorage::Direct,
            NodeStorageConfig::Envelope { read_direct, key } => {
                let wrapper = key
                    .clone()
                    .wrapper()
                    .await
                    .context("invalid storage configuration")?;
                tracing::info!(
                    wrapping = wrapper.wrapping(),
                    key_id = wrapper.key_id(),
                    "unwrapping data keys"
                );
                NodeStorage::Envelope {
                    read_direct: *read_direct,
                    wrapper,
                }
            }
        };
        Self::init_with_storage(config, storage).await
    }

    /// Initializes the `PostgresSecretManager` with the given storage.
    ///
    /// Connects to the Postgres database using the provided configuration. This version does **not** run migrations;
    /// it assumes the database is already set up.
    ///
    /// Stores the max retries and retry delay from the configuration for
    /// use in future database operations.
    ///
    /// If `envelopeV1` is read, loads the party id and threshold from `node_information` and
    /// every data key, unwrapped with the wrapper of `storage`. Otherwise neither
    /// `node_information` nor the KMS is touched.
    ///
    /// # Errors
    /// Returns an error if the connection to the database fails, and, if `envelopeV1` is read,
    /// if `node_information` is missing or a data key cannot be loaded (e.g. the KMS call fails
    /// or the key was wrapped under another key).
    #[instrument(level = "debug", skip_all)]
    pub async fn init_with_storage(
        config: &PostgresConfig,
        storage: NodeStorage,
    ) -> eyre::Result<Self> {
        tracing::debug!("init PgPool with schema: {}", config.schema);
        let pool = nodes_common::postgres::pg_pool_with_schema(config, CreateSchema::No)
            .await
            .context("while connecting to postgres DB")?;
        // we don't run migrations, we just read
        // TODO do we need to check version of the DB to fast crash if migrations don't match?
        let (crypto, wrapper) = match storage {
            // `direct` values are not bound to anything: no context, no data keys, no wrapper.
            NodeStorage::Direct => (StorageCrypto::direct_only(), None),
            NodeStorage::Envelope {
                read_direct,
                wrapper,
            } => {
                let allowed: &[StorageFormat] = if read_direct {
                    &[StorageFormat::Direct, StorageFormat::EnvelopeV1]
                } else {
                    &[StorageFormat::EnvelopeV1]
                };
                let node_information =
                    fetch_node_information(&pool, config.max_retries, config.retry_delay).await?;
                let ctx = AadContext {
                    party_id: node_information.party_id(),
                    threshold: node_information.threshold(),
                };
                let deks = data_keys::load_all(&pool, wrapper.as_ref())
                    .await
                    .context("while loading the data keys")?;
                tracing::info!(?allowed, data_keys = deks.len(), "loaded data keys");
                (StorageCrypto::new(allowed, ctx, deks), Some(wrapper))
            }
        };
        Ok(Self {
            pool,
            max_retries: config.max_retries,
            retry_delay: config.retry_delay,
            crypto,
            wrapper,
            load_lock: tokio::sync::Mutex::new(()),
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

    /// Loads the data key `data_key_id` into the storage policy, unless a concurrent call
    /// already did. Not retried.
    async fn load_data_key(&self, data_key_id: Uuid) -> Result<(), SecretManagerError> {
        let _guard = self.load_lock.lock().await;
        if self.crypto.has_dek(data_key_id) {
            return Ok(());
        }
        let wrapper = self
            .wrapper
            .as_deref()
            .ok_or_else(|| eyre::eyre!("no data key wrapper configured"))?;
        match data_keys::load_one(&self.pool, wrapper, data_key_id).await {
            Ok(Some(dek)) => {
                self.crypto.insert_dek(dek);
                tracing::info!(%data_key_id, "loaded data key");
                Ok(())
            }
            Ok(None) => {
                tracing::error!(%data_key_id, "data key does not exist");
                Err(SecretManagerError::StorageFormat(
                    EnvelopeError::UnknownDataKey(data_key_id),
                ))
            }
            Err(err) => {
                tracing::error!(%data_key_id, %err, "loading data key failed");
                Err(SecretManagerError::Internal(
                    eyre::Report::new(err)
                        .wrap_err(format!("while loading data key {data_key_id}")),
                ))
            }
        }
    }
}

/// Records and logs a refused share.
fn reject(oprf_key_id: OprfKeyId, reason: Rejection) {
    tracing::error!(%oprf_key_id, reason = reason.as_str(), "refusing stored key material");
    storage_metrics::inc_rejected(reason);
}

/// The metric reason of an envelope error, if it is counted.
fn rejection(err: &EnvelopeError) -> Option<Rejection> {
    match err {
        EnvelopeError::FormatNotAllowed(_) => Some(Rejection::FormatNotAllowed),
        EnvelopeError::Decrypt => Some(Rejection::Decrypt),
        EnvelopeError::UnknownFormat(_) => Some(Rejection::UnknownFormat),
        EnvelopeError::UnknownDataKey(_) => Some(Rejection::UnknownDataKey),
        _ => None,
    }
}

/// Loads the node information, retrying transient database errors with the given backoff.
async fn fetch_node_information(
    pool: &PgPool,
    max_retries: NonZeroUsize,
    retry_delay: Duration,
) -> eyre::Result<NodeInformation> {
    oprf_store::retry::with_retry(
        "load address",
        oprf_store::retry::backoff(max_retries, retry_delay),
        oprf_store::retry::is_transient,
        || {
            sqlx::query_as(
                "SELECT eth_address,party_id,threshold FROM node_information WHERE id = TRUE",
            )
            .fetch_optional(pool)
        },
    )
    .await?
    .ok_or_else(|| eyre::eyre!("Cannot get node information from DB, maybe key-gen needs to start"))
}

#[async_trait]
impl SecretManager for PostgresSecretManager {
    #[instrument(level = "debug", skip_all)]
    async fn load_node_information(&self) -> eyre::Result<NodeInformation> {
        fetch_node_information(&self.pool, self.max_retries, self.retry_delay).await
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
        // Only load a data key if `envelopeV1` is allowed at all: a row in a format that is not
        // allowed is refused by `open` without any database or KMS call for its key.
        if let Some(data_key_id) = row.data_key_id()
            && self.crypto.allows(StorageFormat::EnvelopeV1)
            && !self.crypto.has_dek(data_key_id)
        {
            self.load_data_key(data_key_id).await.inspect_err(|err| {
                let reason = match err {
                    SecretManagerError::StorageFormat(EnvelopeError::UnknownDataKey(_)) => {
                        Rejection::UnknownDataKey
                    }
                    _ => Rejection::DataKeyLoadFailed,
                };
                reject(oprf_key_id, reason);
            })?;
        }
        match row.open(&self.crypto) {
            Ok(stored) => Ok(OprfKeyMaterial::new(
                stored.share,
                stored.public_key,
                stored.epoch,
            )),
            Err(StoreError::Envelope(err)) => {
                if let Some(reason) = rejection(&err) {
                    reject(oprf_key_id, reason);
                }
                Err(SecretManagerError::StorageFormat(err))
            }
            Err(err) => Err(SecretManagerError::Internal(eyre::Report::from(err))),
        }
    }
}

#[cfg(test)]
mod tests;
