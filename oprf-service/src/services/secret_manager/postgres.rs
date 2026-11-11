//! This module provides an implementation of [`SecretManager`] using a Postgres database to store shares.
//!
//! Additionally, fetches the node-provider's Ethereum address from the DB.
//!
//! Shares are read in the storage formats allowed by [`NodeStorageConfig`]. The
//! `storage_format` column of a row only describes the row; the configuration decides whether
//! the node reads it. A row in a format that is not allowed is refused, never read in another
//! format.

use std::{
    collections::HashMap,
    num::{NonZeroU16, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use eyre::{Context as _, bail};
use nodes_common::postgres::{CreateSchema, PostgresConfig};
use oprf_store::{StorageCrypto, StoreError, aad::AadContext, data_keys};
use oprf_types::{OprfKeyId, crypto::OprfKeyMaterial, crypto::PartyId, service::NodeInformation};
use parking_lot::Mutex;
use serde::Deserialize;
use sqlx::PgPool;
use tokio::time::Instant;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    metrics::storage::{self as storage_metrics, Rejection},
    secret_manager::{SecretManager, SecretManagerError},
};

pub use alloy::primitives::Address;
pub use oprf_store::{DekWrapper, EnvelopeError, format::StorageFormat};

/// How long a failed on-demand load of a data key is remembered.
///
/// Within this window, reads of rows under that data key fail without calling the database or
/// the KMS again, so an unloadable key cannot turn every request into a KMS call.
const FAILED_LOAD_RETENTION: Duration = Duration::from_secs(30);

/// The storage configuration of the node: which storage formats it reads and what it needs to
/// read `envelopeV1` rows.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct NodeStorageConfig {
    /// The storage formats the node reads shares in.
    ///
    /// Must not be empty. Defaults to `[direct]`.
    #[serde(default = "NodeStorageConfig::default_allowed_storage_formats")]
    pub allowed_storage_formats: Vec<StorageFormat>,
    /// The full ARN of the AWS KMS key that wraps the data keys.
    ///
    /// Required if `envelopeV1` is allowed. Aliases are not accepted.
    #[serde(default)]
    pub kms_key_arn: Option<String>,
    /// Optional custom endpoint for AWS KMS (e.g. for local testing).
    #[serde(default)]
    pub kms_endpoint: Option<String>,
    /// The chain id of the chain the `OprfKeyRegistry` contract lives on.
    ///
    /// Required if `envelopeV1` is allowed; bound into the associated data of every share.
    #[serde(default)]
    pub chain_id: Option<u64>,
    /// The address of the `OprfKeyRegistry` contract.
    ///
    /// Required if `envelopeV1` is allowed; bound into the associated data of every share.
    #[serde(default)]
    pub oprf_key_registry_contract: Option<Address>,
}

impl NodeStorageConfig {
    /// Default allowed storage formats (`[direct]`).
    fn default_allowed_storage_formats() -> Vec<StorageFormat> {
        vec![StorageFormat::Direct]
    }

    /// A configuration that reads `direct` rows only and never touches KMS.
    #[must_use]
    pub fn direct_only() -> Self {
        Self {
            allowed_storage_formats: Self::default_allowed_storage_formats(),
            kms_key_arn: None,
            kms_endpoint: None,
            chain_id: None,
            oprf_key_registry_contract: None,
        }
    }

    /// Whether `envelopeV1` rows may be read.
    fn allows_envelope(&self) -> bool {
        self.allowed_storage_formats
            .contains(&StorageFormat::EnvelopeV1)
    }

    /// Validates the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error naming the offending field if `allowed_storage_formats` is empty, or if
    /// `envelopeV1` is allowed but `kms_key_arn`, `chain_id` or `oprf_key_registry_contract` is
    /// missing or `kms_key_arn` is not a full key ARN.
    pub fn validate(&self) -> eyre::Result<()> {
        if self.allowed_storage_formats.is_empty() {
            bail!("allowed_storage_formats must not be empty");
        }
        if self.allows_envelope() {
            let Some(arn) = &self.kms_key_arn else {
                bail!("kms_key_arn is required when envelopeV1 is an allowed storage format");
            };
            if !(arn.starts_with("arn:") && arn.contains(":key/")) {
                bail!(
                    "kms_key_arn must be the full key ARN (`arn:...:key/...`), not an alias or alias ARN"
                );
            }
            if self.chain_id.is_none() {
                bail!("chain_id is required when envelopeV1 is an allowed storage format");
            }
            if self.oprf_key_registry_contract.is_none() {
                bail!(
                    "oprf_key_registry_contract is required when envelopeV1 is an allowed storage format"
                );
            }
        }
        Ok(())
    }
}

/// A failed on-demand load of a data key.
enum FailedLoad {
    /// The `data_keys` table has no row for the key.
    Missing,
    /// Loading or unwrapping the key failed with this message.
    Failed(String),
}

impl FailedLoad {
    fn to_error(&self, data_key_id: Uuid) -> SecretManagerError {
        match self {
            Self::Missing => {
                SecretManagerError::StorageFormat(EnvelopeError::UnknownDataKey(data_key_id))
            }
            Self::Failed(message) => SecretManagerError::Internal(eyre::eyre!(
                "loading data key {data_key_id} failed recently: {message}"
            )),
        }
    }
}

/// The postgres secret manager wrapping a `PgPool`.
pub struct PostgresSecretManager {
    pool: PgPool,
    max_retries: NonZeroUsize,
    retry_delay: Duration,
    /// The read-only storage policy.
    crypto: StorageCrypto,
    /// Unwraps data keys; set exactly if `envelopeV1` is allowed.
    wrapper: Option<Arc<dyn DekWrapper>>,
    /// Recently failed on-demand loads of data keys, by data key id.
    ///
    /// Ids come from the `data_key_id` column of `shares`, which has a foreign key to
    /// `data_keys`, so the map holds at most one entry per stored data key; a successful load
    /// removes the entry.
    failed_loads: Mutex<HashMap<Uuid, (Instant, FailedLoad)>>,
    /// How long a failed load is remembered; [`FAILED_LOAD_RETENTION`] outside of tests.
    failed_load_retention: Duration,
}

impl std::fmt::Debug for PostgresSecretManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresSecretManager")
            .field("pool", &self.pool)
            .field("max_retries", &self.max_retries)
            .field("retry_delay", &self.retry_delay)
            .field("crypto", &self.crypto)
            .field("kms_key_arn", &self.wrapper.as_ref().map(|w| w.key_arn()))
            .finish_non_exhaustive()
    }
}

impl PostgresSecretManager {
    /// Initializes the `PostgresSecretManager`.
    ///
    /// Validates `storage`, then, only if `envelopeV1` is allowed, creates an AWS KMS wrapper
    /// for `storage.kms_key_arn` (with `storage.kms_endpoint`) and continues as
    /// [`PostgresSecretManager::init_with_wrapper`]. A node that only allows `direct` never
    /// touches AWS.
    ///
    /// # Errors
    /// See [`PostgresSecretManager::init_with_wrapper`].
    #[instrument(level = "debug", skip_all)]
    pub async fn init(config: &PostgresConfig, storage: &NodeStorageConfig) -> eyre::Result<Self> {
        storage
            .validate()
            .context("invalid storage configuration")?;
        let wrapper: Option<Arc<dyn DekWrapper>> = match &storage.kms_key_arn {
            Some(key_arn) if storage.allows_envelope() => {
                tracing::info!("using KMS key {key_arn} to unwrap data keys");
                let wrapper =
                    oprf_store::AwsKmsWrapper::new(key_arn.clone(), storage.kms_endpoint.clone())
                        .await;
                Some(Arc::new(wrapper))
            }
            _ => None,
        };
        Self::init_with_wrapper(config, storage, wrapper).await
    }

    /// Initializes the `PostgresSecretManager` with the given data key wrapper.
    ///
    /// Connects to the Postgres database using the provided configuration. This version does **not** run migrations;
    /// it assumes the database is already set up.
    ///
    /// Stores the max retries and retry delay from the configuration for
    /// use in future database operations.
    ///
    /// If `envelopeV1` is allowed, loads the party id and threshold from `node_information` and
    /// every data key, unwrapped with `wrapper`. `storage.kms_key_arn` and
    /// `storage.kms_endpoint` are not used here; `wrapper` decides which KMS key is used.
    /// Otherwise neither `node_information` nor the KMS is touched and `wrapper` is ignored.
    ///
    /// # Errors
    /// Returns an error if `storage` is invalid or the connection to the database fails, and,
    /// if `envelopeV1` is allowed, if `wrapper` is `None`, `node_information` is missing, or a
    /// data key cannot be loaded (e.g. the KMS call fails or the key was wrapped under another
    /// KMS key).
    #[instrument(level = "debug", skip_all)]
    pub async fn init_with_wrapper(
        config: &PostgresConfig,
        storage: &NodeStorageConfig,
        wrapper: Option<Arc<dyn DekWrapper>>,
    ) -> eyre::Result<Self> {
        storage
            .validate()
            .context("invalid storage configuration")?;
        tracing::debug!("init PgPool with schema: {}", config.schema);
        let pool = nodes_common::postgres::pg_pool_with_schema(config, CreateSchema::No)
            .await
            .context("while connecting to postgres DB")?;
        // we don't run migrations, we just read
        // TODO do we need to check version of the DB to fast crash if migrations don't match?
        let mut secret_manager = Self {
            pool,
            max_retries: config.max_retries,
            retry_delay: config.retry_delay,
            // The associated data is only used for `envelopeV1`, never for `direct`, so this
            // placeholder context is never bound into anything.
            crypto: StorageCrypto::new(
                &[StorageFormat::Direct],
                AadContext {
                    chain_id: 0,
                    registry: Address::ZERO,
                    party_id: PartyId(0),
                    threshold: NonZeroU16::MIN,
                },
                vec![],
            ),
            wrapper: None,
            failed_loads: Mutex::new(HashMap::new()),
            failed_load_retention: FAILED_LOAD_RETENTION,
        };
        if storage.allows_envelope() {
            let wrapper = wrapper.ok_or_else(|| {
                eyre::eyre!(
                    "envelopeV1 is an allowed storage format, but no data key wrapper (KMS key) is given"
                )
            })?;
            let (Some(chain_id), Some(registry)) =
                (storage.chain_id, storage.oprf_key_registry_contract)
            else {
                bail!("chain_id and oprf_key_registry_contract are required for envelopeV1");
            };
            let node_information = secret_manager.load_node_information().await?;
            let ctx = AadContext {
                chain_id,
                registry,
                party_id: node_information.party_id(),
                threshold: node_information.threshold(),
            };
            let deks = data_keys::load_all(&secret_manager.pool, wrapper.as_ref())
                .await
                .context("while loading the data keys")?;
            tracing::info!(
                allowed = ?storage.allowed_storage_formats,
                data_keys = deks.len(),
                "loaded data keys"
            );
            secret_manager.crypto = StorageCrypto::new(&storage.allowed_storage_formats, ctx, deks);
            secret_manager.wrapper = Some(wrapper);
        }
        Ok(secret_manager)
    }

    /// Shortens the window in which failed data key loads are remembered.
    #[cfg(test)]
    pub(crate) fn set_failed_load_retention(&mut self, retention: Duration) {
        self.failed_load_retention = retention;
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

    /// Loads the data key `data_key_id` into the storage policy.
    ///
    /// A failed load is remembered for the retention window; within it the remembered error is
    /// returned without calling the database or the KMS. Not retried.
    async fn load_data_key(&self, data_key_id: Uuid) -> Result<(), SecretManagerError> {
        if let Some((failed_at, failure)) = self.failed_loads.lock().get(&data_key_id)
            && failed_at.elapsed() < self.failed_load_retention
        {
            return Err(failure.to_error(data_key_id));
        }
        let wrapper = self
            .wrapper
            .as_deref()
            .ok_or_else(|| eyre::eyre!("no data key wrapper configured"))?;
        match data_keys::load_one(&self.pool, wrapper, data_key_id).await {
            Ok(Some(dek)) => {
                self.crypto.insert_dek(dek);
                self.failed_loads.lock().remove(&data_key_id);
                tracing::info!(%data_key_id, "loaded data key");
                Ok(())
            }
            Ok(None) => {
                tracing::error!(%data_key_id, "data key does not exist");
                self.remember_failure(data_key_id, FailedLoad::Missing);
                Err(FailedLoad::Missing.to_error(data_key_id))
            }
            Err(err) => {
                tracing::error!(%data_key_id, %err, "loading data key failed");
                self.remember_failure(data_key_id, FailedLoad::Failed(err.to_string()));
                Err(SecretManagerError::Internal(
                    eyre::Report::new(err)
                        .wrap_err(format!("while loading data key {data_key_id}")),
                ))
            }
        }
    }

    fn remember_failure(&self, data_key_id: Uuid, failure: FailedLoad) {
        self.failed_loads
            .lock()
            .insert(data_key_id, (Instant::now(), failure));
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
