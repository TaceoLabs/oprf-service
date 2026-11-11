//! Configuration types for a TACEO:OPRF key-gen instance.
//!
//! This module provides [`OprfKeyGenServiceConfig`], which contains the
//! arguments required to run a TACEO:OPRF key-gen instance.
//!
//! The struct supports:
//! - Required fields: `environment`, `oprf_key_registry_contract`,
//!   `zkey_path`, and `witness_graph_path`.
//! - Optional fields with sensible defaults (see below).
//! - Serde deserialization (with [`humantime_serde`] for durations).
//!
//! HTTP RPC connectivity is configured via `nodes_common::web3::HttpRpcProviderConfig`.
//! The WebSocket URL for event subscriptions is a separate top-level field (`ws_rpc_url`).
//!
//! # Defaults
//!
//! For the backfill defaults, we refer to `nodes_common::web3::event_stream`.
//!
//! | Field                                    | Default     |
//! |------------------------------------------|-------------|
//! | `max_wait_time_transaction_confirmation` | 300 s       |
//! | `max_gas_per_transaction`                | 8 000 000   |
//! | `confirmations_for_transaction`          | 5           |
//! | `max_tries_fetching_receipt`             | 5           |
//! | `sleep_between_get_receipt`              | 5 s         |
//! | `rpc_http_timeout`                       | 10 s        |
//! | `max_tries_simulation`                   | 30          |
//! | `sleep_between_simulation`               | 5 s         |
//! | `cursor_checkpoint_interval`             | 1 day       |
//! | `allowed_storage_formats`                | `[direct]`  |
//! | `storage_write_format`                   | `direct`    |
//! | `kms_key_arn`                            | none        |
//! | `kms_endpoint`                           | none        |

use std::num::{NonZeroU16, NonZeroU64};
use std::{path::PathBuf, time::Duration};

use alloy::primitives::Address;
use eyre::bail;
use nodes_common::web3::HttpRpcProviderConfig;
use nodes_common::web3::event_stream::EventStreamConfig;
use nodes_common::{
    Environment,
    web3::{self},
};
use oprf_store::format::StorageFormat;
use secrecy::SecretString;
use serde::Deserialize;

/// The configuration for TACEO:OPRF key-gen functionality.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct OprfKeyGenServiceConfig {
    /// The environment of OPRF key-gen.
    pub environment: Environment,

    /// Hex-encoded wallet private key (with or without 0x prefix).
    pub wallet_private_key: SecretString,

    /// The Address of the `OprfKeyRegistry` contract.
    pub oprf_key_registry_contract: Address,

    /// The location of the zkey for the key-gen proof in round 2 of `KeyGen`
    pub zkey_path: PathBuf,

    /// The location of the graph binary for the key-gen witness extension
    pub witness_graph_path: PathBuf,

    /// The expected number of peers the contract was configured with
    pub expected_num_peers: NonZeroU16,

    /// The expected threshold the contract was configured with
    pub expected_threshold: NonZeroU16,

    /// The blockchain RPC config
    #[serde(rename = "rpc")]
    pub rpc_provider_config: web3::HttpRpcProviderConfig,

    /// The websocket RPC url used for `eth_subscribe`.
    pub ws_rpc_url: SecretString,

    /// The timeout for HTTP requests to the RPC.
    #[serde(default = "OprfKeyGenServiceConfig::default_rpc_http_timeout")]
    #[serde(with = "humantime_serde")]
    pub rpc_http_timeout: Duration,

    /// Max time we wait for a submitted transaction receipt to reach the required
    /// number of confirmations before treating it as failed.
    ///
    /// Defaults to `300 s`.
    #[serde(default = "OprfKeyGenServiceConfig::default_max_wait_time_transaction_confirmation")]
    #[serde(with = "humantime_serde")]
    pub max_wait_time_transaction_confirmation: Duration,

    /// Additional config for backfill.
    ///
    /// See `nodes-common` for the optional values that might be configured.
    #[serde(default)]
    #[serde(rename = "backfill")]
    pub event_stream_config: EventStreamConfig,

    /// Maximum amount of gas a single transaction is allowed to consume.
    /// This acts as a safety limit to prevent transactions from exceeding expected execution costs. The default value is set to approximately 2× the average gas used by a round-2 transaction, which is currently the most gas-intensive round.
    ///
    /// Defaults to `8_000_000`.
    #[serde(default = "OprfKeyGenServiceConfig::default_max_gas_per_transaction")]
    pub max_gas_per_transaction: u64,

    /// Number of block confirmations required before a transaction is
    /// considered successful.
    ///
    /// Defaults to `5`.
    #[serde(default = "OprfKeyGenServiceConfig::default_confirmations_for_transaction")]
    pub confirmations_for_transaction: u64,

    /// Number of times we try to fetch the receipt after a confirmed transaction with `eth_getTransactionReceipt`.
    ///
    /// Defaults to `5`.
    #[serde(default = "OprfKeyGenServiceConfig::default_max_tries_fetching_receipt")]
    pub max_tries_fetching_receipt: usize,

    /// Time to sleep between `eth_getTransactionReceipt` calls when getting a `NullResponse` on a confirmed transaction.
    ///
    /// Defaults to `5s`.
    #[serde(default = "OprfKeyGenServiceConfig::default_sleep_between_get_receipt")]
    #[serde(with = "humantime_serde")]
    pub sleep_between_get_receipt: Duration,

    /// Number of times we retry a pinned call that fails without revert data.
    ///
    /// Together with `sleep_between_simulation` this bounds how far the RPC pool may lag behind
    /// the endpoint delivering the events. Once exhausted the event watcher restarts and replays
    /// the event from the stored chain cursor.
    ///
    /// Defaults to `30`.
    #[serde(default = "OprfKeyGenServiceConfig::default_max_tries_simulation")]
    pub max_tries_simulation: usize,

    /// Time to sleep between pinned-call retries. Should be in the order of the chain's block
    /// time.
    ///
    /// Defaults to `5s`.
    #[serde(default = "OprfKeyGenServiceConfig::default_sleep_between_simulation")]
    #[serde(with = "humantime_serde")]
    pub sleep_between_simulation: Duration,

    /// Interval in which we persist a [`ChainCursor`](nodes_common::web3::event_stream::ChainCursor) checkpoint.
    ///
    /// The implementation will fetch the current block number, then sleep for this configured period, and then call [`ChainCursorStorage::store_chain_cursor`](crate::event_cursor_store::ChainCursorStorage::store_chain_cursor) with the fetched block number. This should prevent very large backfills in case of idle key-gens.
    ///
    /// This should not be smaller than 12 hours. The implementation expect that the block fetched in this interval is for sure already handled. Setting this to a small value (like 5 seconds) might result in loss of events.
    ///
    /// Defaults to `1 day`.
    #[serde(default = "OprfKeyGenServiceConfig::default_cursor_checkpoint_interval")]
    #[serde(with = "humantime_serde")]
    pub cursor_checkpoint_interval: Duration,

    /// If set, the binary will backfill from this block number inclusively.
    ///
    /// Ignored if the chain cursor service loads a cursor at or after this block.
    #[serde(default)]
    pub explicit_backfill_block: Option<NonZeroU64>,

    /// The storage formats key-gen accepts when reading secret database columns.
    ///
    /// Must not be empty and must contain `storage_write_format`.
    ///
    /// Defaults to `[direct]`.
    #[serde(default = "OprfKeyGenServiceConfig::default_allowed_storage_formats")]
    pub allowed_storage_formats: Vec<StorageFormat>,

    /// The storage format key-gen uses when writing secret database columns.
    ///
    /// Must be contained in `allowed_storage_formats`.
    ///
    /// Defaults to `direct`.
    #[serde(default = "OprfKeyGenServiceConfig::default_storage_write_format")]
    pub storage_write_format: StorageFormat,

    /// The full ARN of the AWS KMS key that wraps the data keys.
    ///
    /// Required if `envelopeV1` is allowed. Aliases are not accepted.
    #[serde(default)]
    pub kms_key_arn: Option<String>,

    /// Optional custom endpoint for AWS KMS (e.g. for local testing).
    #[serde(default)]
    pub kms_endpoint: Option<String>,
}

/// Subset of [`OprfKeyGenServiceConfig`] containing all values that must be
/// explicitly provided by the caller.
///
/// This struct represents the minimal configuration required to start the
/// OPRF key generation service. All fields are mandatory and are typically
/// validated and extracted from the full config before initialization.
#[allow(
    clippy::exhaustive_structs,
    reason = "Having a new mandatory configuration is a breaking change"
)]
pub struct OprfKeyGenServiceConfigMandatoryValues {
    /// Target environment (e.g. dev, staging, production).
    pub environment: Environment,

    /// Address of the `OprfKeyRegistry` contract.
    pub oprf_key_registry_contract: Address,

    /// Hex-encoded private key used to sign transactions.
    ///
    /// Accepts values with or without `0x` prefix.
    pub wallet_private_key: SecretString,

    /// Path to the `.zkey` file used for generating the round-2 proof.
    pub zkey_path: PathBuf,

    /// Path to the witness graph binary used during witness generation.
    pub witness_graph_path: PathBuf,

    /// Expected threshold as defined in the on-chain contract.
    ///
    /// Must match the contract value to ensure protocol correctness.
    pub expected_threshold: NonZeroU16,

    /// Expected total number of peers as defined in the contract.
    ///
    /// Must match the contract value to ensure correct participation.
    pub expected_num_peers: NonZeroU16,

    /// Blockchain RPC configuration used for contract interaction.
    pub rpc_provider_config: HttpRpcProviderConfig,

    /// The websocket RPC url used for `eth_subscribe`.
    pub ws_rpc_url: SecretString,
}

impl OprfKeyGenServiceConfig {
    /// Default timeout for HTTP requests to the RPC: 10 seconds
    fn default_rpc_http_timeout() -> Duration {
        Duration::from_secs(10)
    }

    /// Default max wait time for transaction confirmation (`300 s`).
    fn default_max_wait_time_transaction_confirmation() -> Duration {
        Duration::from_mins(5) // 5min
    }

    /// Default max gas per transaction (`8_000_000`).
    fn default_max_gas_per_transaction() -> u64 {
        8_000_000
    }

    /// Default confirmations for transaction (`5`).
    fn default_confirmations_for_transaction() -> u64 {
        5
    }

    /// Default max tries for fetching receipt after confirmed transaction (`5`).
    fn default_max_tries_fetching_receipt() -> usize {
        5
    }

    /// Default time we sleep between trying to fetch receipt of a confirmed transaction (`5s`).
    fn default_sleep_between_get_receipt() -> Duration {
        Duration::from_secs(5)
    }

    /// Default max tries for a pinned call the RPC could not serve (`30`).
    ///
    /// This allows a lagging HTTP endpoint time to catch up with the event source. Other errors
    /// without revert data use the same bounded retry policy and may exhaust it.
    fn default_max_tries_simulation() -> usize {
        30
    }

    /// Default time we sleep between pinned-call retries (`5s`).
    fn default_sleep_between_simulation() -> Duration {
        Duration::from_secs(5)
    }

    /// Default cursor checkpoint interval (`1 day`).
    fn default_cursor_checkpoint_interval() -> Duration {
        Duration::from_hours(24)
    }

    /// Default allowed storage formats (`[direct]`).
    fn default_allowed_storage_formats() -> Vec<StorageFormat> {
        vec![StorageFormat::Direct]
    }

    /// Default storage write format (`direct`).
    fn default_storage_write_format() -> StorageFormat {
        StorageFormat::Direct
    }

    /// Validates the storage configuration.
    ///
    /// # Errors
    ///
    /// Returns an error naming the offending field if `allowed_storage_formats` is empty, does
    /// not contain `storage_write_format`, or if `envelopeV1` is allowed but `kms_key_arn` or
    /// `rpc.chain_id` is missing or `kms_key_arn` is not a full key ARN.
    pub fn validate_storage(&self) -> eyre::Result<()> {
        if self.allowed_storage_formats.is_empty() {
            bail!("allowed_storage_formats must not be empty");
        }
        if !self
            .allowed_storage_formats
            .contains(&self.storage_write_format)
        {
            bail!(
                "storage_write_format {:?} must be contained in allowed_storage_formats",
                self.storage_write_format
            );
        }
        if self
            .allowed_storage_formats
            .contains(&StorageFormat::EnvelopeV1)
        {
            let Some(arn) = &self.kms_key_arn else {
                bail!("kms_key_arn is required when envelopeV1 is an allowed storage format");
            };
            if !(arn.starts_with("arn:") && arn.contains(":key/")) {
                bail!(
                    "kms_key_arn must be the full key ARN (`arn:...:key/...`), not an alias or alias ARN"
                );
            }
            if self.rpc_provider_config.chain_id.is_none() {
                bail!("rpc.chain_id is required when envelopeV1 is an allowed storage format");
            }
        }
        Ok(())
    }

    /// Construct with all default values except required fields.
    #[must_use]
    pub fn with_default_values(args: OprfKeyGenServiceConfigMandatoryValues) -> Self {
        let OprfKeyGenServiceConfigMandatoryValues {
            environment,
            oprf_key_registry_contract,
            wallet_private_key,
            zkey_path,
            witness_graph_path,
            expected_threshold,
            expected_num_peers,
            rpc_provider_config,
            ws_rpc_url,
        } = args;
        Self {
            environment,
            oprf_key_registry_contract,
            wallet_private_key,
            ws_rpc_url,
            zkey_path,
            witness_graph_path,
            expected_num_peers,
            expected_threshold,
            rpc_provider_config,
            max_wait_time_transaction_confirmation:
                Self::default_max_wait_time_transaction_confirmation(),
            max_gas_per_transaction: Self::default_max_gas_per_transaction(),
            confirmations_for_transaction: Self::default_confirmations_for_transaction(),
            max_tries_fetching_receipt: Self::default_max_tries_fetching_receipt(),
            sleep_between_get_receipt: Self::default_sleep_between_get_receipt(),
            max_tries_simulation: Self::default_max_tries_simulation(),
            sleep_between_simulation: Self::default_sleep_between_simulation(),
            event_stream_config: EventStreamConfig::default(),
            cursor_checkpoint_interval: Self::default_cursor_checkpoint_interval(),
            rpc_http_timeout: Self::default_rpc_http_timeout(),
            explicit_backfill_block: None,
            allowed_storage_formats: Self::default_allowed_storage_formats(),
            storage_write_format: Self::default_storage_write_format(),
            kms_key_arn: None,
            kms_endpoint: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use oprf_store::format::StorageFormat;

    use super::*;

    const KEY_ARN: &str =
        "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    fn config() -> OprfKeyGenServiceConfig {
        OprfKeyGenServiceConfig::with_default_values(OprfKeyGenServiceConfigMandatoryValues {
            environment: Environment::Dev,
            oprf_key_registry_contract: Address::ZERO,
            wallet_private_key: SecretString::from("0x01"),
            zkey_path: PathBuf::from("zkey"),
            witness_graph_path: PathBuf::from("graph"),
            expected_threshold: NonZeroU16::new(2).expect("non-zero"),
            expected_num_peers: NonZeroU16::new(3).expect("non-zero"),
            rpc_provider_config: HttpRpcProviderConfig::with_default_values([
                "http://localhost:8545",
            ])
            .expect("valid url"),
            ws_rpc_url: SecretString::from("ws://localhost:8546"),
        })
    }

    fn envelope_config() -> OprfKeyGenServiceConfig {
        let mut config = config();
        config.allowed_storage_formats = vec![StorageFormat::Direct, StorageFormat::EnvelopeV1];
        config.storage_write_format = StorageFormat::EnvelopeV1;
        config.kms_key_arn = Some(KEY_ARN.to_owned());
        config.rpc_provider_config.chain_id = Some(1);
        config
    }

    fn error_of(config: &OprfKeyGenServiceConfig) -> String {
        config
            .validate_storage()
            .expect_err("config must be rejected")
            .to_string()
    }

    #[test]
    fn rejects_empty_allowed_formats() {
        let mut config = config();
        config.allowed_storage_formats.clear();
        assert!(error_of(&config).contains("allowed_storage_formats"));
    }

    #[test]
    fn rejects_write_format_not_allowed() {
        let mut config = envelope_config();
        config.allowed_storage_formats = vec![StorageFormat::Direct];
        assert!(error_of(&config).contains("storage_write_format"));
    }

    #[test]
    fn rejects_envelope_without_kms_key_arn() {
        let mut config = envelope_config();
        config.kms_key_arn = None;
        assert!(error_of(&config).contains("kms_key_arn"));
    }

    #[test]
    fn rejects_kms_alias_instead_of_key_arn() {
        for alias in [
            "alias/oprf",
            "arn:aws:kms:eu-west-1:111122223333:alias/oprf",
        ] {
            let mut config = envelope_config();
            config.kms_key_arn = Some(alias.to_owned());
            let error = error_of(&config);
            assert!(error.contains("kms_key_arn"), "{alias}: {error}");
            assert!(error.contains("full key ARN"), "{alias}: {error}");
        }
    }

    #[test]
    fn rejects_envelope_without_chain_id() {
        let mut config = envelope_config();
        config.rpc_provider_config.chain_id = None;
        assert!(error_of(&config).contains("chain_id"));
    }

    #[test]
    fn valid_configs_pass() {
        config()
            .validate_storage()
            .expect("the default config is valid");
        envelope_config()
            .validate_storage()
            .expect("envelope config is valid");
    }
}
