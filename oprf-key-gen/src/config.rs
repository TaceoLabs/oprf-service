//! Configuration types for a TACEO:OPRF key-gen instance.
//!
//! This module provides [`OprfKeyGenServiceConfig`], which contains the
//! arguments required to run a TACEO:OPRF key-gen instance.
//!
//! The struct supports:
//! - Required fields: `environment`, `oprf_key_registry_contract`,
//!   `zkey_path`, and `witness_graph_path`.
//! - Optional fields with sensible defaults (see below).
//! - Serde deserialization (with [`jiff`]'s friendly duration format for durations).
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
//!
//! How secrets are stored is configured separately by [`StorageConfig`].

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
use oprf_store::StorageReadConfig;
use oprf_store::format::StorageFormat;
pub use oprf_store::{KmsConfig, WrappingKeyConfig};
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
    #[serde(with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required")]
    pub rpc_http_timeout: Duration,

    /// Max time we wait for a submitted transaction receipt to reach the required
    /// number of confirmations before treating it as failed.
    ///
    /// Defaults to `300 s`.
    #[serde(default = "OprfKeyGenServiceConfig::default_max_wait_time_transaction_confirmation")]
    #[serde(with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required")]
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
    #[serde(with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required")]
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
    #[serde(with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required")]
    pub sleep_between_simulation: Duration,

    /// Interval in which we persist a [`ChainCursor`](nodes_common::web3::event_stream::ChainCursor) checkpoint.
    ///
    /// The implementation will fetch the current block number, then sleep for this configured period, and then call [`ChainCursorStorage::store_chain_cursor`](crate::event_cursor_store::ChainCursorStorage::store_chain_cursor) with the fetched block number. This should prevent very large backfills in case of idle key-gens.
    ///
    /// This should not be smaller than 12 hours. The implementation expect that the block fetched in this interval is for sure already handled. Setting this to a small value (like 5 seconds) might result in loss of events.
    ///
    /// Defaults to `24h`.
    #[serde(default = "OprfKeyGenServiceConfig::default_cursor_checkpoint_interval")]
    #[serde(with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required")]
    pub cursor_checkpoint_interval: Duration,

    /// If set, the binary will backfill from this block number inclusively.
    ///
    /// Ignored if the chain cursor service loads a cursor at or after this block.
    #[serde(default)]
    pub explicit_backfill_block: Option<NonZeroU64>,
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
        }
    }
}

/// How key-gen stores secret database columns.
///
/// Deserialized from the fields of [`StorageReadConfig`] and `storage_write_format` (default
/// `direct`), the format written, which must be one of the allowed formats.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawStorageConfig")]
#[allow(
    clippy::exhaustive_enums,
    reason = "consumers must handle every way secrets are stored"
)]
pub enum StorageConfig {
    /// Reads and writes `direct` only; no wrapping key is used.
    #[default]
    Direct,
    /// Reads `envelopeV1`; what else is read and what is written depends on `mode`.
    Envelope {
        /// The formats read and written.
        mode: EnvelopeMode,
        /// The key wrapping the data keys.
        key: WrappingKeyConfig,
    },
}

/// The formats key-gen reads and writes when `envelopeV1` is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::exhaustive_enums, reason = "consumers must handle every mode")]
pub enum EnvelopeMode {
    /// Reads `direct` and `envelopeV1`, writes `direct`.
    WriteDirect,
    /// Reads `direct` and `envelopeV1`, writes `envelopeV1`.
    WriteEnvelope,
    /// Reads and writes `envelopeV1` only.
    EnvelopeOnly,
}

impl EnvelopeMode {
    /// The formats accepted when reading.
    #[must_use]
    pub fn allowed(self) -> &'static [StorageFormat] {
        match self {
            Self::WriteDirect | Self::WriteEnvelope => {
                &[StorageFormat::Direct, StorageFormat::EnvelopeV1]
            }
            Self::EnvelopeOnly => &[StorageFormat::EnvelopeV1],
        }
    }

    /// The format written.
    #[must_use]
    pub fn write(self) -> StorageFormat {
        match self {
            Self::WriteDirect => StorageFormat::Direct,
            Self::WriteEnvelope | Self::EnvelopeOnly => StorageFormat::EnvelopeV1,
        }
    }
}

/// The fields [`StorageConfig`] is deserialized from.
#[derive(Deserialize)]
struct RawStorageConfig {
    #[serde(flatten)]
    read: StorageReadConfig,
    #[serde(default = "default_storage_write_format")]
    storage_write_format: StorageFormat,
}

fn default_storage_write_format() -> StorageFormat {
    StorageFormat::Direct
}

impl TryFrom<RawStorageConfig> for StorageConfig {
    type Error = eyre::Report;

    fn try_from(raw: RawStorageConfig) -> eyre::Result<Self> {
        let write = raw.storage_write_format;
        let (mode, key) = match (raw.read, write) {
            (StorageReadConfig::Direct, StorageFormat::Direct) => return Ok(Self::Direct),
            (
                StorageReadConfig::Envelope {
                    read_direct: true,
                    key,
                },
                StorageFormat::Direct,
            ) => (EnvelopeMode::WriteDirect, key),
            (StorageReadConfig::Envelope { read_direct, key }, StorageFormat::EnvelopeV1) => {
                let mode = if read_direct {
                    EnvelopeMode::WriteEnvelope
                } else {
                    EnvelopeMode::EnvelopeOnly
                };
                (mode, key)
            }
            _ => {
                bail!("storage_write_format {write:?} must be contained in allowed_storage_formats")
            }
        };
        Ok(Self::Envelope { mode, key })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const KEY_ARN: &str =
        "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    fn parse(value: serde_json::Value) -> Result<StorageConfig, String> {
        serde_json::from_value(value).map_err(|err| err.to_string())
    }

    const MASTER_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn envelope(mode: EnvelopeMode) -> StorageConfig {
        StorageConfig::Envelope {
            mode,
            key: WrappingKeyConfig::parse(Some(KEY_ARN.to_owned()), None, None).expect("valid ARN"),
        }
    }

    #[test]
    fn parses_every_valid_combination() {
        assert_eq!(parse(json!({})), Ok(StorageConfig::Direct));
        // A wrapping key that is not needed is ignored.
        assert_eq!(
            parse(json!({ "kms_key_arn": KEY_ARN })),
            Ok(StorageConfig::Direct)
        );
        assert_eq!(
            parse(json!({ "storage_master_key": MASTER_KEY })),
            Ok(StorageConfig::Direct)
        );
        for (allowed, write, mode) in [
            (
                json!(["direct", "envelopeV1"]),
                "direct",
                EnvelopeMode::WriteDirect,
            ),
            (
                json!(["direct", "envelopeV1"]),
                "envelopeV1",
                EnvelopeMode::WriteEnvelope,
            ),
            (
                json!(["envelopeV1"]),
                "envelopeV1",
                EnvelopeMode::EnvelopeOnly,
            ),
        ] {
            let parsed = parse(json!({
                "allowed_storage_formats": allowed,
                "storage_write_format": write,
                "kms_key_arn": KEY_ARN,
            }));
            assert_eq!(parsed, Ok(envelope(mode)));
            assert_eq!(mode.write().as_str(), write);
        }
    }

    #[test]
    fn rejects_invalid_combinations() {
        let both = json!(["direct", "envelopeV1"]);
        for (config, field) in [
            (
                json!({ "allowed_storage_formats": [] }),
                "allowed_storage_formats",
            ),
            (
                json!({ "storage_write_format": "envelopeV1" }),
                "storage_write_format",
            ),
            (
                json!({ "allowed_storage_formats": ["envelopeV1"], "kms_key_arn": KEY_ARN }),
                "storage_write_format",
            ),
            (
                json!({ "allowed_storage_formats": both }),
                "kms_key_arn or storage_master_key",
            ),
            (
                json!({
                    "allowed_storage_formats": both,
                    "kms_key_arn": KEY_ARN,
                    "storage_master_key": MASTER_KEY,
                }),
                "mutually exclusive",
            ),
            (
                json!({ "allowed_storage_formats": both, "kms_key_arn": "alias/oprf" }),
                "full key ARN",
            ),
            (
                json!({
                    "allowed_storage_formats": both,
                    "kms_key_arn": "arn:aws:kms:eu-west-1:111122223333:alias/oprf",
                }),
                "kms_key_arn",
            ),
        ] {
            let err = parse(config.clone()).expect_err("invalid config");
            assert!(
                err.contains(field),
                "{config}: the error must name {field}: {err}"
            );
        }
    }

    #[test]
    fn accepts_master_key_instead_of_kms_key_arn() {
        let parsed = parse(json!({
            "allowed_storage_formats": ["envelopeV1"],
            "storage_write_format": "envelopeV1",
            "storage_master_key": MASTER_KEY,
        }))
        .expect("master key is enough");
        let StorageConfig::Envelope { mode, key } = parsed else {
            panic!("expected an envelope config, got {parsed:?}");
        };
        assert_eq!(mode, EnvelopeMode::EnvelopeOnly);
        assert!(matches!(key, WrappingKeyConfig::Local(_)), "{key:?}");
    }

    #[test]
    fn rejects_invalid_master_key_without_echoing_it() {
        for bad in ["abcd", &MASTER_KEY.replace('0', "g"), &"11".repeat(32)] {
            let err = parse(json!({
                "allowed_storage_formats": ["direct", "envelopeV1"],
                "storage_master_key": bad,
            }))
            .expect_err("rejected");
            assert!(err.contains("storage_master_key"), "{err}");
            assert!(!err.contains(bad), "the error must not contain the key");
        }
    }
}
