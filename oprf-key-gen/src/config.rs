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
//! | `i_am_alive_interval`                    | 60 s        |

use std::num::NonZeroU16;
use std::{path::PathBuf, time::Duration};

use alloy::primitives::Address;
use nodes_common::web3::HttpRpcProviderConfig;
use nodes_common::web3::event_stream::EventStreamConfig;
use nodes_common::{
    Environment,
    web3::{self},
};
use reqwest::Url;
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
    pub ws_rpc_url: Url,

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

    /// Interval in which we emit "I am alive" metric.
    ///
    /// Defaults to `60 s`.
    #[serde(default = "OprfKeyGenServiceConfig::default_i_am_alive_interval")]
    #[serde(with = "humantime_serde")]
    pub i_am_alive_interval: Duration,
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
    pub ws_rpc_url: Url,
}

impl OprfKeyGenServiceConfig {
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

    /// Default I-am-alive interval (`60 s`).
    fn default_i_am_alive_interval() -> Duration {
        Duration::from_mins(1)
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
            i_am_alive_interval: Self::default_i_am_alive_interval(),
            max_tries_fetching_receipt: Self::default_max_tries_fetching_receipt(),
            sleep_between_get_receipt: Self::default_sleep_between_get_receipt(),
            event_stream_config: EventStreamConfig::default(),
        }
    }
}
