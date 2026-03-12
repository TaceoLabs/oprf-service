//! Configuration types for a TACEO:OPRF key-gen instance.
//!
//! This module provides [`OprfKeyGenServiceConfig`], which contains the
//! arguments required to run a TACEO:OPRF key-gen instance.
//!
//! The struct supports:
//! - Required fields: `environment`, `oprf_key_registry_contract`,
//!   `chain_ws_rpc_url`, `zkey_path`, and `witness_graph_path`.
//! - Optional fields with sensible defaults (see below).
//! - Serde deserialization (with [`humantime_serde`] for durations).
//!
//! # Defaults
//!
//! | Field                                    | Default     |
//! |------------------------------------------|-------------|
//! | `max_wait_time_transaction_confirmation` | 300 s       |
//! | `max_gas_per_transaction`                | 8 000 000   |
//! | `confirmations_for_transaction`          | 5           |
//! | `i_am_alive_interval`                    | 60 s        |

use std::{path::PathBuf, time::Duration};

use alloy::primitives::Address;
use nodes_common::{
    Environment,
    web3::{self, RpcProviderConfig},
};
use reqwest::Url;
use serde::Deserialize;

/// The configuration for TACEO:OPRF key-gen functionality.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct OprfKeyGenServiceConfig {
    /// The environment of OPRF key-gen.
    pub environment: Environment,

    /// The Address of the OprfKeyRegistry contract.
    pub oprf_key_registry_contract: Address,

    /// The location of the zkey for the key-gen proof in round 2 of KeyGen
    pub zkey_path: PathBuf,

    /// The location of the graph binary for the key-gen witness extension
    pub witness_graph_path: PathBuf,

    /// The blockchain RPC config
    #[serde(rename = "rpc")]
    pub rpc_provider_config: web3::RpcProviderConfig,

    /// Max time we wait for a transaction confirmation event until we assume the transaction didn't go through.
    ///
    /// We need this because RPCs are not very reliable, so we need to verify whether a transaction did get through or not.
    ///
    /// Defaults to `300 s`.
    #[serde(default = "OprfKeyGenServiceConfig::default_max_wait_time_transaction_confirmation")]
    #[serde(with = "humantime_serde")]
    pub max_wait_time_transaction_confirmation: Duration,

    /// The block number to start listening for events from the OprfKeyRegistry contract.
    /// If not set, will start from the latest block.
    pub start_block: Option<u64>,

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

    /// Interval in which we emit "I am alive" metric.
    ///
    /// Defaults to `60 s`.
    #[serde(default = "OprfKeyGenServiceConfig::default_i_am_alive_interval")]
    #[serde(with = "humantime_serde")]
    pub i_am_alive_interval: Duration,
}

impl OprfKeyGenServiceConfig {
    /// Default max wait time for transaction confirmation (`300 s`).
    fn default_max_wait_time_transaction_confirmation() -> Duration {
        Duration::from_secs(300) // 5min
    }

    /// Default max gas per transaction (`8_000_000`).
    fn default_max_gas_per_transaction() -> u64 {
        8_000_000
    }

    /// Default confirmations for transaction (`5`).
    fn default_confirmations_for_transaction() -> u64 {
        5
    }

    /// Default I-am-alive interval (`60 s`).
    fn default_i_am_alive_interval() -> Duration {
        Duration::from_secs(60)
    }

    /// Construct with all default values except required fields.
    pub fn with_default_values(
        environment: Environment,
        oprf_key_registry_contract: Address,
        zkey_path: PathBuf,
        witness_graph_path: PathBuf,
        http_urls: Vec<Url>,
        ws_url: Url,
    ) -> Self {
        Self {
            environment,
            oprf_key_registry_contract,
            zkey_path,
            witness_graph_path,
            rpc_provider_config: RpcProviderConfig::with_default_values(http_urls, ws_url),
            max_wait_time_transaction_confirmation:
                Self::default_max_wait_time_transaction_confirmation(),
            start_block: None,
            max_gas_per_transaction: Self::default_max_gas_per_transaction(),
            confirmations_for_transaction: Self::default_confirmations_for_transaction(),
            i_am_alive_interval: Self::default_i_am_alive_interval(),
        }
    }
}
