//! Configuration types for a TACEO:OPRF node.
//!
//! This module provides [`OprfNodeServiceConfig`], which contains the
//! arguments required to run a TACEO:OPRF node.
//!
//! The struct supports:
//! - Required fields: `environment`, `oprf_key_registry_contract`,
//!   `chain_ws_rpc_url`, and `version_req`.
//! - Optional fields with sensible defaults (see below).
//! - Serde deserialization (with [`humantime_serde`] for durations).
//!
//! # Defaults
//!
//! | Field                            | Default    |
//! |----------------------------------|------------|
//! | `ws_max_message_size`            | 1024 bytes |
//! | `session_lifetime`               | 30 s       |
//! | `reload_key_material_interval`   | 24 h       |
//! | `get_oprf_key_material_timeout`  | 10 min     |
//! | `i_am_alive_interval`            | 60 s       |

use std::time::Duration;

use alloy::primitives::Address;
use nodes_common::Environment;
use secrecy::SecretString;
use semver::VersionReq;
use serde::{
    Deserialize,
    de::{self},
};

/// The configuration for TACEO:OPRF core functionality.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct OprfNodeServiceConfig {
    /// The environment of the OPRF-node.
    pub environment: Environment,
    /// The Address of the `OprfKeyRegistry` contract.
    pub oprf_key_registry_contract: Address,
    /// The websocket rpc url of the chain
    pub chain_ws_rpc_url: SecretString,
    /// Accepted `SemVer` versions of clients.
    #[serde(deserialize_with = "deserialize_version_req")]
    pub version_req: VersionReq,

    /// Max message size the websocket connection accepts.
    ///
    /// Defaults to `1024`.
    #[serde(default = "OprfNodeServiceConfig::default_ws_max_message_size")]
    pub ws_max_message_size: usize,
    /// Max time a created session is valid.
    ///
    /// This interval specifies how long a websocket connection is kept alive after a user initiates a session.
    ///
    /// Defaults to `10 s`.
    #[serde(default = "OprfNodeServiceConfig::default_session_lifetime")]
    #[serde(with = "humantime_serde")]
    pub session_lifetime: Duration,
    /// Interval for which the node reloads all oprf-secrets from the secret-manager. Can be a rather long and only acts as fail-safe.
    ///
    /// Defaults to `24 h`.
    #[serde(default = "OprfNodeServiceConfig::default_reload_key_material_interval")]
    #[serde(with = "humantime_serde")]
    pub reload_key_material_interval: Duration,
    /// Max time to wait for oprf key material secret retrieval from secret manager during key-event processing.
    ///
    /// Defaults to `10 min`.
    #[serde(default = "OprfNodeServiceConfig::default_get_oprf_key_material_timeout")]
    #[serde(with = "humantime_serde")]
    pub get_oprf_key_material_timeout: Duration,
    /// The block number to start listening for events from the `OprfKeyRegistry` contract.
    /// If not set, will start from the latest block.
    pub start_block: Option<u64>,
    /// Interval in which we emit "I am alive" metric.
    ///
    /// Defaults to `60 s`.
    #[serde(default = "OprfNodeServiceConfig::default_i_am_alive_interval")]
    #[serde(with = "humantime_serde")]
    pub i_am_alive_interval: Duration,
}

fn deserialize_version_req<'de, D>(deserializer: D) -> Result<VersionReq, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    VersionReq::parse(&s).map_err(de::Error::custom)
}

impl OprfNodeServiceConfig {
    /// Default max message size (`1024`).
    fn default_ws_max_message_size() -> usize {
        1024
    }

    /// Default session lifetime (`30 s`).
    fn default_session_lifetime() -> Duration {
        Duration::from_secs(30)
    }

    /// Default reload key material interval (`24 h`).
    fn default_reload_key_material_interval() -> Duration {
        Duration::from_secs(24 * 60 * 60)
    }

    /// Default get oprf key material timeout (`10 min`).
    fn default_get_oprf_key_material_timeout() -> Duration {
        Duration::from_secs(10 * 60)
    }

    /// Default I-am-alive interval (`60 s`).
    fn default_i_am_alive_interval() -> Duration {
        Duration::from_secs(60)
    }

    /// Construct with all default values except required fields.
    #[must_use]
    pub fn with_default_values(
        environment: Environment,
        oprf_key_registry_contract: Address,
        chain_ws_rpc_url: SecretString,
        version_req: VersionReq,
    ) -> Self {
        Self {
            environment,
            oprf_key_registry_contract,
            chain_ws_rpc_url,
            version_req,
            ws_max_message_size: Self::default_ws_max_message_size(),
            session_lifetime: Self::default_session_lifetime(),
            reload_key_material_interval: Self::default_reload_key_material_interval(),
            get_oprf_key_material_timeout: Self::default_get_oprf_key_material_timeout(),
            start_block: None,
            i_am_alive_interval: Self::default_i_am_alive_interval(),
        }
    }
}
