//! Configuration types for a TACEO:OPRF node.
//!
//! This module provides [`OprfNodeServiceConfig`], which contains the
//! arguments required to run a TACEO:OPRF node.
//!
//! The struct supports:
//! - Required fields: `environment` and `version_req`.
//! - Optional fields with sensible defaults (see below).
//! - Serde deserialization (with [`humantime_serde`] for durations).
//!
//! # Defaults
//!
//! | Field                            | Default    |
//! |----------------------------------|------------|
//! | `ws_max_message_size`            | 1024 bytes |
//! | `session_lifetime`               | 30 s       |
//! | `i_am_alive_interval`            | 60 s       |
//! | `store_max_capacity`             | 10_000     |
//! | `store_ttl`                      | 1 day      |
//! | `store_tti`                      | 1 h        |

use std::time::Duration;

use nodes_common::Environment;
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
    /// This interval specifies how long a websocket connection is kept alive after a user initiates a session. This time starts ticking after the peers finish the web-socket upgrade protocol.
    ///
    /// Defaults to `30 s`.
    #[serde(default = "OprfNodeServiceConfig::default_session_lifetime")]
    #[serde(with = "humantime_serde")]
    pub session_lifetime: Duration,

    /// Max time for HTTP requests.
    ///
    /// In contrast to `session_lifetime`, this timeout addresses HTTP requests, e.g. `health`, `info` routes but also the web-socket upgrade requests.
    ///
    /// Defaults to `20 s`.
    #[serde(default = "OprfNodeServiceConfig::default_http_request_timeout")]
    #[serde(with = "humantime_serde")]
    pub http_request_timeout: Duration,

    /// Interval in which we emit "I am alive" metric.
    ///
    /// Defaults to `60 s`.
    #[serde(default = "OprfNodeServiceConfig::default_i_am_alive_interval")]
    #[serde(with = "humantime_serde")]
    pub i_am_alive_interval: Duration,

    /// Max capacity for the key-material store.
    #[serde(default = "OprfNodeServiceConfig::default_store_max_capacity")]
    pub store_max_capacity: u64,

    /// Time-to-live for shares.
    ///
    /// Exceeding this limit will evict share.
    #[serde(default = "OprfNodeServiceConfig::default_store_ttl")]
    #[serde(with = "humantime_serde")]
    pub store_ttl: Duration,

    /// Time-to-idle for shares.
    ///
    /// If share not requested for this time, will be removed from store.
    #[serde(default = "OprfNodeServiceConfig::default_store_tti")]
    #[serde(with = "humantime_serde")]
    pub store_tti: Duration,
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

    /// Default http request timeout (`20 s`).
    fn default_http_request_timeout() -> Duration {
        Duration::from_secs(20)
    }

    /// Default I-am-alive interval (`60 s`).
    fn default_i_am_alive_interval() -> Duration {
        Duration::from_mins(1)
    }

    /// Default max capacity for share cache (`10_000`).
    fn default_store_max_capacity() -> u64 {
        10_000
    }

    /// Default TTL for share cache (`1 day`).
    fn default_store_ttl() -> Duration {
        Duration::from_hours(24)
    }

    /// Default TTI for share cache (`1h`).
    fn default_store_tti() -> Duration {
        Duration::from_hours(1)
    }

    /// Construct with all default values except required fields.
    #[must_use]
    pub fn with_default_values(environment: Environment, version_req: VersionReq) -> Self {
        Self {
            environment,
            version_req,
            ws_max_message_size: Self::default_ws_max_message_size(),
            session_lifetime: Self::default_session_lifetime(),
            http_request_timeout: Self::default_http_request_timeout(),
            i_am_alive_interval: Self::default_i_am_alive_interval(),
            store_max_capacity: Self::default_store_max_capacity(),
            store_ttl: Self::default_store_ttl(),
            store_tti: Self::default_store_tti(),
        }
    }
}
