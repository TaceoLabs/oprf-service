//! Configuration types and CLI/environment parsing for a TACEO:Oprf node.
//!
//! Concrete implementations may have a more detailed config and can use the exposed [`OprfNodeConfig`] and flatten it with `#[clap(flatten)]`.
//!
//! Additionally this module defines the [`Environment`] to assert dev-only code.

use std::time::Duration;

use alloy::primitives::Address;
use clap::{Parser, ValueEnum};
use secrecy::SecretString;
use semver::VersionReq;

/// The environment the service is running in.
///
/// Main usage for the `Environment` is to call
/// [`Environment::assert_is_dev`]. Services that are intended
/// for `dev` only (like local secret-manager,...)
/// shall assert that they are called from the `dev` environment.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Environment {
    /// Production environment.
    Prod,
    /// Development environment.
    Dev,
}

impl Environment {
    /// Asserts that `Environment` is `dev`. Panics if not the case.
    pub fn assert_is_dev(&self) {
        assert!(matches!(self, Environment::Dev), "Is not dev environment")
    }
}

/// The configuration for TACEO:Oprf core functionality.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct OprfNodeConfig {
    /// The environment of OPRF-service (either `prod` or `dev`).
    #[clap(long, env = "OPRF_NODE_ENVIRONMENT", default_value = "prod")]
    pub environment: Environment,

    /// Max message size the websocket connection accepts.
    ///
    /// Default value: 8 kilobytes
    #[clap(long, env = "OPRF_NODE_MAX_MESSAGE_SIZE", default_value = "8192")]
    pub ws_max_message_size: usize,

    /// Max time a created session is valid.
    ///
    /// This interval specifies how long a websocket connection is kept alive after a user initiates a session.
    #[clap(
        long,
        env = "OPRF_NODE_SESSION_LIFETIME",
        default_value="5min",
        value_parser = humantime::parse_duration
    )]
    pub session_lifetime: Duration,

    /// The Address of the OprfKeyRegistry contract.
    #[clap(long, env = "OPRF_NODE_OPRF_KEY_REGISTRY_CONTRACT")]
    pub oprf_key_registry_contract: Address,

    /// The websocket rpc url of the chain
    #[clap(
        long,
        env = "OPRF_NODE_CHAIN_WS_RPC_URL",
        default_value = "ws://127.0.0.1:8545"
    )]
    pub chain_ws_rpc_url: SecretString,

    /// Prefix for secret name to store rp secrets in secret-manager.
    /// The implementation will call `format!("{rp_secret_id_prefix}/{rp_id}")`
    #[clap(long, env = "OPRF_NODE_RP_SECRET_ID_PREFIX", default_value = "oprf/rp")]
    pub rp_secret_id_prefix: String,

    /// The wallet address
    #[clap(long, env = "OPRF_NODE_WALLET_ADDRESS")]
    pub wallet_address: Address,

    /// Max time to wait for oprf key material secret retrieval from secret manager during key-event processing.
    #[clap(
        long,
        env = "OPRF_NODE_GET_OPRF_KEY_MATERIAL_TIMEOUT",
        default_value="5min",
        value_parser = humantime::parse_duration
    )]
    pub get_oprf_key_material_timeout: Duration,

    /// The block number to start listening for events from the OprfKeyRegistry contract.
    /// If not set, will start from the latest block.
    #[clap(long, env = "OPRF_NODE_START_BLOCK")]
    pub start_block: Option<u64>,

    /// Accepted SemVer versions of clients.
    #[clap(long, env = "OPRF_NODE_ACCEPTED_VERSIONS", value_parser=VersionReq::parse)]
    pub version_req: VersionReq,
}
