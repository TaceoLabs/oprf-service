//! Configuration types and CLI/environment parsing for a TACEO:Oprf key-gen instance.
//!
//! Additionally this module defines the [`Environment`] to assert dev-only code.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use alloy::primitives::Address;
use clap::{Parser, ValueEnum};
use secrecy::SecretString;

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
pub struct OprfKeyGenConfig {
    /// The environment of OPRF-service (either `prod` or `dev`).
    #[clap(long, env = "OPRF_NODE_ENVIRONMENT", default_value = "prod")]
    pub environment: Environment,

    /// The bind addr of the AXUM server
    #[clap(long, env = "OPRF_NODE_BIND_ADDR", default_value = "0.0.0.0:5432")]
    pub bind_addr: SocketAddr,

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

    /// Secret Id of the wallet private key.
    #[clap(long, env = "OPRF_NODE_WALLET_PRIVATE_KEY_SECRET_ID")]
    pub wallet_private_key_secret_id: String,

    /// The location of the zkey for the key-gen proof in round 2 of KeyGen
    #[clap(long, env = "OPRF_NODE_KEY_GEN_ZKEY")]
    pub key_gen_zkey_path: PathBuf,

    /// The location of the graph binary for the key-gen witness extension
    #[clap(long, env = "OPRF_NODE_KEY_GEN_GRAPH")]
    pub key_gen_witness_graph_path: PathBuf,

    /// Max wait time the service waits for its workers during shutdown.
    #[clap(
        long,
        env = "OPRF_NODE_MAX_WAIT_TIME_SHUTDOWN",
        default_value = "10s",
        value_parser = humantime::parse_duration

    )]
    pub max_wait_time_shutdown: Duration,

    /// Max cache size for epochs. Only the latest `max_epoch_cache_size` will be stored in the secret-manager!
    #[clap(long, env = "OPRF_NODE_MAX_EPOCH_CACHE_SIZE", default_value = "3")]
    pub max_epoch_cache_size: usize,

    /// Max time we wait for a transaction nonce until we think the transaction didn't went through.
    ///
    /// We need this because RPCs are not very reliable, so we need to verify whether a transaction did get through or not.
    #[clap(long, env = "OPRF_NODE_MAX_WAIT_TIME_TRANSACTION_NONCE", default_value = "5min", value_parser=humantime::parse_duration)]
    pub max_wait_time_transaction_nonce: Duration,

    /// The block number to start listening for events from the OprfKeyRegistry contract.
    /// If not set, will start from the latest block.
    #[clap(long, env = "OPRF_NODE_START_BLOCK")]
    pub start_block: Option<u64>,
}
