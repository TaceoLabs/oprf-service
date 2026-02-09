//! Configuration types and CLI/environment parsing for a TACEO:OPRF key-gen instance.
//!
//! Additionally this module defines the [`Environment`] to assert dev-only code.

use std::{
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};

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

/// The configuration for TACEO:OPRF core functionality.
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

    /// Secret Id of the wallet private key.
    #[clap(long, env = "OPRF_NODE_WALLET_PRIVATE_KEY_SECRET_ID")]
    pub wallet_private_key_secret_id: String,

    /// The connection string for the Postgres DB
    #[clap(long, env = "OPRF_NODE_DB_CONNECTION_STRING")]
    pub db_connection_string: SecretString,

    /// The schema we use for the DB
    #[clap(long, env = "OPRF_NODE_DB_SCHEMA")]
    pub db_schema: String,

    /// The max connections for the Postgres pool
    #[clap(long, env = "OPRF_KEY_GEN_MAX_DB_CONNECTION", default_value = "4")]
    pub max_db_connections: NonZeroU32,

    /// The max time we wait for a DB connection
    #[clap(long, env = "OPRF_KEY_GEN_DB_ACQUIRE_TIMEOUT", value_parser=humantime::parse_duration, default_value="2min")]
    pub db_acquire_timeout: Duration,

    /// The delay between retires for db backoff.
    #[clap(long, env = "OPRF_KEY_GEN_DB_RETRY_DELAY", value_parser=humantime::parse_duration, default_value="5s")]
    pub db_retry_delay: Duration,

    /// The max retries for backoff strategy in db. With default acquire_timeout and retry delay, this is ~40min.
    #[clap(long, env = "OPRF_KEY_GEN_DB_MAX_RETRIES", default_value = "20")]
    pub db_max_retries: NonZeroUsize,

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

    /// Max time we wait for a transaction confirmation event until we assume the transaction didn't go through.
    ///
    /// We need this because RPCs are not very reliable, so we need to verify whether a transaction did get through or not.
    #[clap(long, env = "OPRF_NODE_MAX_WAIT_TIME_TRANSACTION_CONFIRMATION", default_value = "5min", value_parser=humantime::parse_duration)]
    pub max_wait_time_transaction_confirmation: Duration,

    /// Max attempts for sending a transaction when we get null response from RPC.
    ///
    /// We need this because RPCs are not very reliable, so we potentially need to resend a transaction did get through or not.
    #[clap(long, env = "OPRF_NODE_MAX_TRANSACTION_ATTEMPTS", default_value = "3")]
    pub max_transaction_attempts: usize,

    /// The block number to start listening for events from the OprfKeyRegistry contract.
    /// If not set, will start from the latest block.
    #[clap(long, env = "OPRF_NODE_START_BLOCK")]
    pub start_block: Option<u64>,

    /// Maximum amount of gas a single transaction is allowed to consume.
    /// This acts as a safety limit to prevent transactions from exceeding expected execution costs. The default value is set to approximately 2× the average gas used by a round-2 transaction, which is currently the most gas-intensive round.
    #[clap(
        long,
        env = "OPRF_NODE_MAX_GAS_PER_TRANSACTION",
        default_value = "8000000"
    )]
    pub max_gas_per_transaction: u64,

    /// Number of block confirmations required before a transaction is
    /// considered successful.
    ///
    /// Default value derived from (<https://help.coinbase.com/en/coinbase/getting-started/crypto-education/glossary/confirmations>).
    #[clap(
        long,
        env = "OPRF_NODE_TRANSACTION_CONFIRMATIONS",
        default_value = "14"
    )]
    pub confirmations_for_transaction: u64,
}
