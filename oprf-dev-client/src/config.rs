use std::time::Duration;

use alloy::primitives::Address;
use clap::{Parser, Subcommand};
use secrecy::SecretString;

#[derive(Clone, Parser, Debug)]
pub struct StressTestOprfCommand {
    /// The amount of OPRF runs
    #[clap(long, env = "OPRF_DEV_CLIENT_RUNS", default_value = "10")]
    pub runs: usize,

    /// Send requests sequentially instead of concurrently
    #[clap(long, env = "OPRF_DEV_CLIENT_SEQUENTIAL")]
    pub sequential: bool,

    /// Send requests sequentially instead of concurrently
    #[clap(long, env = "OPRF_DEV_CLIENT_SKIP_CHECKS")]
    pub skip_checks: bool,
}

#[derive(Clone, Parser, Debug)]
pub struct StressTestKeyGenCommand {
    /// The amount of OPRF runs
    #[clap(long, env = "OPRF_DEV_CLIENT_RUNS", default_value = "10")]
    pub runs: usize,
}

#[derive(Clone, Parser, Debug)]
pub struct ReshareTest {
    /// The amount of requests we need to observe to accept the new epoch
    #[clap(long, env = "OPRF_DEV_CLIENT_ACCEPTANCE_NUM", default_value = "50")]
    pub acceptance_num: usize,
}

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    Test,
    DeleteTest,
    StressTestOprf(StressTestOprfCommand),
    StressTestKeyGen(StressTestKeyGenCommand),
    ReshareTest(ReshareTest),
}

#[derive(Parser, Debug, Clone)]
pub struct DevClientConfig {
    /// The URLs to all OPRF nodes
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_NODES",
        value_delimiter = ',',
        default_value = "http://127.0.0.1:10000,http://127.0.0.1:10001,http://127.0.0.1:10002"
    )]
    pub nodes: Vec<String>,

    /// The threshold of services that need to respond
    #[clap(long, env = "OPRF_DEV_CLIENT_THRESHOLD", default_value = "2")]
    pub threshold: usize,

    /// The Address of the OprfKeyRegistry contract.
    #[clap(long, env = "OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT")]
    pub oprf_key_registry_contract: Address,

    /// The RPC for chain communication
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_CHAIN_RPC_URL",
        default_value = "http://localhost:8545"
    )]
    pub chain_rpc_url: SecretString,

    /// The PRIVATE_KEY of the TACEO admin wallet - used to register the OPRF nodes
    ///
    /// Default is anvil wallet 0
    #[clap(
        long,
        env = "TACEO_ADMIN_PRIVATE_KEY",
        default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )]
    pub taceo_private_key: SecretString,

    /// The share epoch. Will be ignored if `oprf_key_id` is `None`.
    #[clap(long, env = "OPRF_DEV_CLIENT_SHARE_EPOCH", default_value = "0")]
    pub share_epoch: u32,

    /// max wait time for init key-gen/reshare to succeed.
    #[clap(long, env = "OPRF_DEV_CLIENT_WAIT_TIME", default_value="2min", value_parser=humantime::parse_duration)]
    pub max_wait_time: Duration,

    /// Command
    #[command(subcommand)]
    pub command: Command,
}
