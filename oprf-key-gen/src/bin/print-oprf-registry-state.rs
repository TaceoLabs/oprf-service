//! Binary to print OprfKeyRegistry internal mappings (runningKeyGens and oprfKeyRegistry).
//!
//! Connects to a chain via RPC (e.g. anvil at http://127.0.0.1:8545), fetches key-gen events,
//! reconstructs state from events, and optionally enriches with view calls for registered keys.
//!
//! Run anvil and deploy the contract separately, then pass --contract-address and optionally
//! --rpc-url (default http://127.0.0.1:8545).

use std::collections::{BTreeMap, BTreeSet};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, LogData, U160},
    providers::{Provider, ProviderBuilder},
    rpc::types::{Filter, Log},
    sol_types::SolEvent as _,
};
use clap::Parser;
use eyre::Context;
use oprf_types::chain::OprfKeyRegistry::{self, OprfKeyRegistryInstance};

#[derive(Parser, Debug)]
#[command(name = "print-oprf-registry-state")]
struct Args {
    /// RPC URL (e.g. http://127.0.0.1:8545 for local anvil).
    #[arg(long, env = "OPRF_REGISTRY_RPC_URL", default_value = "http://127.0.0.1:8545")]
    rpc_url: String,

    /// OprfKeyRegistry contract address.
    #[arg(long, env = "OPRF_KEY_REGISTRY_CONTRACT")]
    contract_address: Address,

    /// First block to fetch logs from (default: 0).
    #[arg(long, default_value = "0")]
    from_block: u64,

    /// Include keygens in NOT_STARTED state in the runningKeyGens table (default: exclude them).
    #[arg(long, default_value_t = false)]
    show_not_started: bool,
}

/// Round as inferred from events (matches OprfKeyGen.Round).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Round {
    NotStarted,
    One,
    Two,
    Three,
    Stuck,
    Deleted,
}

impl std::fmt::Display for Round {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Round::NotStarted => f.write_str("NOT_STARTED"),
            Round::One => f.write_str("ONE"),
            Round::Two => f.write_str("TWO"),
            Round::Three => f.write_str("THREE"),
            Round::Stuck => f.write_str("STUCK"),
            Round::Deleted => f.write_str("DELETED"),
        }
    }
}

/// Row for runningKeyGens table.
#[derive(Debug)]
struct RunningKeyGenRow {
    round: Round,
    generated_epoch: u32,
    kind: KeyGenKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyGenKind {
    Keygen,
    Reshare,
}

impl std::fmt::Display for KeyGenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyGenKind::Keygen => f.write_str("keygen"),
            KeyGenKind::Reshare => f.write_str("reshare"),
        }
    }
}

/// Build filter for key-gen events. We fetch all logs from the contract and filter by topic0 when decoding.
fn key_gen_log_filter(contract_address: Address, from_block: u64) -> Filter {
    Filter::new()
        .address(contract_address)
        .from_block(BlockNumberOrTag::Number(from_block))
        .to_block(BlockNumberOrTag::Latest)
}

/// Replay events in order and return (running_key_gens, registered_key_ids with epoch from Finalize).
fn replay_events(
    logs: &[(u64, u64, Log<LogData>)],
    running_key_gens: &mut BTreeMap<U160, RunningKeyGenRow>,
    registered: &mut BTreeMap<U160, u32>,
) -> eyre::Result<()> {
    for (_block, _idx, log) in logs {
        let topic0 = match log.topic0() {
            Some(t) => t,
            None => continue,
        };
        if *topic0 == OprfKeyRegistry::SecretGenRound1::SIGNATURE_HASH {
            let decoded: alloy::rpc::types::Log<OprfKeyRegistry::SecretGenRound1> =
                log.clone().log_decode().context("decode SecretGenRound1")?;
            let oprf_key_id = decoded.inner.data.oprfKeyId;
            running_key_gens.insert(
                oprf_key_id,
                RunningKeyGenRow {
                    round: Round::One,
                    generated_epoch: 0,
                    kind: KeyGenKind::Keygen,
                },
            );
        } else if *topic0 == OprfKeyRegistry::ReshareRound1::SIGNATURE_HASH {
            let decoded: alloy::rpc::types::Log<OprfKeyRegistry::ReshareRound1> =
                log.clone().log_decode().context("decode ReshareRound1")?;
            let oprf_key_id = decoded.inner.data.oprfKeyId;
            let epoch = decoded.inner.data.epoch;
            running_key_gens.insert(
                oprf_key_id,
                RunningKeyGenRow {
                    round: Round::One,
                    generated_epoch: epoch,
                    kind: KeyGenKind::Reshare,
                },
            );
        } else if *topic0 == OprfKeyRegistry::SecretGenRound2::SIGNATURE_HASH {
            let decoded: alloy::rpc::types::Log<OprfKeyRegistry::SecretGenRound2> =
                log.clone().log_decode().context("decode SecretGenRound2")?;
            let oprf_key_id = decoded.inner.data.oprfKeyId;
            if let Some(row) = running_key_gens.get_mut(&oprf_key_id) {
                row.round = Round::Two;
                row.generated_epoch = decoded.inner.data.epoch;
            }
        } else if *topic0 == OprfKeyRegistry::SecretGenRound3::SIGNATURE_HASH {
            let decoded: alloy::rpc::types::Log<OprfKeyRegistry::SecretGenRound3> =
                log.clone().log_decode().context("decode SecretGenRound3")?;
            let oprf_key_id = decoded.inner.data.oprfKeyId;
            if let Some(row) = running_key_gens.get_mut(&oprf_key_id) {
                row.round = Round::Three;
            }
        } else if *topic0 == OprfKeyRegistry::ReshareRound3::SIGNATURE_HASH {
            let decoded: alloy::rpc::types::Log<OprfKeyRegistry::ReshareRound3> =
                log.clone().log_decode().context("decode ReshareRound3")?;
            let oprf_key_id = decoded.inner.data.oprfKeyId;
            if let Some(row) = running_key_gens.get_mut(&oprf_key_id) {
                row.round = Round::Three;
                row.generated_epoch = decoded.inner.data.epoch;
            }
        } else if *topic0 == OprfKeyRegistry::SecretGenFinalize::SIGNATURE_HASH {
            let decoded: alloy::rpc::types::Log<OprfKeyRegistry::SecretGenFinalize> =
                log.clone().log_decode().context("decode SecretGenFinalize")?;
            let oprf_key_id = decoded.inner.data.oprfKeyId;
            let epoch = decoded.inner.data.epoch;
            if let Some(row) = running_key_gens.get_mut(&oprf_key_id) {
                row.round = Round::NotStarted;
            }
            registered.insert(oprf_key_id, epoch);
        } else if *topic0 == OprfKeyRegistry::KeyGenAbort::SIGNATURE_HASH {
            let decoded: alloy::rpc::types::Log<OprfKeyRegistry::KeyGenAbort> =
                log.clone().log_decode().context("decode KeyGenAbort")?;
            let oprf_key_id = decoded.inner.data.oprfKeyId;
            if let Some(row) = running_key_gens.get_mut(&oprf_key_id) {
                row.round = Round::NotStarted;
            }
        } else if *topic0 == OprfKeyRegistry::KeyDeletion::SIGNATURE_HASH {
            let decoded: alloy::rpc::types::Log<OprfKeyRegistry::KeyDeletion> =
                log.clone().log_decode().context("decode KeyDeletion")?;
            let oprf_key_id = decoded.inner.data.oprfKeyId;
            if let Some(row) = running_key_gens.get_mut(&oprf_key_id) {
                row.round = Round::Deleted;
            }
            registered.remove(&oprf_key_id);
        } else if *topic0 == OprfKeyRegistry::NotEnoughProducers::SIGNATURE_HASH {
            let decoded: alloy::rpc::types::Log<OprfKeyRegistry::NotEnoughProducers> =
                log.clone().log_decode().context("decode NotEnoughProducers")?;
            let oprf_key_id = decoded.inner.data.oprfKeyId;
            if let Some(row) = running_key_gens.get_mut(&oprf_key_id) {
                row.round = Round::Stuck;
            }
        }
    }
    Ok(())
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build runtime")?;

    rt.block_on(run(&args))
}

async fn run(args: &Args) -> eyre::Result<()> {
    let rpc_url = reqwest::Url::parse(&args.rpc_url).context("invalid rpc_url")?;
    let provider = ProviderBuilder::new()
        .connect_http(rpc_url)
        .erased();

    let contract_address = args.contract_address;
    let from_block = args.from_block;

    let filter = key_gen_log_filter(contract_address, from_block);

    let logs = provider
        .get_logs(&filter)
        .await
        .context("get_logs")?;

    let key_gen_topic0 = [
        OprfKeyRegistry::SecretGenRound1::SIGNATURE_HASH,
        OprfKeyRegistry::SecretGenRound2::SIGNATURE_HASH,
        OprfKeyRegistry::SecretGenRound3::SIGNATURE_HASH,
        OprfKeyRegistry::SecretGenFinalize::SIGNATURE_HASH,
        OprfKeyRegistry::ReshareRound1::SIGNATURE_HASH,
        OprfKeyRegistry::ReshareRound3::SIGNATURE_HASH,
        OprfKeyRegistry::KeyDeletion::SIGNATURE_HASH,
        OprfKeyRegistry::KeyGenAbort::SIGNATURE_HASH,
        OprfKeyRegistry::NotEnoughProducers::SIGNATURE_HASH,
    ];
    let mut sorted: Vec<(u64, u64, Log<LogData>)> = logs
        .into_iter()
        .filter(|log| {
            log.topic0().map_or(false, |t| key_gen_topic0.iter().any(|sig| *t == *sig))
        })
        .map(|log| {
            let block = log.block_number.unwrap_or(0);
            let idx = log.log_index.unwrap_or(0);
            (block, idx, log)
        })
        .collect();
    sorted.sort_by_key(|(block, idx, _)| (*block, *idx));

    if sorted.is_empty() {
        eprintln!("No key-gen events found for contract {contract_address} from block {from_block}. Check address and RPC.");
        return Ok(());
    }

    let mut running_key_gens: BTreeMap<U160, RunningKeyGenRow> = BTreeMap::new();
    let mut registered: BTreeMap<U160, u32> = BTreeMap::new();
    replay_events(&sorted, &mut running_key_gens, &mut registered)?;

    let contract = OprfKeyRegistryInstance::new(contract_address, provider.clone());

    // ---- Table 1: runningKeyGens ----
    println!("\n=== runningKeyGens (from events) ===\n");
    const W_ID: usize = 22;
    const W_ROUND: usize = 12;
    const W_EPOCH: usize = 8;
    const W_KIND: usize = 10;
    println!(
        "{:<W_ID$} {:>W_ROUND$} {:>W_EPOCH$} {:>W_KIND$}",
        "oprfKeyId", "round", "epoch", "kind"
    );
    println!("{}", "-".repeat(W_ID + 1 + W_ROUND + 1 + W_EPOCH + 1 + W_KIND));
    for (id, row) in &running_key_gens {
        if !args.show_not_started && row.round == Round::NotStarted {
            continue;
        }
        println!(
            "{:<W_ID$} {:>W_ROUND$} {:>W_EPOCH$} {:>W_KIND$}",
            id.to_string(),
            row.round.to_string(),
            row.generated_epoch,
            row.kind.to_string()
        );
    }

    // ---- Table 2: oprfKeyRegistry ----
    println!("\n=== oprfKeyRegistry (registered keys) ===\n");
    const W_X: usize = 78;
    const W_Y: usize = 78;
    println!(
        "{:<W_ID$} {:>W_EPOCH$} {:>W_X$} {:>W_Y$}",
        "oprfKeyId", "epoch", "key.x", "key.y"
    );
    println!("{}", "-".repeat(W_ID + 1 + W_EPOCH + 1 + W_X + 1 + W_Y));

    let registered_ids: BTreeSet<U160> = registered.keys().copied().collect();
    for oprf_key_id in &registered_ids {
        match contract.getOprfPublicKeyAndEpoch(*oprf_key_id).call().await {
            Ok(result) => {
                let key = result.key;
                let epoch = result.epoch;
                println!(
                    "{:<W_ID$} {:>W_EPOCH$} {:>W_X$} {:>W_Y$}",
                    oprf_key_id.to_string(),
                    epoch,
                    key.x.to_string(),
                    key.y.to_string()
                );
            }
            Err(e) => {
                let epoch_hint = registered.get(oprf_key_id).copied().unwrap_or(0);
                println!(
                    "{:<W_ID$} {:>W_EPOCH$} (view call failed: {e})",
                    oprf_key_id.to_string(),
                    epoch_hint
                );
            }
        }
    }

    if registered_ids.is_empty() {
        println!("(no registered keys)");
    }

    Ok(())
}
