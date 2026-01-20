use std::{path::PathBuf, process::Command, str::FromStr as _};

use alloy::primitives::{Address, U160};
use oprf_types::OprfKeyId;
use regex::Regex;

pub fn deploy_test_setup(
    rpc_url: &str,
    taceo_admin_address: &str,
    taceo_admin_private_key: &str,
    participant_addresses: &str,
    threshold: usize,
    num_peers: usize,
) -> Address {
    let mut cmd = Command::new("forge");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cmd = cmd
        .current_dir(dir.join("../contracts"))
        .env("TACEO_ADMIN_ADDRESS", taceo_admin_address)
        .env("NUM_PEERS", num_peers.to_string())
        .env("THRESHOLD", threshold.to_string())
        .env("PARTICIPANT_ADDRESSES", participant_addresses)
        .arg("script")
        .arg("script/test/TestSetup.s.sol")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--broadcast")
        .arg("--private-key")
        .arg(taceo_admin_private_key);
    let output = cmd.output().expect("failed to run forge script");
    assert!(
        output.status.success(),
        "forge script failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"OprfKeyRegistry deployed to:\s*(0x[0-9a-fA-F]{40})").unwrap();
    let addr = re
        .captures(&stdout)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .expect("failed to parse deployed address from script output");
    Address::from_str(&addr).expect("valid addr")
}

pub fn register_participants(
    rpc_url: &str,
    oprf_key_registry_contract: Address,
    taceo_admin_private_key: &str,
    participant_addresses: &str,
) {
    let mut cmd = Command::new("forge");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cmd = cmd
        .current_dir(dir.join("../contracts/script/"))
        .env(
            "OPRF_KEY_REGISTRY_PROXY",
            oprf_key_registry_contract.to_string(),
        )
        .env("PARTICIPANT_ADDRESSES", participant_addresses)
        .arg("script")
        .arg("RegisterParticipants.s.sol")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--broadcast")
        .arg("--private-key")
        .arg(taceo_admin_private_key);
    let output = cmd.output().expect("failed to run forge script");
    assert!(
        output.status.success(),
        "forge script failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn init_key_gen_with_id(
    rpc_url: &str,
    oprf_key_registry_contract: Address,
    taceo_admin_private_key: &str,
    oprf_key_id: OprfKeyId,
) {
    let mut cmd = Command::new("forge");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    tracing::debug!("init key gen with oprf_key_id: {oprf_key_id}");
    tracing::debug!("with rpc url: {rpc_url}");
    tracing::debug!("on contract: {oprf_key_registry_contract}");
    let cmd = cmd
        .current_dir(dir.join("../contracts"))
        .env(
            "OPRF_KEY_REGISTRY_PROXY",
            oprf_key_registry_contract.to_string(),
        )
        .env("OPRF_KEY_ID", oprf_key_id.to_string())
        .arg("script")
        .arg("script/InitKeyGen.s.sol")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--broadcast")
        .arg("--private-key")
        .arg(taceo_admin_private_key);
    tracing::debug!("executing cmd: {:?}", cmd);
    let output = cmd.output().expect("failed to run forge script");
    assert!(
        output.status.success(),
        "forge script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn init_key_gen(
    rpc_url: &str,
    oprf_key_registry_contract: Address,
    taceo_admin_private_key: &str,
) -> OprfKeyId {
    let oprf_key_id = OprfKeyId::new(U160::from(rand::random::<u32>()));
    init_key_gen_with_id(
        rpc_url,
        oprf_key_registry_contract,
        taceo_admin_private_key,
        oprf_key_id,
    );
    oprf_key_id
}

pub fn key_gen_abort(
    rpc_url: &str,
    oprf_key_registry_contract: Address,
    taceo_admin_private_key: &str,
) {
    let mut cmd = Command::new("forge");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let oprf_key_id = rand::random::<u32>();
    let cmd = cmd
        .current_dir(dir.join("../contracts"))
        .env(
            "OPRF_KEY_REGISTRY_PROXY",
            oprf_key_registry_contract.to_string(),
        )
        .env("OPRF_KEY_ID", oprf_key_id.to_string())
        .arg("script")
        .arg("script/AbortKeyGen.s.sol")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--broadcast")
        .arg("--private-key")
        .arg(taceo_admin_private_key);
    tracing::debug!("executing cmd: {:?}", cmd);
    cmd.output().expect("failed to run forge script");
}

pub fn init_reshare(
    oprf_key_id: OprfKeyId,
    rpc_url: &str,
    oprf_key_registry_contract: Address,
    taceo_admin_private_key: &str,
) {
    let mut cmd = Command::new("forge");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    tracing::debug!("init reshare for oprf_key_id: {oprf_key_id}");
    tracing::debug!("with rpc url: {rpc_url}");
    tracing::debug!("on contract: {oprf_key_registry_contract}");
    let cmd = cmd
        .current_dir(dir.join("../contracts"))
        .env(
            "OPRF_KEY_REGISTRY_PROXY",
            oprf_key_registry_contract.to_string(),
        )
        .env("OPRF_KEY_ID", oprf_key_id.to_string())
        .arg("script")
        .arg("script/InitReshare.s.sol")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--broadcast")
        .arg("--private-key")
        .arg(taceo_admin_private_key);
    tracing::debug!("executing cmd: {:?}", cmd);
    let output = cmd.output().expect("failed to run forge script");
    assert!(
        output.status.success(),
        "forge script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn delete_oprf_key_material(
    rpc_url: &str,
    oprf_key_registry_contract: Address,
    oprf_key_id: OprfKeyId,
    taceo_admin_private_key: &str,
) {
    let mut cmd = Command::new("forge");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cmd = cmd
        .current_dir(dir.join("../contracts"))
        .env(
            "OPRF_KEY_REGISTRY_PROXY",
            oprf_key_registry_contract.to_string(),
        )
        .env("OPRF_KEY_ID", oprf_key_id.to_string())
        .arg("script")
        .arg("script/DeleteOprfKey.s.sol")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--broadcast")
        .arg("--private-key")
        .arg(taceo_admin_private_key);
    tracing::debug!("executing cmd: {:?}", cmd);
    let output = cmd.output().expect("failed to run forge script");
    assert!(
        output.status.success(),
        "forge script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
