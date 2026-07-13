#![allow(clippy::exhaustive_enums, reason = "This is only for tests")]
#![allow(clippy::exhaustive_structs, reason = "This is only for tests")]
#![allow(missing_docs, reason = "generated bindings from the sol! macro")]
//! Test helpers for deploying the OPRF contracts to a local
//! [Anvil](https://book.getfoundry.sh/anvil/) devnet, for use in integration tests.
//!
//! From the compiled artifacts in `contracts/`, these helpers deploy the Groth16
//! key-gen verifier, the `BabyJubJub` library, and `OprfKeyRegistry` behind an
//! ERC-1967 upgradeable proxy.
//!
//! Two committee presets are provided as entry points:
//! - [`deploy_oprf_key_registry_13`] – a 2-of-3 committee.
//! - [`deploy_oprf_key_registry_25`] – a 3-of-5 committee.
//!
//! Additionally provides methods to interact with the deployed contract.
use alloy::{
    hex,
    primitives::{Address, Bytes, TxKind},
    providers::{DynProvider, Provider as _},
    rpc::types::TransactionRequest,
    sol,
    sol_types::SolCall as _,
};
use eyre::{Context as _, ContextCompat as _};
use oprf_types::{OprfKeyId, chain::OprfKeyRegistry};

sol!(
    #[sol(rpc, ignore_unlinked)]
    VerifierKeyGen13,
    concat!(env!("CARGO_MANIFEST_DIR"), "/contracts/Verifier.13.json")
);

sol!(
    #[sol(rpc, ignore_unlinked)]
    VerifierKeyGen25,
    concat!(env!("CARGO_MANIFEST_DIR"), "/contracts/Verifier.25.json")
);

sol!(
    #[sol(rpc)]
    ERC1967Proxy,
    concat!(env!("CARGO_MANIFEST_DIR"), "/contracts/ERC1967Proxy.json")
);

async fn deploy_contract(
    provider: DynProvider,
    bytecode: Bytes,
    constructor_args: Bytes,
) -> eyre::Result<Address> {
    let mut deployment_bytecode = bytecode.to_vec();
    deployment_bytecode.extend_from_slice(&constructor_args);

    let tx = TransactionRequest {
        to: Some(TxKind::Create),
        input: deployment_bytecode.into(),
        ..Default::default()
    };

    let pending_tx = provider.send_transaction(tx).await?;
    let receipt = pending_tx.get_receipt().await?;

    receipt
        .contract_address
        .context("contract deployment failed - no address in receipt")
}

/// Links a library to bytecode hex string and returns the hex string (no decoding).
///
/// Use this when you need to link multiple libraries before decoding.
fn link_bytecode_hex(
    json: &str,
    bytecode_str: &str,
    library_path: &str,
    library_address: Address,
) -> eyre::Result<String> {
    let json: serde_json::Value = serde_json::from_str(json)?;
    let link_refs = &json["bytecode"]["linkReferences"];
    let (file_path, library_name) = library_path
        .split_once(':')
        .context("library_path must be in format 'file:Library'")?;

    let references = link_refs
        .get(file_path)
        .and_then(|v| v.get(library_name))
        .and_then(|v| v.as_array())
        .context("library reference not found")?;

    // Format library address as 40-character hex (20 bytes, no 0x prefix)
    let lib_addr_hex = format!("{library_address:040x}");

    let mut linked_bytecode = bytecode_str.to_string();

    // Process all references in reverse order to maintain correct positions
    let mut refs: Vec<_> = references
        .iter()
        .filter_map(|r| {
            #[allow(clippy::cast_possible_truncation, reason = "This is only for tests")]
            let start = r["start"].as_u64()? as usize * 2; // byte offset -> hex offset
            Some(start)
        })
        .collect();
    refs.sort_by(|a, b| b.cmp(a)); // Sort descending

    for start_pos in refs {
        if start_pos + 40 <= linked_bytecode.len() {
            linked_bytecode.replace_range(start_pos..start_pos + 40, &lib_addr_hex);
        }
    }

    Ok(linked_bytecode)
}

/// Deploys the `OprfKeyRegistry` contract using the supplied signer.
async fn deploy_oprf_key_registry(
    provider: DynProvider,
    admin: Address,
    key_gen_verifier: Address,
    threshold: u16,
    num_peers: u16,
) -> eyre::Result<Address> {
    // Deploy BabyJubJub library (no dependencies)
    let baby_jub_jub_json = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/contracts/BabyJubJub.json"
    ));
    let json_value: serde_json::Value = serde_json::from_str(baby_jub_jub_json)?;
    let bytecode_str = json_value["bytecode"]["object"]
        .as_str()
        .context("bytecode not found in JSON")?
        .strip_prefix("0x")
        .unwrap_or_else(|| {
            json_value["bytecode"]["object"]
                .as_str()
                .expect("bytecode should be a string")
        })
        .to_string();
    let baby_jub_jub_bytecode = Bytes::from(hex::decode(bytecode_str)?);

    let baby_jub_jub_address =
        deploy_contract(provider.clone(), baby_jub_jub_bytecode, Bytes::new())
            .await
            .context("failed to deploy BabyJubJub library")?;

    // Link BabyJubJub to OprfKeyRegistry
    let oprf_key_registry_json = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oprf-types/OprfKeyRegistry.json"
    ));
    let json_value: serde_json::Value = serde_json::from_str(oprf_key_registry_json)?;
    let mut bytecode_str = json_value["bytecode"]["object"]
        .as_str()
        .context("bytecode not found in JSON")?
        .strip_prefix("0x")
        .unwrap_or_else(|| {
            json_value["bytecode"]["object"]
                .as_str()
                .expect("bytecode should be a string")
        })
        .to_string();

    bytecode_str = link_bytecode_hex(
        oprf_key_registry_json,
        &bytecode_str,
        "lib/babyjubjub-solidity/src/BabyJubJub.sol:BabyJubJub",
        baby_jub_jub_address,
    )?;

    // Decode the fully-linked bytecode
    let oprf_key_registry_bytecode = Bytes::from(hex::decode(bytecode_str)?);

    let implementation_address =
        deploy_contract(provider.clone(), oprf_key_registry_bytecode, Bytes::new())
            .await
            .context("failed to deploy OprfKeyRegistry implementation")?;

    let init_data = Bytes::from(
        OprfKeyRegistry::initializeCall {
            _keygenAdmin: admin,
            _keyGenVerifierAddress: key_gen_verifier,
            _threshold: threshold,
            _numPeers: num_peers,
            _owner: admin,
        }
        .abi_encode(),
    );

    let proxy = ERC1967Proxy::deploy(provider, implementation_address, init_data)
        .await
        .context("failed to deploy OprfKeyRegistry proxy")?;

    Ok(*proxy.address())
}

/// Deploys the `OprfKeyRegistry` contract using the supplied signer.
///
/// # Errors
/// If the deployment fails for any reasons.
pub async fn deploy_oprf_key_registry_13(
    provider: DynProvider,
    admin: Address,
) -> eyre::Result<Address> {
    let key_gen_verifier = VerifierKeyGen13::deploy(provider.clone())
        .await
        .context("failed to deploy Groth16VerifierKeyGen13 contract")?;

    deploy_oprf_key_registry(provider, admin, *key_gen_verifier.address(), 2, 3).await
}

/// Deploys the `OprfKeyRegistry` contract using the supplied signer.
///
/// # Errors
/// If the deployment fails for any reasons.
pub async fn deploy_oprf_key_registry_25(
    provider: DynProvider,
    admin: Address,
) -> eyre::Result<Address> {
    let key_gen_verifier = VerifierKeyGen25::deploy(provider.clone())
        .await
        .context("failed to deploy Groth16VerifierKeyGen25 contract")?;

    deploy_oprf_key_registry(provider, admin, *key_gen_verifier.address(), 3, 5).await
}

/// Registers the supplied node addresses as OPRF peers in the `OprfKeyRegistry`.
///
/// # Errors
/// If the registration transaction fails for any reason.
pub async fn register_oprf_nodes(
    provider: DynProvider,
    oprf_key_registry: Address,
    node_addresses: Vec<Address>,
) -> eyre::Result<()> {
    let oprf_key_registry = OprfKeyRegistry::new(oprf_key_registry, provider);
    let receipt = oprf_key_registry
        .registerOprfPeers(node_addresses)
        .send()
        .await?
        .get_receipt()
        .await?;
    if !receipt.status() {
        eyre::bail!("failed to register OPRF peers");
    }
    Ok(())
}

/// Initialises a key-generation round for the given `oprf_key_id` in the `OprfKeyRegistry`.
///
/// # Errors
/// If the key-generation transaction fails for any reason.
pub async fn init_key_gen(
    provider: DynProvider,
    oprf_key_registry: Address,
    oprf_key_id: OprfKeyId,
) -> eyre::Result<()> {
    let oprf_key_registry = OprfKeyRegistry::new(oprf_key_registry, provider);
    let receipt = oprf_key_registry
        .initKeyGen(oprf_key_id.into_inner())
        .send()
        .await?
        .get_receipt()
        .await?;
    if !receipt.status() {
        eyre::bail!("failed to init OPRF key gen");
    }
    Ok(())
}

/// Initialises a reshare round for the given `oprf_key_id` in the `OprfKeyRegistry`.
///
/// # Errors
/// If the reshare transaction fails for any reason.
pub async fn init_reshare(
    provider: DynProvider,
    oprf_key_registry: Address,
    oprf_key_id: OprfKeyId,
) -> eyre::Result<()> {
    let oprf_key_registry = OprfKeyRegistry::new(oprf_key_registry, provider);
    let receipt = oprf_key_registry
        .initReshare(oprf_key_id.into_inner())
        .send()
        .await?
        .get_receipt()
        .await?;
    if !receipt.status() {
        eyre::bail!("failed to init OPRF reshare");
    }
    Ok(())
}

/// Deletes the given `oprf_key_id` in the `OprfKeyRegistry`.
///
/// # Errors
/// If the delete transaction fails for any reason.
pub async fn init_delete(
    provider: DynProvider,
    oprf_key_registry: Address,
    oprf_key_id: OprfKeyId,
) -> eyre::Result<()> {
    let oprf_key_registry = OprfKeyRegistry::new(oprf_key_registry, provider);
    let receipt = oprf_key_registry
        .deleteOprfPublicKey(oprf_key_id.into_inner())
        .send()
        .await?
        .get_receipt()
        .await?;
    if !receipt.status() {
        eyre::bail!("failed to delete OPRF public key");
    }
    Ok(())
}

/// Aborts the in-process key-generation for the given `oprf_key_id` in the `OprfKeyRegistry`.
///
/// # Errors
/// If the abort transaction fails for any reason.
pub async fn init_abort(
    provider: DynProvider,
    oprf_key_registry: Address,
    oprf_key_id: OprfKeyId,
) -> eyre::Result<()> {
    let oprf_key_registry = OprfKeyRegistry::new(oprf_key_registry, provider);
    let receipt = oprf_key_registry
        .abortKeyGen(oprf_key_id.into_inner())
        .send()
        .await?
        .get_receipt()
        .await?;
    if !receipt.status() {
        eyre::bail!("failed to abort OPRF key gen");
    }
    Ok(())
}
