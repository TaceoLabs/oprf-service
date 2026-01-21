use alloy::{
    hex,
    primitives::{Address, Bytes, TxKind, address},
    providers::{DynProvider, Provider as _},
    rpc::types::TransactionRequest,
    sol,
    sol_types::SolCall as _,
};
use eyre::{Context as _, ContextCompat as _};

/// anvil wallet 0
pub const TACEO_ADMIN_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
pub const TACEO_ADMIN_ADDRESS: Address = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// anvil wallet 5
pub const OPRF_PEER_PRIVATE_KEY_0: &str =
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba";
pub const OPRF_PEER_ADDRESS_0: Address = address!("0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc");
/// anvil wallet 6
pub const OPRF_PEER_PRIVATE_KEY_1: &str =
    "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e";
pub const OPRF_PEER_ADDRESS_1: Address = address!("0x976EA74026E726554dB657fA54763abd0C3a0aa9");
/// anvil wallet 7
pub const OPRF_PEER_PRIVATE_KEY_2: &str =
    "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356";
pub const OPRF_PEER_ADDRESS_2: Address = address!("0x14dC79964da2C08b23698B3D3cc7Ca32193d9955");
/// anvil wallet 8
pub const OPRF_PEER_PRIVATE_KEY_3: &str =
    "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97";
pub const OPRF_PEER_ADDRESS_3: Address = address!("0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f");
/// anvil wallet 9
pub const OPRF_PEER_PRIVATE_KEY_4: &str =
    "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";
pub const OPRF_PEER_ADDRESS_4: Address = address!("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720");

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    VerifierKeyGen13,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/out/VerifierKeyGen13.sol/Verifier.json"
    )
);

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    VerifierKeyGen25,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/out/VerifierKeyGen25.sol/Verifier.json"
    )
);

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    OprfKeyRegistry,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/out/OprfKeyRegistry.sol/OprfKeyRegistry.json"
    )
);

sol!(
    #[sol(rpc)]
    ERC1967Proxy,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/out/ERC1967Proxy.sol/ERC1967Proxy.json"
    )
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
        "/../contracts/out/BabyJubJub.sol/BabyJubJub.json"
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
        "/../contracts/out/OprfKeyRegistry.sol/OprfKeyRegistry.json"
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
        "src/BabyJubJub.sol:BabyJubJub",
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
        }
        .abi_encode(),
    );

    let proxy = ERC1967Proxy::deploy(provider, implementation_address, init_data)
        .await
        .context("failed to deploy OprfKeyRegistry proxy")?;

    Ok(*proxy.address())
}

/// Deploys the `OprfKeyRegistry` contract using the supplied signer.
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
pub async fn deploy_oprf_key_registry_25(
    provider: DynProvider,
    admin: Address,
) -> eyre::Result<Address> {
    let key_gen_verifier = VerifierKeyGen25::deploy(provider.clone())
        .await
        .context("failed to deploy Groth16VerifierKeyGen25 contract")?;

    deploy_oprf_key_registry(provider, admin, *key_gen_verifier.address(), 3, 5).await
}
