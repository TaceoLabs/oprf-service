use alloy::{
    hex,
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, Bytes, TxKind, address},
    providers::{DynProvider, Provider as _, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolCall as _,
};
use eyre::{Context as _, ContextCompat as _};
use oprf_test_utils::{health_checks, oprf_key_registry, test_secret_manager::TestSecretManager};
use semver::VersionReq;
use std::{path::PathBuf, str::FromStr as _, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

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

pub type TestSetup13 = TestSetup<1, 3>;
pub type TestSetup25 = TestSetup<2, 5>;

pub struct TestSetup<const DEGREE: usize, const NUM_PEERS: usize> {
    pub anvil: AnvilInstance,
    pub provider: DynProvider,
    pub oprf_key_registry: Address,
    pub secret_managers: [TestSecretManager; NUM_PEERS],
    pub nodes: [String; NUM_PEERS],
    pub node_cancellation_tokens: [CancellationToken; NUM_PEERS],
    pub key_gens: [String; NUM_PEERS],
    pub key_gen_cancellation_tokens: [CancellationToken; NUM_PEERS],
}

impl TestSetup<1, 3> {
    pub async fn new() -> eyre::Result<Self> {
        let anvil = Anvil::new().spawn();
        let private_key = PrivateKeySigner::from_str(TACEO_ADMIN_PRIVATE_KEY)?;
        let wallet = EthereumWallet::from(private_key);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(&anvil.endpoint())
            .await
            .context("while connecting to RPC")?
            .erased();

        println!("Deploying OprfKeyRegistry contract...");
        let oprf_key_registry =
            deploy_oprf_key_registry_13(provider.clone(), TACEO_ADMIN_ADDRESS).await?;
        oprf_key_registry::register_oprf_nodes(
            provider.clone(),
            oprf_key_registry,
            vec![
                OPRF_PEER_ADDRESS_0,
                OPRF_PEER_ADDRESS_1,
                OPRF_PEER_ADDRESS_2,
            ],
        )
        .await?;

        let secret_managers = create_3_secret_managers();
        println!("Starting OPRF key-gens...");
        let (key_gens, key_gen_cancellation_tokens) = start_3_key_gens(
            &anvil.ws_endpoint(),
            secret_managers.clone(),
            oprf_key_registry,
        )
        .await;

        println!("Starting OPRF nodes...");
        let (nodes, node_cancellation_tokens) = start_3_nodes(
            &anvil.ws_endpoint(),
            secret_managers.clone(),
            oprf_key_registry,
        )
        .await;

        health_checks::services_health_check(&key_gens, Duration::from_secs(60)).await?;

        Ok(Self {
            anvil,
            provider,
            oprf_key_registry,
            secret_managers,
            nodes,
            node_cancellation_tokens,
            key_gens,
            key_gen_cancellation_tokens,
        })
    }
}

impl TestSetup<2, 5> {
    pub async fn new() -> eyre::Result<Self> {
        let anvil = Anvil::new().spawn();
        let private_key = PrivateKeySigner::from_str(TACEO_ADMIN_PRIVATE_KEY)?;
        let wallet = EthereumWallet::from(private_key);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(&anvil.endpoint())
            .await
            .context("while connecting to RPC")?
            .erased();

        println!("Deploying OprfKeyRegistry contract...");
        let oprf_key_registry =
            deploy_oprf_key_registry_25(provider.clone(), TACEO_ADMIN_ADDRESS).await?;
        oprf_key_registry::register_oprf_nodes(
            provider.clone(),
            oprf_key_registry,
            vec![
                OPRF_PEER_ADDRESS_0,
                OPRF_PEER_ADDRESS_1,
                OPRF_PEER_ADDRESS_2,
                OPRF_PEER_ADDRESS_3,
                OPRF_PEER_ADDRESS_4,
            ],
        )
        .await?;

        let secret_managers = create_5_secret_managers();
        println!("Starting OPRF key-gens...");
        let (key_gens, key_gen_cancellation_tokens) = start_5_key_gens(
            &anvil.ws_endpoint(),
            secret_managers.clone(),
            oprf_key_registry,
        )
        .await;

        println!("Starting OPRF nodes...");
        let (nodes, node_cancellation_tokens) = start_5_nodes(
            &anvil.ws_endpoint(),
            secret_managers.clone(),
            oprf_key_registry,
        )
        .await;

        health_checks::services_health_check(&key_gens, Duration::from_secs(60)).await?;

        Ok(Self {
            anvil,
            provider,
            oprf_key_registry,
            secret_managers,
            nodes,
            node_cancellation_tokens,
            key_gens,
            key_gen_cancellation_tokens,
        })
    }
}

pub async fn start_node(
    id: usize,
    chain_ws_rpc_url: &str,
    secret_manager: TestSecretManager,
    oprf_key_registry_contract: Address,
    wallet_address: Address,
) -> (String, CancellationToken) {
    let cancellation_token = CancellationToken::new();
    let url = format!("http://localhost:1{id:04}"); // set port based on id, e.g. 10001 for id 1
    let config = oprf_service_example::config::ExampleOprfNodeConfig {
        bind_addr: format!("0.0.0.0:1{id:04}").parse().unwrap(),
        max_wait_time_shutdown: Duration::from_secs(10),
        service_config: oprf_service::config::OprfNodeConfig {
            environment: oprf_service::config::Environment::Dev,
            rp_secret_id_prefix: format!("oprf/rp/n{id}"),
            oprf_key_registry_contract,
            chain_ws_rpc_url: chain_ws_rpc_url.into(),
            ws_max_message_size: 512 * 1024,
            session_lifetime: Duration::from_secs(60),
            wallet_address,
            get_oprf_key_material_timeout: Duration::from_secs(60),
            start_block: None,
            // allow all versions (does not match pre-releases)
            version_req: VersionReq::STAR,
            region: "test_region".to_string(),
        },
    };

    tokio::spawn({
        let cancellation_token = cancellation_token.clone();
        let cancellation_token_axum = cancellation_token.clone();
        async move {
            let res = oprf_service_example::start(config, Arc::new(secret_manager), async move {
                cancellation_token_axum.cancelled().await
            })
            .await;
            match res {
                Ok(_) => println!("service with {id} stopped gracefully"),
                Err(err) => eprintln!("service stopped unexpectedly: {err:?}"),
            }
        }
    });
    // very graceful timeout for CI
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if reqwest::get(url.clone() + "/health").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("can start");
    (url, cancellation_token)
}

pub async fn start_key_gen(
    id: usize,
    chain_ws_rpc_url: &str,
    secret_manager: TestSecretManager,
    rp_registry_contract: Address,
    key_gen_zkey_path: PathBuf,
    key_gen_witness_graph_path: PathBuf,
) -> (String, CancellationToken) {
    let cancellation_token = CancellationToken::new();
    let url = format!("http://localhost:2{id:04}"); // set port based on id, e.g. 20001 for id 1
    let config = oprf_key_gen::config::OprfKeyGenConfig {
        environment: oprf_key_gen::config::Environment::Dev,
        bind_addr: format!("0.0.0.0:2{id:04}").parse().unwrap(),
        oprf_key_registry_contract: rp_registry_contract,
        chain_ws_rpc_url: chain_ws_rpc_url.into(),
        rp_secret_id_prefix: format!("oprf/rp/n{id}"),
        wallet_private_key_secret_id: "wallet/privatekey".to_string(),
        key_gen_zkey_path,
        key_gen_witness_graph_path,
        max_wait_time_shutdown: Duration::from_secs(10),
        start_block: None,
        max_wait_time_transaction_confirmation: Duration::from_secs(30),
        max_transaction_attempts: 3,
    };
    tokio::spawn({
        let cancellation_token = cancellation_token.clone();
        let cancellation_token_axum = cancellation_token.clone();
        async move {
            let res = oprf_key_gen::start(config, Arc::new(secret_manager), async move {
                cancellation_token_axum.cancelled().await
            })
            .await;
            match res {
                Ok(_) => println!("key-gen with {id} stopped gracefully"),
                Err(err) => eprintln!("key-gen stopped unexpectedly: {err:?}"),
            }
        }
    });
    (url, cancellation_token)
}

pub fn create_3_secret_managers() -> [TestSecretManager; 3] {
    [
        TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_0),
        TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_1),
        TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_2),
    ]
}

pub fn create_5_secret_managers() -> [TestSecretManager; 5] {
    [
        TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_0),
        TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_1),
        TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_2),
        TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_3),
        TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_4),
    ]
}

pub async fn start_3_nodes(
    chain_ws_rpc_url: &str,
    secret_manager: [TestSecretManager; 3],
    key_gen_contract: Address,
) -> ([String; 3], [CancellationToken; 3]) {
    let [secret_manager0, secret_manager1, secret_manager2] = secret_manager;
    let (node0, node1, node2) = tokio::join!(
        start_node(
            0,
            chain_ws_rpc_url,
            secret_manager0,
            key_gen_contract,
            OPRF_PEER_ADDRESS_0,
        ),
        start_node(
            1,
            chain_ws_rpc_url,
            secret_manager1,
            key_gen_contract,
            OPRF_PEER_ADDRESS_1,
        ),
        start_node(
            2,
            chain_ws_rpc_url,
            secret_manager2,
            key_gen_contract,
            OPRF_PEER_ADDRESS_2,
        )
    );
    ([node0.0, node1.0, node2.0], [node0.1, node1.1, node2.1])
}

pub async fn start_5_nodes(
    chain_ws_rpc_url: &str,
    secret_manager: [TestSecretManager; 5],
    key_gen_contract: Address,
) -> ([String; 5], [CancellationToken; 5]) {
    let [
        secret_manager0,
        secret_manager1,
        secret_manager2,
        secret_manager3,
        secret_manager4,
    ] = secret_manager;
    let (node0, node1, node2, node3, node4) = tokio::join!(
        start_node(
            0,
            chain_ws_rpc_url,
            secret_manager0,
            key_gen_contract,
            OPRF_PEER_ADDRESS_0,
        ),
        start_node(
            1,
            chain_ws_rpc_url,
            secret_manager1,
            key_gen_contract,
            OPRF_PEER_ADDRESS_1,
        ),
        start_node(
            2,
            chain_ws_rpc_url,
            secret_manager2,
            key_gen_contract,
            OPRF_PEER_ADDRESS_2,
        ),
        start_node(
            3,
            chain_ws_rpc_url,
            secret_manager3,
            key_gen_contract,
            OPRF_PEER_ADDRESS_3,
        ),
        start_node(
            4,
            chain_ws_rpc_url,
            secret_manager4,
            key_gen_contract,
            OPRF_PEER_ADDRESS_4,
        ),
    );
    (
        [node0.0, node1.0, node2.0, node3.0, node4.0],
        [node0.1, node1.1, node2.1, node3.1, node4.1],
    )
}

pub async fn start_3_key_gens(
    chain_ws_rpc_url: &str,
    secret_manager: [TestSecretManager; 3],
    key_gen_contract: Address,
) -> ([String; 3], [CancellationToken; 3]) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let key_get_zkey_path = dir.join("../circom/main/key-gen/OPRFKeyGen.13.arks.zkey");
    let key_gen_witness_graph_path = dir.join("../circom/main/key-gen/OPRFKeyGenGraph.13.bin");
    let [secret_manager0, secret_manager1, secret_manager2] = secret_manager;
    let (node0, node1, node2) = tokio::join!(
        start_key_gen(
            0,
            chain_ws_rpc_url,
            secret_manager0,
            key_gen_contract,
            key_get_zkey_path.clone(),
            key_gen_witness_graph_path.clone()
        ),
        start_key_gen(
            1,
            chain_ws_rpc_url,
            secret_manager1,
            key_gen_contract,
            key_get_zkey_path.clone(),
            key_gen_witness_graph_path.clone()
        ),
        start_key_gen(
            2,
            chain_ws_rpc_url,
            secret_manager2,
            key_gen_contract,
            key_get_zkey_path.clone(),
            key_gen_witness_graph_path.clone()
        ),
    );
    ([node0.0, node1.0, node2.0], [node0.1, node1.1, node2.1])
}

pub async fn start_2_key_gens(
    chain_ws_rpc_url: &str,
    secret_manager: [TestSecretManager; 2],
    key_gen_contract: Address,
) -> ([String; 2], [CancellationToken; 2]) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let key_get_zkey_path = dir.join("../circom/main/key-gen/OPRFKeyGen.13.arks.zkey");
    let key_gen_witness_graph_path = dir.join("../circom/main/key-gen/OPRFKeyGenGraph.13.bin");
    let [secret_manager0, secret_manager1] = secret_manager;
    let (node0, node1) = tokio::join!(
        start_key_gen(
            0,
            chain_ws_rpc_url,
            secret_manager0,
            key_gen_contract,
            key_get_zkey_path.clone(),
            key_gen_witness_graph_path.clone()
        ),
        start_key_gen(
            1,
            chain_ws_rpc_url,
            secret_manager1,
            key_gen_contract,
            key_get_zkey_path.clone(),
            key_gen_witness_graph_path.clone()
        )
    );
    ([node0.0, node1.0], [node0.1, node1.1])
}

pub async fn start_5_key_gens(
    chain_ws_rpc_url: &str,
    secret_manager: [TestSecretManager; 5],
    key_gen_contract: Address,
) -> ([String; 5], [CancellationToken; 5]) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let key_get_zkey_path = dir.join("../circom/main/key-gen/OPRFKeyGen.25.arks.zkey");
    let key_gen_witness_graph_path = dir.join("../circom/main/key-gen/OPRFKeyGenGraph.25.bin");
    let [
        secret_manager0,
        secret_manager1,
        secret_manager2,
        secret_manager3,
        secret_manager4,
    ] = secret_manager;
    let (node0, node1, node2, node3, node4) = tokio::join!(
        start_key_gen(
            0,
            chain_ws_rpc_url,
            secret_manager0,
            key_gen_contract,
            key_get_zkey_path.clone(),
            key_gen_witness_graph_path.clone()
        ),
        start_key_gen(
            1,
            chain_ws_rpc_url,
            secret_manager1,
            key_gen_contract,
            key_get_zkey_path.clone(),
            key_gen_witness_graph_path.clone()
        ),
        start_key_gen(
            2,
            chain_ws_rpc_url,
            secret_manager2,
            key_gen_contract,
            key_get_zkey_path.clone(),
            key_gen_witness_graph_path.clone()
        ),
        start_key_gen(
            3,
            chain_ws_rpc_url,
            secret_manager3,
            key_gen_contract,
            key_get_zkey_path.clone(),
            key_gen_witness_graph_path.clone()
        ),
        start_key_gen(
            4,
            chain_ws_rpc_url,
            secret_manager4,
            key_gen_contract,
            key_get_zkey_path.clone(),
            key_gen_witness_graph_path.clone()
        ),
    );
    (
        [node0.0, node1.0, node2.0, node3.0, node4.0],
        [node0.1, node1.1, node2.1, node3.1, node4.1],
    )
}
