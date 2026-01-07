use crate::test_secret_manager::TestSecretManager;
use alloy::primitives::{Address, address};
use std::{path::PathBuf, sync::Arc, time::Duration};

pub mod health_checks;
pub mod oprf_key_registry_scripts;
pub mod test_secret_manager;

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

async fn start_node(
    id: usize,
    chain_ws_rpc_url: &str,
    secret_manager: TestSecretManager,
    rp_registry_contract: Address,
    wallet_address: Address,
) -> String {
    let url = format!("http://localhost:1{id:04}"); // set port based on id, e.g. 10001 for id 1
    let config = oprf_service_example::config::ExampleOprfNodeConfig {
        bind_addr: format!("0.0.0.0:1{id:04}").parse().unwrap(),
        max_wait_time_shutdown: Duration::from_secs(10),
        service_config: oprf_service::config::OprfNodeConfig {
            environment: oprf_service::config::Environment::Dev,
            rp_secret_id_prefix: format!("oprf/rp/n{id}"),
            oprf_key_registry_contract: rp_registry_contract,
            chain_ws_rpc_url: chain_ws_rpc_url.into(),
            ws_max_message_size: 512 * 1024,
            session_lifetime: Duration::from_secs(60),
            wallet_address,
            get_oprf_key_material_timeout: Duration::from_secs(60),
            start_block: Some(0),
        },
    };
    let never = async { futures::future::pending::<()>().await };
    tokio::spawn(async move {
        let res = oprf_service_example::start(config, Arc::new(secret_manager), never).await;
        eprintln!("service failed to start: {res:?}");
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
    url
}

async fn start_key_gen(
    id: usize,
    chain_ws_rpc_url: &str,
    secret_manager: TestSecretManager,
    rp_registry_contract: Address,
    key_gen_zkey_path: PathBuf,
    key_gen_witness_graph_path: PathBuf,
) -> String {
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
        max_epoch_cache_size: 3,
        start_block: Some(0),
        max_wait_time_transaction_confirmation: Duration::from_secs(30),
        max_transaction_attempts: 3,
    };
    let never = async { futures::future::pending::<()>().await };
    tokio::spawn(async move {
        let res = oprf_key_gen::start(config, Arc::new(secret_manager), never).await;
        eprintln!("key-gen failed to start: {res:?}");
    });
    url
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
) -> [String; 3] {
    let [secret_manager0, secret_manager1, secret_manager2] = secret_manager;
    tokio::join!(
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
    )
    .into()
}

pub async fn start_5_nodes(
    chain_ws_rpc_url: &str,
    secret_manager: [TestSecretManager; 5],
    key_gen_contract: Address,
) -> [String; 5] {
    let [
        secret_manager0,
        secret_manager1,
        secret_manager2,
        secret_manager3,
        secret_manager4,
    ] = secret_manager;
    tokio::join!(
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
    )
    .into()
}

pub async fn start_3_key_gens(
    chain_ws_rpc_url: &str,
    secret_manager: [TestSecretManager; 3],
    key_gen_contract: Address,
) -> [String; 3] {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let key_get_zkey_path = dir.join("../circom/main/key-gen/OPRFKeyGen.13.arks.zkey");
    let key_gen_witness_graph_path = dir.join("../circom/main/key-gen/OPRFKeyGenGraph.13.bin");
    let [secret_manager0, secret_manager1, secret_manager2] = secret_manager;
    tokio::join!(
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
    )
    .into()
}

pub async fn start_5_key_gens(
    chain_ws_rpc_url: &str,
    secret_manager: [TestSecretManager; 5],
    key_gen_contract: Address,
) -> [String; 5] {
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
    tokio::join!(
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
    )
    .into()
}
