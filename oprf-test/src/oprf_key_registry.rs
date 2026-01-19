use alloy::{
    primitives::{Address, Bytes, U256},
    providers::DynProvider,
    sol,
    sol_types::SolCall as _,
    uint,
};
use eyre::Context as _;
use oprf_types::OprfKeyId;

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
    BabyJubJub,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/out/BabyJubJub.sol/BabyJubJub.json"
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

/// Deploys the `OprfKeyRegistry` contract using the supplied signer.
async fn deploy_oprf_key_registry(
    provider: DynProvider,
    admin: Address,
    key_gen_verifier: Address,
    threshold: U256,
    num_peers: U256,
) -> eyre::Result<Address> {
    // // Step 1: Deploy VerifierKeyGen13 contract (no dependencies)
    // let key_gen_verifier = VerifierKeyGen13::deploy(provider.clone())
    //     .await
    //     .context("failed to deploy Groth16VerifierKeyGen13 contract")?;

    let babyjubjub = BabyJubJub::deploy(provider.clone())
        .await
        .context("failed to deploy BabyJubJub contract")?;

    let oprf_key_registry = OprfKeyRegistry::deploy(provider.clone())
        .await
        .context("failed to deploy OprfKeyRegistry contract")?;

    let init_data = Bytes::from(
        OprfKeyRegistry::initializeCall {
            _keygenAdmin: admin,
            _keyGenVerifierAddress: key_gen_verifier,
            _accumulatorAddress: *babyjubjub.address(),
            _threshold: threshold,
            _numPeers: num_peers,
        }
        .abi_encode(),
    );

    let proxy = ERC1967Proxy::deploy(provider, *oprf_key_registry.address(), init_data)
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

    deploy_oprf_key_registry(
        provider,
        admin,
        *key_gen_verifier.address(),
        uint!(2_U256),
        uint!(3_U256),
    )
    .await
}

/// Deploys the `OprfKeyRegistry` contract using the supplied signer.
pub async fn deploy_oprf_key_registry_25(
    provider: DynProvider,
    admin: Address,
) -> eyre::Result<Address> {
    let key_gen_verifier = VerifierKeyGen25::deploy(provider.clone())
        .await
        .context("failed to deploy Groth16VerifierKeyGen25 contract")?;

    deploy_oprf_key_registry(
        provider,
        admin,
        *key_gen_verifier.address(),
        uint!(3_U256),
        uint!(5_U256),
    )
    .await
}

/// Registers the oprf nodes at the `OprfKeyRegistry`.
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
        eyre::bail!("failed to init oprf key gen");
    }
    Ok(())
}

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

pub async fn delete_oprf_key_material(
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
        eyre::bail!("failed to delete OPRF pk");
    }
    Ok(())
}
