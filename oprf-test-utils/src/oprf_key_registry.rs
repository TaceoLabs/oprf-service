use alloy::{primitives::Address, providers::DynProvider};
#[cfg(feature = "deploy-anvil")]
use oprf_types::ShareEpoch;
use oprf_types::{OprfKeyId, chain::OprfKeyRegistry};

#[cfg(feature = "deploy-anvil")]
use crate::TestOprfKeyRegistry;

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

pub async fn abort_key_gen(
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

#[cfg(feature = "deploy-anvil")]
pub async fn emit_delete_event(
    provider: DynProvider,
    oprf_key_registry: Address,
    oprf_key_id: OprfKeyId,
) -> eyre::Result<()> {
    let oprf_key_registry = TestOprfKeyRegistry::new(oprf_key_registry, provider);
    let receipt = oprf_key_registry
        .emitDeleteEvent(oprf_key_id.into_inner())
        .send()
        .await?
        .get_receipt()
        .await?;
    if !receipt.status() {
        eyre::bail!("could not emit delete event");
    }
    Ok(())
}

#[cfg(feature = "deploy-anvil")]
pub async fn emit_secret_gen_finalize(
    provider: DynProvider,
    oprf_key_registry: Address,
    oprf_key_id: OprfKeyId,
    epoch: ShareEpoch,
) -> eyre::Result<()> {
    let oprf_key_registry = TestOprfKeyRegistry::new(oprf_key_registry, provider);
    let receipt = oprf_key_registry
        .emitSecretGenFinalize(oprf_key_id.into_inner(), epoch.into_inner())
        .send()
        .await?
        .get_receipt()
        .await?;
    if !receipt.status() {
        eyre::bail!("could not emit secret-gen finalize");
    }
    Ok(())
}
