use std::{num::NonZeroU16, path::PathBuf};

use alloy::{
    eips::BlockNumberOrTag,
    hex,
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, FixedBytes},
    providers::{DynProvider, Provider as _, ProviderBuilder, ext::AnvilApi},
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
};
use eyre::Context as _;
use futures::StreamExt as _;
use sqlx::PgPool;
use taceo_oprf::core::ddlog_equality::shamir::DLogShareShamir;
use taceo_oprf::types::OprfKeyId;
use taceo_oprf::types::{ShareEpoch, crypto::OprfPublicKey};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::{TEST_TIMEOUT, to_db_ark_serialize_uncompressed};

/// Upper bound on the number of peers any [`DeploySetup`] registers, and the
/// number of peer key/address slots [`TestSetup`] derives from Anvil.
const MAX_PEERS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploySetup {
    TwoThree,
    ThreeFive,
}

pub(crate) async fn insert_key_material(
    pool: &PgPool,
    key_id: OprfKeyId,
    epoch: ShareEpoch,
    share: DLogShareShamir,
    public_key: OprfPublicKey,
) -> eyre::Result<()> {
    sqlx::query(
        "
        INSERT INTO shares (id, share, epoch, public_key)
        VALUES ($1, $2, $3, $4)
    ",
    )
    .bind(key_id.to_le_bytes())
    .bind(to_db_ark_serialize_uncompressed(&share).as_slice())
    .bind(i64::from(epoch))
    .bind(to_db_ark_serialize_uncompressed(&public_key).as_slice())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_key_material(pool: &PgPool, key_id: OprfKeyId) -> eyre::Result<()> {
    let success = sqlx::query(
        "
            UPDATE shares
            SET
                share = NULL,
                deleted = true
            WHERE id = $1
        ",
    )
    .bind(key_id.to_le_bytes())
    .execute(pool)
    .await
    .context("while deleting key material in DB")?;
    if success.rows_affected() == 1 {
        Ok(())
    } else {
        Err(eyre::eyre!("No row found to delete for key_id {key_id:?}"))
    }
}

impl DeploySetup {
    pub fn key_gen_path(&self) -> PathBuf {
        let file = match self {
            DeploySetup::TwoThree => "OPRFKeyGen.13.arks.zkey",
            DeploySetup::ThreeFive => "OPRFKeyGen.25.arks.zkey",
        };
        let path = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));
        path.join(format!("../artifacts/{file}"))
    }

    pub fn witness_path(&self) -> PathBuf {
        let file = match self {
            DeploySetup::TwoThree => "OPRFKeyGenGraph.13.bin",
            DeploySetup::ThreeFive => "OPRFKeyGenGraph.25.bin",
        };
        let path = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));
        path.join(format!("../artifacts/{file}"))
    }

    pub fn num_peers(&self) -> usize {
        match self {
            DeploySetup::TwoThree => 3,
            DeploySetup::ThreeFive => 5,
        }
    }

    pub fn threshold(&self) -> NonZeroU16 {
        match self {
            DeploySetup::TwoThree => NonZeroU16::new(2).expect("2 is non-zero"),
            DeploySetup::ThreeFive => NonZeroU16::new(3).expect("3 is non-zero"),
        }
    }
}

pub struct TestSetup {
    pub anvil: AnvilInstance,
    pub provider: DynProvider,
    pub oprf_key_registry: Address,
    pub cancellation_token: CancellationToken,
    pub setup: DeploySetup,
    pub mine_strategy: MineStrategy,
    /// Anvil's default dev account 0, used as the `OprfKeyRegistry` admin.
    pub admin_address: Address,
    /// Anvil's default dev accounts `1..=n`, registered as OPRF peers.
    pub peer_addresses: Vec<Address>,
    /// Hex-encoded private keys matching [`Self::peer_addresses`].
    pub peer_private_keys: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MineStrategy {
    Auto,
    Interval(u64),
}

impl TestSetup {
    pub async fn new(setup: DeploySetup) -> eyre::Result<TestSetup> {
        Self::with_mine_strategy(setup, MineStrategy::Auto).await
    }

    pub async fn with_mine_strategy(
        setup: DeploySetup,
        mine_strategy: MineStrategy,
    ) -> eyre::Result<TestSetup> {
        let anvil = Anvil::new().spawn();

        let admin_address = anvil.addresses()[0];
        let peer_addresses = anvil.addresses()[1..=MAX_PEERS].to_vec();
        let peer_private_keys = anvil.keys()[1..=MAX_PEERS]
            .iter()
            .map(|key| format!("0x{}", hex::encode(key.to_bytes())))
            .collect();

        let admin_signer = PrivateKeySigner::from(&anvil.keys()[0]);
        let wallet = EthereumWallet::from(admin_signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(&anvil.ws_endpoint())
            .await
            .context("while connecting to RPC")?
            .erased();

        let oprf_key_registry = match setup {
            DeploySetup::TwoThree => {
                taceo_oprf::anvil::deploy_oprf_key_registry_13(provider.clone(), admin_address)
                    .await?
            }
            DeploySetup::ThreeFive => {
                taceo_oprf::anvil::deploy_oprf_key_registry_25(provider.clone(), admin_address)
                    .await?
            }
        };
        taceo_oprf::anvil::register_oprf_nodes(
            provider.clone(),
            oprf_key_registry,
            peer_addresses[..setup.num_peers()].to_vec(),
        )
        .await?;
        let cancellation_token = CancellationToken::new();
        // default is Auto
        if let MineStrategy::Interval(secs) = mine_strategy {
            provider
                .anvil_set_interval_mining(secs)
                .await
                .context("while setting interval mining")?;
        }
        Ok(TestSetup {
            anvil,
            provider,
            oprf_key_registry,
            cancellation_token,
            mine_strategy,
            setup,
            admin_address,
            peer_addresses,
            peer_private_keys,
        })
    }

    pub async fn delete_oprf_key(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        taceo_oprf::anvil::init_delete(self.provider.clone(), self.oprf_key_registry, oprf_key_id)
            .await
    }

    pub async fn init_keygen(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        taceo_oprf::anvil::init_key_gen(self.provider.clone(), self.oprf_key_registry, oprf_key_id)
            .await
    }

    pub async fn init_reshare(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        taceo_oprf::anvil::init_reshare(self.provider.clone(), self.oprf_key_registry, oprf_key_id)
            .await
    }

    pub async fn expect_event(
        &self,
        signature_hash: FixedBytes<32>,
        times: usize,
    ) -> eyre::Result<oneshot::Receiver<()>> {
        let filter = Filter::new()
            .address(self.oprf_key_registry)
            .from_block(BlockNumberOrTag::Latest)
            .event_signature(vec![signature_hash]);
        let sub = self.provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn(async move {
            let observed = tokio::time::timeout(TEST_TIMEOUT, async {
                let mut count = 0;
                while stream.next().await.is_some() {
                    count += 1;
                    if count >= times {
                        return true;
                    }
                }
                false
            })
            .await;

            if observed == Ok(true) {
                let _ = tx.send(());
            }
        });
        Ok(rx)
    }
}
