use std::{path::PathBuf, str::FromStr as _};

use crate::{
    PEER_ADDRESSES, PEER_PRIVATE_KEYS, TACEO_ADMIN_ADDRESS, deploy_anvil::TACEO_ADMIN_PRIVATE_KEY,
    oprf_key_registry,
};
use alloy::{
    eips::BlockNumberOrTag,
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, FixedBytes},
    providers::{DynProvider, Provider as _, ProviderBuilder, ext::AnvilApi},
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
};
use eyre::Context as _;
use futures::StreamExt as _;
use itertools::Itertools;
use oprf_types::{OprfKeyId, ShareEpoch};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploySetup {
    TwoThree,
    ThreeFive,
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

    pub fn addresses(&self) -> Vec<Address> {
        let take = match self {
            DeploySetup::TwoThree => 3,
            DeploySetup::ThreeFive => 5,
        };
        PEER_ADDRESSES.iter().take(take).cloned().collect_vec()
    }

    pub fn private_keys(&self) -> Vec<&str> {
        let take = match self {
            DeploySetup::TwoThree => 3,
            DeploySetup::ThreeFive => 5,
        };
        PEER_PRIVATE_KEYS.iter().take(take).cloned().collect_vec()
    }
}

pub struct TestSetup {
    pub anvil: AnvilInstance,
    pub provider: DynProvider,
    pub oprf_key_registry: Address,
    pub cancellation_token: CancellationToken,
    pub setup: DeploySetup,
    pub mine_strategy: MineStrategy,
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
        let private_key = PrivateKeySigner::from_str(TACEO_ADMIN_PRIVATE_KEY)?;
        let wallet = EthereumWallet::from(private_key);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(&anvil.ws_endpoint())
            .await
            .context("while connecting to RPC")?
            .erased();

        let oprf_key_registry = match setup {
            DeploySetup::TwoThree => {
                crate::deploy_oprf_key_registry_13(provider.clone(), TACEO_ADMIN_ADDRESS).await?
            }
            DeploySetup::ThreeFive => {
                crate::deploy_oprf_key_registry_25(provider.clone(), TACEO_ADMIN_ADDRESS).await?
            }
        };
        crate::register_oprf_nodes(provider.clone(), oprf_key_registry, setup.addresses()).await?;
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
        })
    }

    pub async fn delete_oprf_key(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        crate::emit_delete_event(self.provider.clone(), self.oprf_key_registry, oprf_key_id).await
    }

    pub async fn finalize_keygen(
        &self,
        oprf_key_id: OprfKeyId,
        share_epoch: ShareEpoch,
    ) -> eyre::Result<()> {
        crate::emit_secret_gen_finalize(
            self.provider.clone(),
            self.oprf_key_registry,
            oprf_key_id,
            share_epoch,
        )
        .await
    }

    pub async fn init_keygen(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        oprf_key_registry::init_key_gen(self.provider.clone(), self.oprf_key_registry, oprf_key_id)
            .await
    }

    pub async fn init_reshare(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        oprf_key_registry::init_reshare(self.provider.clone(), self.oprf_key_registry, oprf_key_id)
            .await
    }

    pub async fn abort_keygen(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        oprf_key_registry::init_abort(self.provider.clone(), self.oprf_key_registry, oprf_key_id)
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
            let observed = tokio::time::timeout(crate::TEST_TIMEOUT, async {
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
