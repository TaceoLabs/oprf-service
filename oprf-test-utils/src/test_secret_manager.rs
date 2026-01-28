use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use alloy::{primitives::U160, signers::local::PrivateKeySigner};
use ark_ff::UniformRand;
use async_trait::async_trait;
use itertools::Itertools;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_service::oprf_key_material_store::OprfKeyMaterialStore;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    crypto::{OprfKeyMaterial, OprfPublicKey},
};
use parking_lot::Mutex;
use rand::{CryptoRng, Rng};

use crate::TEST_TIMEOUT;

#[derive(Default, Clone)]
pub struct TestSecretManager {
    pub wallet_private_key: Option<PrivateKeySigner>,
    pub store: Arc<Mutex<HashMap<OprfKeyId, OprfKeyMaterial>>>,
}

impl TestSecretManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_private_key(wallet_private_key: &str) -> Self {
        Self {
            wallet_private_key: Some(
                PrivateKeySigner::from_str(wallet_private_key).expect("valid private key"),
            ),
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn clear(&self) {
        self.store.lock().clear();
    }

    pub fn take(&self) -> HashMap<OprfKeyId, OprfKeyMaterial> {
        let mut old_store = self.store.lock();
        let cloned = old_store.clone();
        old_store.clear();
        cloned
    }

    pub fn put(&self, map: HashMap<OprfKeyId, OprfKeyMaterial>) {
        self.store.lock().extend(map);
    }

    pub fn add_random_key_material<R: Rng + CryptoRng>(&self, rng: &mut R) -> OprfKeyId {
        // need to generate usize because rust-analyzer is unhappy with generating U160
        let oprf_key_id = OprfKeyId::new(U160::from(rng.r#gen::<usize>()));
        let mut shares = BTreeMap::new();
        let epoch = ShareEpoch::default();
        shares.insert(epoch, DLogShareShamir::from(ark_babyjubjub::Fr::rand(rng)));
        let key_material = OprfKeyMaterial::new(shares, OprfPublicKey::new(rng.r#gen()));
        self.store.lock().insert(oprf_key_id, key_material);
        oprf_key_id
    }

    pub fn get_key_material(&self, oprf_key_id: OprfKeyId) -> Option<OprfKeyMaterial> {
        self.store.lock().get(&oprf_key_id).cloned()
    }

    pub async fn is_key_id_stored(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> eyre::Result<OprfPublicKey> {
        let public_key = tokio::time::timeout(TEST_TIMEOUT, async move {
            loop {
                if let Some(key_material) = self.get_key_material(oprf_key_id)
                    && key_material.get_latest_epoch().unwrap() == epoch
                {
                    break key_material.get_oprf_public_key();
                } else {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        })
        .await?;
        Ok(public_key)
    }

    pub async fn is_key_id_not_stored(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        tokio::time::timeout(TEST_TIMEOUT, async move {
            loop {
                if self.get_key_material(oprf_key_id).is_none() {
                    break;
                } else {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        })
        .await?;
        Ok(())
    }

    pub fn load_key_ids(&self) -> Vec<OprfKeyId> {
        self.store.lock().keys().copied().collect_vec()
    }
}

#[async_trait]
impl oprf_key_gen::secret_manager::SecretManager for TestSecretManager {
    async fn load_or_insert_wallet_private_key(&self) -> eyre::Result<PrivateKeySigner> {
        Ok(self
            .wallet_private_key
            .clone()
            .expect("Cannot provide private key for this test run"))
    }

    async fn get_previous_share(
        &self,
        oprf_key_id: OprfKeyId,
        generated_epoch: ShareEpoch,
    ) -> eyre::Result<Option<DLogShareShamir>> {
        let store = self.store.lock();
        if let Some(oprf_key_material) = store.get(&oprf_key_id)
            && let Some((stored_epoch, share)) = oprf_key_material.get_latest_share()
        {
            tracing::debug!("my latest epoch is: {stored_epoch}");
            if stored_epoch.next() == generated_epoch {
                Ok(Some(share))
            } else {
                tracing::debug!("we missed an epoch - returning None");
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn remove_oprf_key_material(&self, rp_id: OprfKeyId) -> eyre::Result<()> {
        if self.store.lock().remove(&rp_id).is_none() {
            panic!("trying to remove oprf_key_id that does not exist");
        }
        Ok(())
    }

    async fn store_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        public_key: OprfPublicKey,
        epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> eyre::Result<()> {
        let mut store = self.store.lock();
        if epoch.is_initial_epoch() || !store.contains_key(&oprf_key_id) {
            assert!(
                store
                    .insert(
                        oprf_key_id,
                        OprfKeyMaterial::new(BTreeMap::from([(epoch, share)]), public_key,)
                    )
                    .is_none(),
                "On initial epoch, secret-manager must be empty"
            )
        } else {
            store
                .get_mut(&oprf_key_id)
                .expect("Checked above")
                .insert_share(epoch, share);
        }
        Ok(())
    }
}

#[async_trait]
impl oprf_service::secret_manager::SecretManager for TestSecretManager {
    async fn load_secrets(&self) -> eyre::Result<OprfKeyMaterialStore> {
        Ok(OprfKeyMaterialStore::new(self.store.lock().clone()))
    }

    async fn get_oprf_key_material(&self, oprf_key_id: OprfKeyId) -> eyre::Result<OprfKeyMaterial> {
        self.store
            .lock()
            .get(&oprf_key_id)
            .cloned()
            .ok_or_else(|| eyre::eyre!("oprf_key_id {oprf_key_id} not found"))
    }
}
