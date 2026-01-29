use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use alloy::{primitives::U160, signers::local::PrivateKeySigner};
use ark_ff::UniformRand;
use itertools::Itertools;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
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
