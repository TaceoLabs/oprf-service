use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
    sync::Arc,
};

use alloy::signers::local::PrivateKeySigner;
use async_trait::async_trait;
use itertools::Itertools;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_service::oprf_key_material_store::OprfKeyMaterialStore;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    crypto::{OprfKeyMaterial, OprfPublicKey},
};
use parking_lot::Mutex;

pub const SECRET_MAX_CACHE_SIZE: u8 = 2;

#[derive(Clone)]
pub struct TestSecretManager {
    wallet_private_key: PrivateKeySigner,
    store: Arc<Mutex<HashMap<OprfKeyId, OprfKeyMaterial>>>,
}

impl TestSecretManager {
    pub fn new(wallet_private_key: &str) -> Self {
        Self {
            wallet_private_key: PrivateKeySigner::from_str(wallet_private_key)
                .expect("valid private key"),
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn load_key_ids(&self) -> Vec<OprfKeyId> {
        self.store.lock().keys().copied().collect_vec()
    }
}

#[async_trait]
impl oprf_key_gen::secret_manager::SecretManager for TestSecretManager {
    async fn load_or_insert_wallet_private_key(&self) -> eyre::Result<PrivateKeySigner> {
        Ok(self.wallet_private_key.clone())
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
                        OprfKeyMaterial::new(
                            BTreeMap::from([(epoch, share)]),
                            public_key,
                            usize::from(SECRET_MAX_CACHE_SIZE)
                        )
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
        Ok(OprfKeyMaterialStore::default())
    }

    async fn get_oprf_key_material(&self, oprf_key_id: OprfKeyId) -> eyre::Result<OprfKeyMaterial> {
        self.store
            .lock()
            .get(&oprf_key_id)
            .cloned()
            .ok_or_else(|| eyre::eyre!("oprf_key_id {oprf_key_id} not found"))
    }
}
