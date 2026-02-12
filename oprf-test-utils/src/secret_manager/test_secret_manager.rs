use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};

use alloy::{primitives::Address, signers::local::PrivateKeySigner};
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

#[macro_export]
macro_rules! key_gen_test_secret_manager {
    ($trait: path, $name: ident) => {
        mod impl_secret_manager {
            use $crate::alloy::signers::local::PrivateKeySigner;
            use $crate::async_trait::async_trait;
            use $crate::eyre::Context;
            use $crate::oprf_core::ddlog_equality::shamir::DLogShareShamir;
            use $crate::oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};

            // need a new type to implement the trait
            pub struct $name(pub std::sync::Arc<$crate::test_secret_manager::TestSecretManager>);

            #[async_trait]
            impl $trait for $name {
                async fn load_or_insert_wallet_private_key(
                    &self,
                ) -> eyre::Result<PrivateKeySigner> {
                    self.0.load_or_insert_wallet_private_key().await
                }

                async fn ping(&self) -> eyre::Result<()> {
                    // noop
                    Ok(())
                }

                async fn get_share_by_epoch(
                    &self,
                    oprf_key_id: OprfKeyId,
                    generated_epoch: ShareEpoch,
                ) -> eyre::Result<Option<DLogShareShamir>> {
                    self.0
                        .get_share_by_epoch(oprf_key_id, generated_epoch)
                        .await
                }

                async fn remove_oprf_key_material(&self, rp_id: OprfKeyId) -> eyre::Result<()> {
                    self.0
                        .remove_oprf_key_material(rp_id)
                        .await
                        .context("while remove oprf key material")?;
                    Ok(())
                }

                async fn store_dlog_share(
                    &self,
                    oprf_key_id: OprfKeyId,
                    public_key: OprfPublicKey,
                    epoch: ShareEpoch,
                    share: DLogShareShamir,
                ) -> eyre::Result<()> {
                    self.0
                        .store_dlog_share(oprf_key_id, public_key, epoch, share)
                        .await
                        .context("while store DlogShare")?;
                    Ok(())
                }
            }
        }
        use impl_secret_manager::$name;
    };
}

#[macro_export]
macro_rules! oprf_node_test_secret_manager {
    ($module: path, $name: ident) => {
        mod impl_secret_manager {
            use $crate::alloy::primitives::Address;
            use $crate::async_trait::async_trait;
            use $crate::oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfKeyMaterial};
            use $module::{GetOprfKeyMaterialError, SecretManager};

            // need a new type to implement the trait
            pub struct $name(pub std::sync::Arc<$crate::test_secret_manager::TestSecretManager>);

            #[async_trait]
            impl SecretManager for $name {
                async fn load_address(&self) -> eyre::Result<Address> {
                    self.0.load_address().await
                }

                async fn load_secrets(
                    &self,
                ) -> eyre::Result<std::collections::HashMap<OprfKeyId, OprfKeyMaterial>> {
                    Ok(self.0.store.lock().clone())
                }

                async fn get_oprf_key_material(
                    &self,
                    oprf_key_id: OprfKeyId,
                    epoch: ShareEpoch,
                ) -> Result<OprfKeyMaterial, GetOprfKeyMaterialError> {
                    self.0
                        .get_oprf_key_material(oprf_key_id, epoch)
                        .await?
                        .ok_or(GetOprfKeyMaterialError::NotFound)
                }
            }
        }
        use impl_secret_manager::$name;
    };
}

#[derive(Clone)]
pub struct TestSecretManager {
    pub wallet_private_key: PrivateKeySigner,
    pub store: Arc<Mutex<HashMap<OprfKeyId, OprfKeyMaterial>>>,
}

impl TestSecretManager {
    pub fn new(wallet_private_key: &str) -> Self {
        Self {
            wallet_private_key: PrivateKeySigner::from_str(wallet_private_key)
                .expect("valid private key"),
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

    pub fn add_random_key_material_with_epoch<R: Rng + CryptoRng>(
        &self,
        epoch: ShareEpoch,
        rng: &mut R,
    ) -> OprfKeyId {
        let oprf_key_id = OprfKeyId::from(rng.r#gen::<usize>());
        self.add_random_key_material_with_id_epoch(oprf_key_id, epoch, rng);
        oprf_key_id
    }

    pub fn add_random_key_material<R: Rng + CryptoRng>(&self, rng: &mut R) -> OprfKeyId {
        let oprf_key_id = OprfKeyId::from(rng.r#gen::<usize>());
        self.add_random_key_material_with_id(oprf_key_id, rng);
        oprf_key_id
    }

    pub fn add_random_key_material_with_id<R: Rng + CryptoRng>(
        &self,
        oprf_key_id: OprfKeyId,
        rng: &mut R,
    ) {
        self.add_random_key_material_with_id_epoch(oprf_key_id, ShareEpoch::default(), rng);
    }

    pub fn add_random_key_material_with_id_epoch<R: Rng + CryptoRng>(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        rng: &mut R,
    ) {
        let share = DLogShareShamir::from(ark_babyjubjub::Fr::rand(rng));
        let key_material = OprfKeyMaterial::new(share, OprfPublicKey::new(rng.r#gen()), epoch);
        self.store.lock().insert(oprf_key_id, key_material);
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
                    && key_material.is_epoch(epoch)
                {
                    break key_material.public_key();
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

    pub async fn load_or_insert_wallet_private_key(&self) -> eyre::Result<PrivateKeySigner> {
        Ok(self.wallet_private_key.clone())
    }

    pub async fn get_share_by_epoch(
        &self,
        oprf_key_id: OprfKeyId,
        generated_epoch: ShareEpoch,
    ) -> eyre::Result<Option<DLogShareShamir>> {
        let store = self.store.lock();
        if let Some(oprf_key_material) = store.get(&oprf_key_id)
            && oprf_key_material.is_epoch(generated_epoch)
        {
            Ok(Some(oprf_key_material.share()))
        } else {
            Ok(None)
        }
    }

    pub async fn remove_oprf_key_material(&self, rp_id: OprfKeyId) -> eyre::Result<()> {
        if self.store.lock().remove(&rp_id).is_none() {
            panic!("trying to remove oprf_key_id that does not exist");
        }
        Ok(())
    }

    pub async fn store_dlog_share(
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
                    .insert(oprf_key_id, OprfKeyMaterial::new(share, public_key, epoch))
                    .is_none(),
                "On initial epoch, secret-manager must be empty"
            )
        } else {
            store.insert(oprf_key_id, OprfKeyMaterial::new(share, public_key, epoch));
        }
        Ok(())
    }

    pub async fn load_address(&self) -> eyre::Result<Address> {
        Ok(self.wallet_private_key.address())
    }

    pub async fn get_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> eyre::Result<Option<OprfKeyMaterial>> {
        let key_material_epoch = self.store.lock().get(&oprf_key_id).cloned();
        if let Some(key_material) = key_material_epoch
            && key_material.is_epoch(epoch)
        {
            Ok(Some(key_material))
        } else {
            Ok(None)
        }
    }
}
