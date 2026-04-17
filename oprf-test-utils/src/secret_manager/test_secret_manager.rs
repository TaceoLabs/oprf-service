use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};

use alloy::{hex, primitives::Address, signers::local::PrivateKeySigner};
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

#[derive(Clone)]
pub struct TestSecretManager(Arc<Mutex<TestSecretManagerInner>>);

struct TestSecretManagerInner {
    pub wallet_private_key: PrivateKeySigner,
    pub store: HashMap<OprfKeyId, OprfKeyMaterial>,
    pub pending_shares: HashMap<OprfKeyId, DLogShareShamir>,
}

impl TestSecretManager {
    fn inner<'a>(&'a self) -> parking_lot::MutexGuard<'a, TestSecretManagerInner> {
        self.0.lock()
    }

    pub fn new(wallet_private_key: &str) -> Self {
        Self(Arc::new(Mutex::new(TestSecretManagerInner {
            wallet_private_key: PrivateKeySigner::from_str(wallet_private_key)
                .expect("valid private key"),
            store: HashMap::new(),
            pending_shares: HashMap::new(),
        })))
    }

    pub fn wallet_private_key(&self) -> PrivateKeySigner {
        self.inner().wallet_private_key.clone()
    }

    pub fn wallet_private_key_hex_string(&self) -> String {
        let inner = self.inner();
        let private_key_bytes = inner.wallet_private_key.to_bytes();
        hex::encode_prefixed(private_key_bytes)
    }

    pub fn clear(&self) {
        self.inner().store.clear();
    }

    pub fn take(&self) -> HashMap<OprfKeyId, OprfKeyMaterial> {
        let mut inner = self.inner();
        let cloned = inner.store.clone();
        inner.store.clear();
        cloned
    }

    pub fn put(&self, map: HashMap<OprfKeyId, OprfKeyMaterial>) {
        self.inner().store.extend(map);
    }

    pub fn clone_key_materials(&self) -> HashMap<OprfKeyId, OprfKeyMaterial> {
        self.inner().store.clone()
    }

    pub fn insert_key_material(
        &self,
        oprf_key_id: OprfKeyId,
        key_material: OprfKeyMaterial,
    ) -> Option<OprfKeyMaterial> {
        self.inner().store.insert(oprf_key_id, key_material)
    }

    pub fn remove_key_material(&self, oprf_key_id: OprfKeyId) -> Option<OprfKeyMaterial> {
        self.inner().store.remove(&oprf_key_id)
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
        self.inner().store.insert(oprf_key_id, key_material);
    }

    pub fn get_key_material(&self, oprf_key_id: OprfKeyId) -> Option<OprfKeyMaterial> {
        self.inner().store.get(&oprf_key_id).cloned()
    }

    pub async fn is_key_id_stored(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> eyre::Result<OprfPublicKey> {
        let this = self.clone();
        let public_key = tokio::time::timeout(TEST_TIMEOUT, async move {
            loop {
                if let Some(key_material) = this.get_key_material(oprf_key_id)
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
        let this = self.clone();
        tokio::time::timeout(TEST_TIMEOUT, async move {
            loop {
                if this.get_key_material(oprf_key_id).is_none() {
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
        self.inner().store.keys().copied().collect_vec()
    }

    pub async fn get_share_by_epoch(
        &self,
        oprf_key_id: OprfKeyId,
        generated_epoch: ShareEpoch,
    ) -> eyre::Result<Option<DLogShareShamir>> {
        let inner = self.inner();
        if let Some(oprf_key_material) = inner.store.get(&oprf_key_id)
            && oprf_key_material.is_epoch(generated_epoch)
        {
            Ok(Some(oprf_key_material.share()))
        } else {
            Ok(None)
        }
    }

    pub async fn remove_oprf_key_material(&self, rp_id: OprfKeyId) -> eyre::Result<()> {
        if self.inner().store.remove(&rp_id).is_none() {
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
        let mut inner = self.inner();
        if epoch.is_initial_epoch() || !inner.store.contains_key(&oprf_key_id) {
            assert!(
                inner
                    .store
                    .insert(oprf_key_id, OprfKeyMaterial::new(share, public_key, epoch))
                    .is_none(),
                "On initial epoch, secret-manager must be empty"
            )
        } else {
            inner
                .store
                .insert(oprf_key_id, OprfKeyMaterial::new(share, public_key, epoch));
        }
        Ok(())
    }

    /// Clears all pending state (intermediates + pending share) for the given key ID.
    /// Does NOT remove confirmed shares.
    pub async fn abort_keygen(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        self.inner().pending_shares.remove(&oprf_key_id);
        Ok(())
    }

    /// Stores a pending (pre-finalization) share for the given key ID.
    pub async fn store_pending_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        share: DLogShareShamir,
    ) -> eyre::Result<()> {
        self.inner().pending_shares.insert(oprf_key_id, share);
        Ok(())
    }

    /// Confirms the pending share for the given key ID, making it the active share.
    ///
    /// Moves the pending share from `pending_shares` into `store`, paired with
    /// the provided epoch and public key.
    ///
    /// # Panics
    ///
    /// Panics if no pending share exists for `oprf_key_id`.
    pub async fn confirm_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        public_key: OprfPublicKey,
    ) -> eyre::Result<()> {
        let mut inner = self.inner();
        let share = inner
            .pending_shares
            .remove(&oprf_key_id)
            .expect("confirm_dlog_share called but no pending share exists for this key ID");
        inner
            .store
            .insert(oprf_key_id, OprfKeyMaterial::new(share, public_key, epoch));
        Ok(())
    }

    pub async fn load_address(&self) -> eyre::Result<Address> {
        Ok(self.inner().wallet_private_key.address())
    }

    pub async fn store_wallet_address(&self, address: String) -> eyre::Result<()> {
        // noop, since the test secret manager already has the wallet private key
        assert!(self.inner().wallet_private_key.address().to_string() == address);
        Ok(())
    }

    pub async fn get_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> eyre::Result<Option<OprfKeyMaterial>> {
        let inner = self.inner();
        let key_material = inner.store.get(&oprf_key_id).cloned();
        if let Some(key_material) = key_material
            && key_material.is_epoch(epoch)
        {
            Ok(Some(key_material))
        } else {
            Ok(None)
        }
    }
}
