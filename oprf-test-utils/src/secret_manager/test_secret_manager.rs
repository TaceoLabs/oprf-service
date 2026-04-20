use std::{collections::HashMap, str::FromStr};

use alloy::{hex, primitives::Address, signers::local::PrivateKeySigner};
use ark_ff::UniformRand;
use itertools::Itertools;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    crypto::{OprfKeyMaterial, OprfPublicKey},
};
use rand::{CryptoRng, Rng};

pub struct TestSecretManager {
    wallet_private_key: PrivateKeySigner,
    store: HashMap<OprfKeyId, OprfKeyMaterial>,
}

impl TestSecretManager {
    pub fn new(wallet_private_key: &str) -> Self {
        Self {
            wallet_private_key: PrivateKeySigner::from_str(wallet_private_key)
                .expect("valid private key"),
            store: HashMap::new(),
        }
    }

    pub fn wallet_private_key(&self) -> PrivateKeySigner {
        self.wallet_private_key.clone()
    }

    pub fn wallet_private_key_hex_string(&self) -> String {
        hex::encode_prefixed(self.wallet_private_key.to_bytes())
    }

    pub fn clear(&mut self) {
        self.store.clear();
    }

    pub fn take(&mut self) -> HashMap<OprfKeyId, OprfKeyMaterial> {
        std::mem::take(&mut self.store)
    }

    pub fn put(&mut self, map: HashMap<OprfKeyId, OprfKeyMaterial>) {
        self.store.extend(map);
    }

    pub fn clone_key_materials(&self) -> HashMap<OprfKeyId, OprfKeyMaterial> {
        self.store.clone()
    }

    pub fn insert_key_material(
        &mut self,
        oprf_key_id: OprfKeyId,
        key_material: OprfKeyMaterial,
    ) -> Option<OprfKeyMaterial> {
        self.store.insert(oprf_key_id, key_material)
    }

    pub fn remove_key_material(&mut self, oprf_key_id: OprfKeyId) -> Option<OprfKeyMaterial> {
        self.store.remove(&oprf_key_id)
    }

    pub fn add_random_key_material_with_epoch<R: Rng + CryptoRng>(
        &mut self,
        epoch: ShareEpoch,
        rng: &mut R,
    ) -> OprfKeyId {
        let oprf_key_id = OprfKeyId::from(rng.r#gen::<usize>());
        self.add_random_key_material_with_id_epoch(oprf_key_id, epoch, rng);
        oprf_key_id
    }

    pub fn add_random_key_material<R: Rng + CryptoRng>(&mut self, rng: &mut R) -> OprfKeyId {
        let oprf_key_id = OprfKeyId::from(rng.r#gen::<usize>());
        self.add_random_key_material_with_id(oprf_key_id, rng);
        oprf_key_id
    }

    pub fn add_random_key_material_with_id<R: Rng + CryptoRng>(
        &mut self,
        oprf_key_id: OprfKeyId,
        rng: &mut R,
    ) {
        self.add_random_key_material_with_id_epoch(oprf_key_id, ShareEpoch::default(), rng);
    }

    pub fn add_random_key_material_with_id_epoch<R: Rng + CryptoRng>(
        &mut self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        rng: &mut R,
    ) {
        let share = DLogShareShamir::from(ark_babyjubjub::Fr::rand(rng));
        let key_material = OprfKeyMaterial::new(share, OprfPublicKey::new(rng.r#gen()), epoch);
        self.store.insert(oprf_key_id, key_material);
    }

    pub fn get_key_material(&self, oprf_key_id: OprfKeyId) -> Option<OprfKeyMaterial> {
        self.store.get(&oprf_key_id).cloned()
    }

    pub fn load_key_ids(&self) -> Vec<OprfKeyId> {
        self.store.keys().copied().collect_vec()
    }

    pub fn get_share_by_epoch(
        &self,
        oprf_key_id: OprfKeyId,
        generated_epoch: ShareEpoch,
    ) -> Option<DLogShareShamir> {
        if let Some(oprf_key_material) = self.store.get(&oprf_key_id)
            && oprf_key_material.is_epoch(generated_epoch)
        {
            Some(oprf_key_material.share())
        } else {
            None
        }
    }

    pub fn remove_oprf_key_material(&mut self, rp_id: OprfKeyId) {
        assert!(
            self.store.remove(&rp_id).is_some(),
            "trying to remove oprf_key_id that does not exist"
        );
    }

    pub fn store_dlog_share(
        &mut self,
        oprf_key_id: OprfKeyId,
        public_key: OprfPublicKey,
        epoch: ShareEpoch,
        share: DLogShareShamir,
    ) {
        if epoch.is_initial_epoch() || !self.store.contains_key(&oprf_key_id) {
            assert!(
                self.store
                    .insert(oprf_key_id, OprfKeyMaterial::new(share, public_key, epoch))
                    .is_none(),
                "On initial epoch, secret-manager must be empty"
            );
        } else {
            self.store
                .insert(oprf_key_id, OprfKeyMaterial::new(share, public_key, epoch));
        }
    }

    pub fn load_address(&self) -> Address {
        self.wallet_private_key.address()
    }

    pub fn store_wallet_address(&self, address: String) {
        assert_eq!(self.wallet_private_key.address().to_string(), address);
    }

    pub fn get_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> Option<OprfKeyMaterial> {
        let key_material = self.store.get(&oprf_key_id).cloned();
        if let Some(key_material) = key_material
            && key_material.is_epoch(epoch)
        {
            Some(key_material)
        } else {
            None
        }
    }
}
