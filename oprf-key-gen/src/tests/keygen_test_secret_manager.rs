use std::{collections::HashMap, sync::Arc, time::Duration};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use nodes_common::web3::event_stream::ChainCursor;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_test_utils::{TEST_TIMEOUT, test_secret_manager::TestSecretManager};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    crypto::{OprfKeyMaterial, OprfPublicKey},
};
use parking_lot::Mutex;
use rand::{CryptoRng, Rng};

use crate::{
    event_cursor_store::ChainCursorStorage,
    secret_manager::{KeyGenIntermediateValues, SecretManager, SecretManagerError},
};

struct TestKeyGenSecretManagerState {
    base: TestSecretManager,
    keygen_intermediates: HashMap<(OprfKeyId, ShareEpoch), Vec<u8>>,
    pending_shares: HashMap<(OprfKeyId, ShareEpoch), DLogShareShamir>,
    deleted_keys: HashMap<OprfKeyId, ShareEpoch>,
}

#[derive(Clone, Default)]
pub(crate) struct TestChainCursorService(Arc<Mutex<ChainCursor>>);

#[derive(Clone)]
pub(crate) struct TestKeyGenSecretManager(Arc<Mutex<TestKeyGenSecretManagerState>>);

impl TestChainCursorService {
    pub(crate) fn with_cursor(cursor: ChainCursor) -> Self {
        Self(Arc::new(Mutex::new(cursor)))
    }

    pub(crate) fn service(&self) -> crate::ChainCursorService {
        Arc::new(self.clone())
    }
}

#[async_trait]
impl ChainCursorStorage for TestChainCursorService {
    async fn load_chain_cursor(&self) -> eyre::Result<ChainCursor> {
        Ok(*self.0.lock())
    }

    async fn store_chain_cursor(&self, chain_cursor: ChainCursor) -> eyre::Result<()> {
        let mut stored_cursor = self.0.lock();
        if stored_cursor.is_before(chain_cursor) {
            *stored_cursor = chain_cursor;
        }
        Ok(())
    }
}

impl TestKeyGenSecretManager {
    pub(crate) fn new(wallet_private_key: &str) -> Self {
        Self(Arc::new(Mutex::new(TestKeyGenSecretManagerState {
            base: TestSecretManager::new(wallet_private_key),
            keygen_intermediates: HashMap::new(),
            pending_shares: HashMap::new(),
            deleted_keys: HashMap::new(),
        })))
    }

    pub(crate) fn service(&self) -> crate::secret_manager::SecretManagerService {
        Arc::new(self.clone())
    }

    fn clear_in_progress_state(state: &mut TestKeyGenSecretManagerState, oprf_key_id: OprfKeyId) {
        state
            .keygen_intermediates
            .retain(|(key_id, _), _| *key_id != oprf_key_id);
        state
            .pending_shares
            .retain(|(key_id, _), _| *key_id != oprf_key_id);
    }

    fn serialize_intermediates(
        intermediate: &KeyGenIntermediateValues,
    ) -> Result<Vec<u8>, SecretManagerError> {
        let mut bytes = Vec::with_capacity(intermediate.uncompressed_size());
        intermediate
            .serialize_uncompressed(&mut bytes)
            .map_err(|error| SecretManagerError::Internal(eyre::eyre!(error)))?;
        Ok(bytes)
    }

    fn deserialize_intermediates(
        bytes: &[u8],
    ) -> Result<KeyGenIntermediateValues, SecretManagerError> {
        KeyGenIntermediateValues::deserialize_uncompressed(bytes)
            .map_err(|error| SecretManagerError::Internal(eyre::eyre!(error)))
    }

    pub(crate) fn clear(&self) {
        self.0.lock().base.clear();
    }

    pub(crate) fn take(&self) -> HashMap<OprfKeyId, OprfKeyMaterial> {
        self.0.lock().base.take()
    }

    pub(crate) fn put(&self, map: HashMap<OprfKeyId, OprfKeyMaterial>) {
        self.0.lock().base.put(map);
    }

    pub(crate) fn add_random_key_material<R: Rng + CryptoRng>(&self, rng: &mut R) -> OprfKeyId {
        self.0.lock().base.add_random_key_material(rng)
    }

    pub(crate) fn add_random_key_material_with_id_epoch<R: Rng + CryptoRng>(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        rng: &mut R,
    ) {
        self.0
            .lock()
            .base
            .add_random_key_material_with_id_epoch(oprf_key_id, epoch, rng);
    }

    pub(crate) fn get_key_material(&self, oprf_key_id: OprfKeyId) -> Option<OprfKeyMaterial> {
        self.0.lock().base.get_key_material(oprf_key_id)
    }

    pub(crate) async fn is_key_id_stored(
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
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await?;
        Ok(public_key)
    }

    pub(crate) async fn is_key_id_not_stored(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        let this = self.clone();
        tokio::time::timeout(TEST_TIMEOUT, async move {
            loop {
                if this.get_key_material(oprf_key_id).is_none() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await?;
        Ok(())
    }
}

#[async_trait]
impl SecretManager for TestKeyGenSecretManager {
    async fn store_wallet_address(&self, address: String) -> Result<(), SecretManagerError> {
        self.0.lock().base.store_wallet_address(address);
        Ok(())
    }

    async fn get_share_by_epoch(
        &self,
        oprf_key_id: OprfKeyId,
        generated_epoch: ShareEpoch,
    ) -> Result<Option<DLogShareShamir>, SecretManagerError> {
        Ok(self
            .0
            .lock()
            .base
            .get_share_by_epoch(oprf_key_id, generated_epoch))
    }

    async fn delete_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> Result<(), SecretManagerError> {
        let mut state = self.0.lock();
        let removed_epoch = state
            .base
            .remove_key_material(oprf_key_id)
            .map(|share| share.epoch());
        if let Some(epoch) = removed_epoch {
            state.deleted_keys.insert(oprf_key_id, epoch);
        }
        Self::clear_in_progress_state(&mut state, oprf_key_id);
        Ok(())
    }

    async fn abort_keygen(&self, oprf_key_id: OprfKeyId) -> Result<(), SecretManagerError> {
        let mut state = self.0.lock();
        Self::clear_in_progress_state(&mut state, oprf_key_id);
        Ok(())
    }

    async fn try_store_keygen_intermediates(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        intermediate: KeyGenIntermediateValues,
    ) -> Result<KeyGenIntermediateValues, SecretManagerError> {
        let mut state = self.0.lock();
        let serialized = Self::serialize_intermediates(&intermediate)?;
        Self::deserialize_intermediates(
            state
                .keygen_intermediates
                .entry((oprf_key_id, pending_epoch))
                .or_insert(serialized),
        )
    }

    async fn fetch_keygen_intermediates(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
    ) -> Result<Option<KeyGenIntermediateValues>, SecretManagerError> {
        let state = self.0.lock();
        state
            .keygen_intermediates
            .get(&(oprf_key_id, pending_epoch))
            .map(|bytes| Self::deserialize_intermediates(bytes))
            .transpose()
    }

    async fn store_pending_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> Result<(), SecretManagerError> {
        let mut state = self.0.lock();
        if !state
            .keygen_intermediates
            .contains_key(&(oprf_key_id, pending_epoch))
        {
            return Err(SecretManagerError::MissingIntermediates(
                oprf_key_id,
                pending_epoch,
            ));
        }

        state
            .pending_shares
            .insert((oprf_key_id, pending_epoch), share);
        Ok(())
    }

    async fn confirm_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        public_key: OprfPublicKey,
    ) -> Result<(), SecretManagerError> {
        let mut state = self.0.lock();

        if let Some(existing) = state.base.get_key_material(oprf_key_id) {
            if existing.epoch() == epoch {
                Self::clear_in_progress_state(&mut state, oprf_key_id);
                return Ok(());
            }
            if existing.epoch() > epoch {
                return Err(SecretManagerError::RefusingToRollbackEpoch);
            }
        }

        let share = state
            .pending_shares
            .get(&(oprf_key_id, epoch))
            .cloned()
            .ok_or(SecretManagerError::MissingIntermediates(oprf_key_id, epoch))?;

        if let Some(deleted_epoch) = state.deleted_keys.get(&oprf_key_id).copied() {
            return if deleted_epoch < epoch {
                Err(SecretManagerError::StoreOnDeletedShare)
            } else {
                Err(SecretManagerError::RefusingToRollbackEpoch)
            };
        }

        state
            .base
            .insert_key_material(oprf_key_id, OprfKeyMaterial::new(share, public_key, epoch));
        Self::clear_in_progress_state(&mut state, oprf_key_id);
        Ok(())
    }
}
