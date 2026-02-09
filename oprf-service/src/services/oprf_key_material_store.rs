//! This module provides [`OprfKeyMaterialStore`], which securely holds each OPRF DLog shares (per epoch).
//! Access is synchronized via a `RwLock` and wrapped in an `Arc` for thread-safe shared ownership.
//!
//! Use the store to retrieve or add shares and public keys safely.
//! Each OPRF key material is represented by [`OprfKeyMaterial`].

use oprf_core::{
    ddlog_equality::shamir::{
        DLogCommitmentsShamir, DLogProofShareShamir, DLogSessionShamir,
        PartialDLogCommitmentsShamir,
    },
    shamir,
};
use oprf_types::{
    OprfKeyId,
    api::OprfPublicKeyWithEpoch,
    crypto::{OprfKeyMaterial, PartyId},
};
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};
use tracing::instrument;
use uuid::Uuid;

use crate::metrics::METRICS_ID_NODE_OPRF_SECRETS;

type Result<T> = std::result::Result<T, OprfKeyMaterialStoreError>;

/// Errors returned by the [`OprfKeyMaterial`].
///
/// This error type is mostly used in API contexts, meaning it should be digested by the `crate::api::errors` module.
///
/// Methods that are used in other contexts may return one of the variants
/// here or return an `eyre::Result`.
#[derive(Debug, thiserror::Error)]
pub enum OprfKeyMaterialStoreError {
    /// Cannot find the OPRF key id.
    #[error("Cannot find key id: {0}")]
    UnknownOprfKeyId(OprfKeyId),
}

/// Storage for [`OprfKeyMaterial`]s.
#[derive(Default, Clone)]
pub struct OprfKeyMaterialStore(Arc<RwLock<HashMap<OprfKeyId, OprfKeyMaterial>>>);

/// The session obtained after calling `partial_commit`. Doesn't implement `Debug/Clone` to not accidentally leak private data and prevent reusing the same session.
pub(crate) struct OprfSession {
    dlog_session: DLogSessionShamir,
    key_material: OprfKeyMaterial,
}

impl OprfSession {
    /// Returns the public part of the [`OprfSession`], the [`OprfPublicKeyWithEpoch`].
    pub fn public_key_with_epoch(&self) -> OprfPublicKeyWithEpoch {
        self.key_material.public_key_with_epoch()
    }
}

impl OprfKeyMaterialStore {
    /// Creates a new storage instance with the provided initial shares.
    pub fn new(inner: HashMap<OprfKeyId, OprfKeyMaterial>) -> Self {
        ::metrics::gauge!(METRICS_ID_NODE_OPRF_SECRETS).set(inner.len() as f64);
        Self(Arc::new(RwLock::new(inner)))
    }

    /// Returns the amount of stored [`OprfKeyMaterial`]s.
    ///
    /// _Note_ that this acquires a lock internally and returns the length at that point in time.
    pub fn len(&self) -> usize {
        self.0.read().len()
    }

    /// Returns `true` iff the store has no [`OprfKeyMaterial`] stored.
    ///
    /// _Note_ that this acquires a lock internally and returns the result from that point in time.
    pub fn is_empty(&self) -> bool {
        self.0.read().is_empty()
    }

    /// Returns the `true` iff the store contains key-material associated with the [`OprfKeyId`].
    ///
    /// _Note_ that this acquires a lock internally and returns the result from that point in time.
    pub fn contains(&self, oprf_key_id: OprfKeyId) -> bool {
        self.0.read().contains_key(&oprf_key_id)
    }

    /// Swaps the inner `HashMap` with the provided `HashMap`.
    pub(crate) fn reload(&self, mut new_store: HashMap<OprfKeyId, OprfKeyMaterial>) {
        tracing::info!("new store size: {}", new_store.len());
        ::metrics::gauge!(METRICS_ID_NODE_OPRF_SECRETS).set(new_store.len() as f64);
        {
            let mut current = self.0.write();
            std::mem::swap(&mut *current, &mut new_store);
        }
        tracing::info!("old store size: {}", new_store.len());
    }

    /// Computes C = B * x_share and commitments to a random value k_share, where x_share is identified by [`OprfKeyId`].
    ///
    /// This generates the node's partial contribution used in the DLogEqualityProof and returns an [`OprfSession`] and a [`PartialDLogCommitmentsShamir`].
    ///
    /// # Errors
    ///
    /// Returns an error if the OPRF key is unknown.
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn partial_commit(
        &self,
        point_b: ark_babyjubjub::EdwardsAffine,
        oprf_key_id: OprfKeyId,
    ) -> Result<(OprfSession, PartialDLogCommitmentsShamir)> {
        tracing::debug!("computing partial commitment");
        // we still need to check here, because even if we call contains, we might have removed this share in the meantime
        let key_material = self
            .get(oprf_key_id)
            .ok_or(OprfKeyMaterialStoreError::UnknownOprfKeyId(oprf_key_id))?;
        let (dlog_session, commitment) = DLogSessionShamir::partial_commitments(
            point_b,
            key_material.share(),
            &mut rand::thread_rng(),
        );
        tracing::debug!("created session with epoch {}", key_material.epoch());
        let session = OprfSession {
            dlog_session,
            key_material,
        };
        Ok((session, commitment))
    }

    /// Finalizes a proof share for a [`DLogCommitmentsShamir`] and an [`OprfSession`].
    ///
    /// Consumes the session to prevent reuse of the randomness.
    /// The provided [`OprfKeyId`] identifies the used OPRF key.
    ///
    /// # Errors
    ///
    /// Returns an error if the OPRF key is unknown.
    pub(crate) fn challenge(
        &self,
        session_id: Uuid,
        my_party_id: PartyId,
        session: OprfSession,
        challenge: DLogCommitmentsShamir,
    ) -> Result<DLogProofShareShamir> {
        tracing::debug!("finalizing proof share");
        let OprfSession {
            dlog_session,
            key_material,
        } = session;
        let lagrange_coefficient = shamir::single_lagrange_from_coeff(
            my_party_id.into_inner() + 1,
            challenge.get_contributing_parties(),
        );
        Ok(dlog_session.challenge(
            session_id,
            key_material.share(),
            key_material.public_key().inner(),
            challenge,
            lagrange_coefficient,
        ))
    }

    /// Retrieves the [`OprfKeyMaterial`] for the given [`OprfKeyId`].
    ///
    /// Returns `None` if the OPRF key or share epoch is not found.
    fn get(&self, oprf_key_id: OprfKeyId) -> Option<OprfKeyMaterial> {
        self.0.read().get(&oprf_key_id).cloned()
    }

    /// Returns the [`OprfPublicKeyWithEpoch`], if registered.
    pub(crate) fn oprf_public_key_with_epoch(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> Option<OprfPublicKeyWithEpoch> {
        Some(self.0.read().get(&oprf_key_id)?.public_key_with_epoch())
    }

    /// Adds OPRF key-material and overwrites any existing entry.
    pub(super) fn insert(&self, oprf_key_id: OprfKeyId, key_material: OprfKeyMaterial) {
        let mut store = self.0.write();
        store
        .entry(oprf_key_id)
        .and_modify(|stored| {
            if stored.epoch() >= key_material.epoch() {
                tracing::debug!(
                    "refusing to roll back share for {oprf_key_id} to epoch {} when already at {}",
                    key_material.epoch(),
                    stored.epoch()
                );
            } else {
                tracing::debug!("overwriting material for {oprf_key_id}");
                *stored = key_material.clone();
            }
        })
        .or_insert_with(|| {
            ::metrics::gauge!(METRICS_ID_NODE_OPRF_SECRETS).increment(1);
            tracing::debug!(
                "added {oprf_key_id:?} material to OprfKeyMaterialStore"
            );
            key_material
        });
    }

    /// Removes the OPRF key entry associated with the provided [`OprfKeyId`].
    ///
    /// If the id is not registered, doesn't do anything.
    pub(super) fn remove(&self, oprf_key_id: OprfKeyId) {
        if self.0.write().remove(&oprf_key_id).is_some() {
            ::metrics::gauge!(METRICS_ID_NODE_OPRF_SECRETS).decrement(1);
            tracing::debug!("removed {oprf_key_id:?} material from OprfKeyMaterialStore");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy::primitives::U160;
    use oprf_core::ddlog_equality::shamir::DLogShareShamir;
    use oprf_types::{
        OprfKeyId, ShareEpoch,
        crypto::{OprfKeyMaterial, OprfPublicKey},
    };

    use crate::oprf_key_material_store::OprfKeyMaterialStore;

    #[test]
    fn test_oprf_key_material_insert() {
        let oprf_key_material_store = OprfKeyMaterialStore::new(HashMap::new());
        let oprf_key_id = OprfKeyId::from(U160::from(42));
        let public_key = OprfPublicKey::new(rand::random());
        let epoch0 = ShareEpoch::default();
        let epoch42 = ShareEpoch::new(42);
        let should_epoch_0_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
        let should_epoch_1_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
        let share_not_used = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

        let should_material0 = OprfKeyMaterial::new(should_epoch_0_share, public_key, epoch0);
        oprf_key_material_store.insert(oprf_key_id, should_material0.clone());
        check_key_material(&oprf_key_material_store, oprf_key_id, should_material0);

        let should_material1 = OprfKeyMaterial::new(should_epoch_1_share, public_key, epoch42);
        oprf_key_material_store.insert(oprf_key_id, should_material1.clone());
        check_key_material(
            &oprf_key_material_store,
            oprf_key_id,
            should_material1.clone(),
        );

        let material_to_refuse =
            OprfKeyMaterial::new(share_not_used.clone(), public_key, epoch42.prev());
        oprf_key_material_store.insert(oprf_key_id, material_to_refuse);
        // Check that still older material
        check_key_material(
            &oprf_key_material_store,
            oprf_key_id,
            should_material1.clone(),
        );

        let material_to_refuse = OprfKeyMaterial::new(share_not_used, public_key, epoch42);
        oprf_key_material_store.insert(oprf_key_id, material_to_refuse.clone());
        // Check that still older material
        check_key_material(&oprf_key_material_store, oprf_key_id, should_material1);
    }

    fn check_key_material(
        store: &OprfKeyMaterialStore,
        oprf_key_id: OprfKeyId,
        should_material: OprfKeyMaterial,
    ) {
        let is_material = store.get(oprf_key_id).expect("Must be there");
        assert_eq!(
            is_material.public_key_with_epoch(),
            should_material.public_key_with_epoch()
        );
        assert_eq!(
            ark_babyjubjub::Fr::from(is_material.share()),
            ark_babyjubjub::Fr::from(should_material.share()),
        );
    }
}
