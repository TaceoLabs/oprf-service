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
    OprfKeyId, ShareEpoch,
    api::{OprfPublicKeyWithEpoch, v1::ShareIdentifier},
    crypto::{OprfKeyMaterial, OprfPublicKey, PartyId},
};
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};
use tracing::instrument;
use uuid::Uuid;

use crate::metrics::METRICS_ID_NODE_OPRF_SECRETS;

type OprfKeyMaterialStoreResult<T> = std::result::Result<T, OprfKeyMaterialStoreError>;

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
    /// Cannot find a secret share for the epoch.
    #[error("Cannot find share with epoch: {0}")]
    UnknownShareEpoch(ShareEpoch),
}

/// Storage for [`OprfKeyMaterial`]s.
#[derive(Default, Clone)]
pub struct OprfKeyMaterialStore(Arc<RwLock<HashMap<OprfKeyId, OprfKeyMaterial>>>);

impl OprfKeyMaterialStore {
    /// Creates a new storage instance with the provided initial shares.
    pub(crate) fn new(inner: HashMap<OprfKeyId, OprfKeyMaterial>) -> Self {
        ::metrics::gauge!(METRICS_ID_NODE_OPRF_SECRETS).set(inner.len() as f64);
        Self(Arc::new(RwLock::new(inner)))
    }

    /// Computes C = B * x_share and commitments to a random value k_share.
    ///
    /// This generates the node's partial contribution used in the DLogEqualityProof.
    /// The provided [`ShareIdentifier`] identifies the used OPRF key and the epoch of the share.
    ///
    /// Returns an error if the OPRF key is unknown or the share for the epoch is not registered.
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn partial_commit(
        &self,
        point_b: ark_babyjubjub::EdwardsAffine,
        share_identifier: ShareIdentifier,
    ) -> OprfKeyMaterialStoreResult<(DLogSessionShamir, PartialDLogCommitmentsShamir)> {
        tracing::debug!("computing partial commitment");
        let share = self
            .get(share_identifier.oprf_key_id)
            .ok_or(OprfKeyMaterialStoreError::UnknownOprfKeyId(
                share_identifier.oprf_key_id,
            ))?
            .get_share(share_identifier.share_epoch)
            .ok_or(OprfKeyMaterialStoreError::UnknownShareEpoch(
                share_identifier.share_epoch,
            ))?;
        Ok(DLogSessionShamir::partial_commitments(
            point_b,
            share,
            &mut rand::thread_rng(),
        ))
    }

    /// Finalizes a proof share for a given challenge hash and session.
    ///
    /// Consumes the session to prevent reuse of the randomness.
    /// The provided [`ShareIdentifier`] identifies the used OPRF key and the epoch of the share.
    ///
    /// Returns an error if the OPRF key is unknown or the share for the epoch is not registered.
    pub(crate) fn challenge(
        &self,
        session_id: Uuid,
        my_party_id: PartyId,
        session: DLogSessionShamir,
        challenge: DLogCommitmentsShamir,
        share_identifier: ShareIdentifier,
    ) -> OprfKeyMaterialStoreResult<DLogProofShareShamir> {
        tracing::debug!("finalizing proof share");
        let oprf_public_key = self
            .get_oprf_public_key(share_identifier.oprf_key_id)
            .ok_or(OprfKeyMaterialStoreError::UnknownOprfKeyId(
                share_identifier.oprf_key_id,
            ))?;
        let share = self
            .get(share_identifier.oprf_key_id)
            .ok_or(OprfKeyMaterialStoreError::UnknownOprfKeyId(
                share_identifier.oprf_key_id,
            ))?
            .get_share(share_identifier.share_epoch)
            .ok_or(OprfKeyMaterialStoreError::UnknownShareEpoch(
                share_identifier.share_epoch,
            ))?;
        let lagrange_coefficient = shamir::single_lagrange_from_coeff(
            my_party_id.into_inner() + 1,
            challenge.get_contributing_parties(),
        );
        Ok(session.challenge(
            session_id,
            share,
            oprf_public_key.inner(),
            challenge,
            lagrange_coefficient,
        ))
    }

    /// Retrieves the secret share for the given [`ShareIdentifier`].
    ///
    /// Returns `None` if the OPRF key or share epoch is not found.
    fn get(&self, oprf_key_id: OprfKeyId) -> Option<OprfKeyMaterial> {
        self.0.read().get(&oprf_key_id).cloned()
    }

    /// Returns the [`OprfPublicKey`], if registered.
    pub(crate) fn get_oprf_public_key(&self, oprf_key_id: OprfKeyId) -> Option<OprfPublicKey> {
        Some(self.0.read().get(&oprf_key_id)?.get_oprf_public_key())
    }

    /// Returns the [`OprfPublicKey`], if registered.
    pub(crate) fn get_oprf_public_key_with_epoch(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> Option<OprfPublicKeyWithEpoch> {
        self.0
            .read()
            .get(&oprf_key_id)?
            .get_oprf_public_key_with_epoch()
    }

    /// Adds OPRF key-material and overwrites any existing entry.
    pub(super) fn insert(&self, oprf_key_id: OprfKeyId, key_material: OprfKeyMaterial) {
        if self.0.write().insert(oprf_key_id, key_material).is_some() {
            tracing::debug!("overwriting material for {oprf_key_id}");
        } else {
            ::metrics::gauge!(METRICS_ID_NODE_OPRF_SECRETS).increment(1);
            tracing::debug!("added {oprf_key_id:?} material to OprfKeyMaterialStore");
        }
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
