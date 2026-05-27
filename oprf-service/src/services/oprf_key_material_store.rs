//! This module provides [`OprfKeyMaterialStore`], which securely holds `OPRF DLog` shares.
//!
//! Shares are loaded on demand from the secret manager and cached using a `moka` async cache
//! with configurable capacity, TTL, and TTI eviction policies.
//! Each OPRF key material is represented by [`OprfKeyMaterial`].

use moka::future::Cache;
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
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

use crate::{
    metrics,
    secret_manager::{SecretManagerError, SecretManagerService},
};

/// Storage for [`OprfKeyMaterial`]s.
#[derive(Clone)]
pub struct OprfKeyMaterialStore {
    store: Cache<OprfKeyId, OprfKeyMaterial>,
    secret_manager: SecretManagerService,
}

/// The session obtained after calling `partial_commit`. Doesn't implement `Debug/Clone` to not accidentally leak private data and prevent reusing the same session.
pub(crate) struct OprfSession {
    oprf_key_id: OprfKeyId,
    dlog_session: DLogSessionShamir,
    key_material: OprfKeyMaterial,
}

impl OprfSession {
    /// Returns the public part of the [`OprfSession`], the [`OprfPublicKeyWithEpoch`].
    pub(crate) fn public_key_with_epoch(&self) -> OprfPublicKeyWithEpoch {
        self.key_material.public_key_with_epoch()
    }

    /// Returns the [`OprfKeyId`] associated with this session.
    pub(crate) fn key_id(&self) -> OprfKeyId {
        self.oprf_key_id
    }
}

impl OprfKeyMaterialStore {
    /// Creates a new storage instance with the provided initial shares.
    #[must_use]
    pub fn new(
        secret_manager: SecretManagerService,
        max_capacity: u64,
        time_to_live: Duration,
        time_to_idle: Duration,
    ) -> Self {
        metrics::secrets::set(0);

        let store = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(time_to_live)
            .time_to_idle(time_to_idle)
            .eviction_listener(move |k, _, cause| {
                tracing::debug!("removing OprfKeyId {k} because: {cause:?}");
                metrics::secrets::dec();
            })
            .build();

        Self {
            store,
            secret_manager,
        }
    }

    /// Computes `C = B * x_share` and commitments to a random value `k_share`, where `x_share` is identified by [`OprfKeyId`].
    ///
    /// This generates the node's partial contribution used in the `DLogEqualityProof` and returns an [`OprfSession`] and a [`PartialDLogCommitmentsShamir`].
    ///
    /// # Errors
    ///
    /// Returns an error if the OPRF key is unknown.
    pub(crate) async fn partial_commit(
        &self,
        point_b: ark_babyjubjub::EdwardsAffine,
        oprf_key_id: OprfKeyId,
    ) -> Result<(OprfSession, PartialDLogCommitmentsShamir), Arc<SecretManagerError>> {
        tracing::trace!("computing partial commitment");
        let key_material = self.try_get(oprf_key_id).await?;
        let (dlog_session, commitment) = DLogSessionShamir::partial_commitments(
            point_b,
            key_material.share(),
            &mut rand::thread_rng(),
        );
        tracing::trace!("created session with epoch {}", key_material.epoch());
        let session = OprfSession {
            oprf_key_id,
            dlog_session,
            key_material,
        };
        Ok((session, commitment))
    }

    /// Finalizes a proof share for a [`DLogCommitmentsShamir`] and an [`OprfSession`].
    ///
    /// Consumes the session to prevent reuse of the randomness.
    /// The provided [`OprfKeyId`] identifies the used OPRF key.
    pub(crate) fn challenge(
        session_id: Uuid,
        my_party_id: PartyId,
        session: OprfSession,
        challenge: DLogCommitmentsShamir,
    ) -> DLogProofShareShamir {
        tracing::trace!("finalizing proof share");
        let OprfSession {
            oprf_key_id: _,
            dlog_session,
            key_material,
        } = session;
        let lagrange_coefficient = shamir::single_lagrange_from_coeff(
            my_party_id.into_inner() + 1,
            challenge.get_contributing_parties(),
        );
        dlog_session.challenge(
            session_id,
            key_material.share(),
            key_material.public_key().inner(),
            challenge,
            lagrange_coefficient,
        )
    }

    /// Returns the [`OprfPublicKeyWithEpoch`], fetching from the secret manager on cache miss.
    pub(crate) async fn oprf_public_key_with_epoch(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> Result<OprfPublicKeyWithEpoch, Arc<SecretManagerError>> {
        Ok(self.try_get(oprf_key_id).await?.public_key_with_epoch())
    }

    async fn try_get(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> Result<OprfKeyMaterial, Arc<SecretManagerError>> {
        let key_material = self
            .store
            .entry(oprf_key_id)
            .or_try_insert_with(self.secret_manager.get_oprf_key_material(oprf_key_id))
            .await?;
        if key_material.is_fresh() {
            metrics::secrets::inc();
        }
        Ok(key_material.into_value())
    }
}
