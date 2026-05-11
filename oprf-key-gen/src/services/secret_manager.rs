//! Secret manager interface for OPRF nodes.
//!
//! This module defines the [`SecretManager`] trait, which is used to
//! persist and retrieve `OprfKeyMaterial`.
//!
//! Current `SecretManager` implementations:
//! - Postgres

use std::sync::Arc;

use async_trait::async_trait;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};

pub use crate::services::secret_gen::KeyGenIntermediateValues;

/// Dynamic trait object for secret manager service.
///
/// Must be `Send + Sync` to work with async contexts (e.g., Axum).
pub type SecretManagerService = Arc<dyn SecretManager + Send + Sync>;

/// Type alias for `std::result::Result` with [`SecretManagerError`].
pub type Result<T> = std::result::Result<T, SecretManagerError>;

/// All errors that might occur when interacting with the [`SecretManagerService`].
///
/// Internal errors that are implementation dependent (e.g. Postgres DB errors) shall be wrapped with `eyre::Report::from`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretManagerError {
    /// Tried to overwrite already existing intermediates for the given key/epoch pair.
    #[error("Intermediates already stored for {0}/{1}")]
    DuplicateIntermediates(OprfKeyId, ShareEpoch),
    /// Tried to use in-progress state that does not exist for the given key/epoch pair.
    #[error("Intermediates NOT stored for {0}/{1} - stuck")]
    MissingIntermediates(OprfKeyId, ShareEpoch),
    /// Tried to confirm a share for a key that has already been deleted.
    #[error("Constraint violation - tried to store share for deleted id")]
    StoreOnDeletedShare,
    /// Tried to overwrite a confirmed share with the same or an older epoch.
    #[error("Refusing to overwrite newer share")]
    RefusingToRollbackEpoch,
    /// Implementation specific error.
    #[error(transparent)]
    Internal(#[from] eyre::Report),
}

/// Trait that implementations of secret managers must provide.
///
/// Handles persistence of `OprfKeyMaterial`.
#[async_trait]
pub trait SecretManager {
    /// Stores the node wallet address in the secret manager.
    async fn store_wallet_address(&self, address: String) -> Result<()>;

    /// Returns the share of a given [`OprfKeyId`] and a given [`ShareEpoch`].
    ///
    /// Returns `Ok(None)` if there is no confirmed share for the given key/epoch pair.
    async fn get_share_by_epoch(
        &self,
        oprf_key_id: OprfKeyId,
        generated_epoch: ShareEpoch,
    ) -> Result<Option<DLogShareShamir>>;

    /// Removes finalized share material and any in-progress state for the specified [`OprfKeyId`].
    async fn delete_oprf_key_material(&self, oprf_key_id: OprfKeyId) -> Result<()>;

    /// Aborts ALL in progress key generations (or reshare).
    ///
    /// In contrast to [`Self::delete_oprf_key_material`] this method only removes in-progress state associated with the given key. It MUST not delete finalized shares.
    ///
    /// Must return `Ok(())` if there is no key generation in process.
    ///
    /// During ordinary flow it is not possible to have multiple key-gens running at the same time for the same key. Theoretically though a node might drop out during an ongoing key-gen and come back later, trying to start a new run. If we then abort, we still want to remove all in-progress state associated with this key.
    ///
    /// There exists a theoretical race condition where two parallel key-generations — one for epoch
    /// `x` and one for epoch `y` where `y > x` — execute concurrently. If the abort event for `x`
    /// arrives after `y` has already started, it may delete the intermediates for `y` as well.
    /// The callsite is expected to handle this; the current key-gen implementation processes events
    /// sequentially, so this cannot occur as long as events are processed in order.
    async fn abort_keygen(&self, oprf_key_id: OprfKeyId) -> Result<()>;

    /// Tries to persist the intermediate values needed for key generation (or reshare).
    ///
    /// If intermediate values already exist for this `OprfKeyId` and `ShareEpoch` pair, this method must return the already stored `KeyGenIntermediateValues` and discard the new ones.
    async fn try_store_keygen_intermediates(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        intermediate: KeyGenIntermediateValues,
    ) -> Result<KeyGenIntermediateValues>;

    /// Retrieves the intermediate values needed for key generation (or reshare).
    ///
    /// # Errors
    ///
    /// Returns [`SecretManagerError::MissingIntermediates`]`(oprf_key_id, epoch)` when no
    /// intermediate values are stored for the provided key/epoch pair.
    async fn fetch_keygen_intermediates(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
    ) -> Result<KeyGenIntermediateValues>;

    /// Stores a pending share for the given key/epoch pair.
    ///
    /// This is the share for this node before the finalize event confirms it and marks it ready to use.
    async fn store_pending_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> Result<()>;

    /// Confirms a pending share and finalizes key-generation for the given epoch.
    ///
    /// This method MUST store the confirmed share and delete all in-progress intermediates
    /// associated with this [`OprfKeyId`]. After calling this method, the share for the provided
    /// epoch MUST be ready to use.
    ///
    /// # Attention
    ///
    /// All intermediates for this [`OprfKeyId`] are deleted regardless of epoch. If a
    /// key-generation for a later epoch `y` is in progress concurrently with a confirm for epoch
    /// `x` where `x < y`, the intermediates for `y` may be deleted. The callsite is expected to
    /// handle this; the current key-gen implementation processes events sequentially, so this
    /// cannot occur as long as events are processed in order.
    async fn confirm_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        public_key: OprfPublicKey,
    ) -> Result<()>;
}
