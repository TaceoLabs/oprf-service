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

pub mod postgres;

/// Dynamic trait object for secret manager service.
///
/// Must be `Send + Sync` to work with async contexts (e.g., Axum).
pub type SecretManagerService = Arc<dyn SecretManager + Send + Sync>;

/// Trait that implementations of secret managers must provide.
///
/// Handles persistence of `OprfKeyMaterial`.
#[async_trait]
pub trait SecretManager {
    /// Stores the wallet address in the secret manager, so that nodes can later retrieve it.
    async fn store_wallet_address(&self, address: String) -> eyre::Result<()>;

    /// Pings the secret manager. Mostly used for secret-managers in deep-sleep to reduce latency during finalize round.
    async fn ping(&self) -> eyre::Result<()>;

    /// Returns the share of a given [`OprfKeyId`] and a given [`ShareEpoch`].
    /// Returns `Ok(None)` if the secret-manager does not contain a share associated with the key-id or if the epoch does not match.
    async fn get_share_by_epoch(
        &self,
        oprf_key_id: OprfKeyId,
        generated_epoch: ShareEpoch,
    ) -> eyre::Result<Option<DLogShareShamir>>;

    /// Removes all information stored associated with the specified [`OprfKeyId`].
    ///
    /// Certain secret-managers might not be able to immediately delete the secret. In that case it shall mark the secret for deletion.
    async fn remove_oprf_key_material(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()>;

    /// Stores an OPRF secret with with the provided epoch.
    ///
    /// This method SHOULD overwrite/delete the old epoch, if it already existed.
    async fn store_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        public_key: OprfPublicKey,
        epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> eyre::Result<()>;
}
