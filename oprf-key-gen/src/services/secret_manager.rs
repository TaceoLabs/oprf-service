//! Secret manager interface for OPRF nodes.
//!
//! This module defines the [`SecretManager`] trait, which is used to
//! persist and retrieve `OprfKeyMaterial`.
//!
//! Current `SecretManager` implementations:
//! - AWS (cloud storage)

use std::sync::Arc;

use alloy::signers::local::PrivateKeySigner;
use async_trait::async_trait;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};

pub mod aws;
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
    /// Loads the wallet private key from the secret-manager.
    ///
    /// If the secret-manager can't find a secret, it shall create a new one, store it and then return the new one.
    async fn load_or_insert_wallet_private_key(&self) -> eyre::Result<PrivateKeySigner>;

    /// Returns the previous share of a given [`OprfKeyId`] and a given [`ShareEpoch`].
    /// Returns `Ok(None)` if the store does not contain the previous epoch (or any secret associated with the key id).
    async fn get_previous_share(
        &self,
        oprf_key_id: OprfKeyId,
        generated_epoch: ShareEpoch,
    ) -> eyre::Result<Option<DLogShareShamir>>;

    /// Removes all information stored associated with the specified [`OprfKeyId`].
    ///
    /// Certain secret-managers might not be able to immediately delete the secret. In that case it shall mark the secret for deletion.
    async fn remove_oprf_key_material(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()>;

    /// Stores an OPRF secret with at the secret-manager with the provided epoch.
    ///
    /// If epoch is zero or if the secret-manager does not contain a secret with this [`OprfKeyId`], calls `create_secret`.
    ///
    /// Otherwise, loads the existing secret, moves the current epoch to previous and stores the new share as the current epoch.
    async fn store_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        public_key: OprfPublicKey,
        epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> eyre::Result<()>;
}
