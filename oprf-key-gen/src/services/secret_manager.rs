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
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfKeyMaterial};

pub mod aws;

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

    /// Stores the provided [`OprfKeyMaterial`] for the given [`OprfKeyId`].
    ///
    /// This method is intended **only** for initializing a new [`OprfKeyMaterial`]. For updating
    /// existing shares, use [`Self::update_dlog_share`].
    async fn store_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
        oprf_key_material: OprfKeyMaterial,
    ) -> eyre::Result<()>;

    /// Removes all information stored associated with the specified [`OprfKeyId`].
    ///
    /// Certain secret-managers might not be able to immediately delete the secret. In that case it shall mark the secret for deletion.
    async fn remove_oprf_key_material(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()>;

    /// Updates the [`DLogShareShamir`] of an existing [`OprfKeyId`] to a new epoch.
    ///
    /// Use this method for updating existing shares. For creating use [`Self::store_oprf_key_material`].
    async fn update_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> eyre::Result<()>;
}
