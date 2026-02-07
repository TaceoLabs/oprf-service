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

/// The error from a secret-manager. Can either be Recoverable or NonRecoverable.
#[derive(Debug, thiserror::Error)]
pub enum SecretManagerError {
    /// A Recoverable error - we don't need to shutdown the binary.
    #[error("Can recover from this error")]
    Recoverable,
    /// A Non-Recoverable error - we most likely need to shutdown the binary.
    #[error(transparent)]
    NonRecoverable(#[from] eyre::Report),
}

/// All information needed to persist the share of an OPRF key.
#[derive(Clone)]
pub struct StoreDLogShare {
    /// The oprf key id
    pub oprf_key_id: OprfKeyId,
    /// The public key
    pub public_key: OprfPublicKey,
    /// The epoch of this share
    pub epoch: ShareEpoch,
    /// The actual share
    pub share: DLogShareShamir,
}

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
    async fn remove_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> Result<(), SecretManagerError>;

    /// Removes all information stored associated with the specified [`OprfKeyId`]s.
    ///
    /// Certain secret-managers might not be able to immediately delete the secret. In that case it shall mark the secret for deletion.
    async fn remove_oprf_key_material_batch(&self, oprf_key_ids: &[OprfKeyId]) -> eyre::Result<()>;

    /// Stores an OPRF secret with at secret-manager with the provided epoch.
    async fn store_dlog_share(
        &self,
        store_dlog_share: StoreDLogShare,
    ) -> Result<(), SecretManagerError>;

    /// Stores a batch of OPRF secrets. If a persisted share has a later epoch than the one inserted here, will ignore that row.
    async fn store_dlog_share_batch(
        &self,
        store_dlog_shares: Vec<StoreDLogShare>,
    ) -> eyre::Result<()>;
}
