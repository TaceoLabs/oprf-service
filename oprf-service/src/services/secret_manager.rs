//! Secret manager interface for OPRF nodes.
//!
//! This module defines the [`SecretManager`] trait, which is used to
//! persist and retrieve `OprfKeyMaterial`.
//!
//! Current `SecretManager` implementations:
//! - AWS (cloud storage)
//! - Postgres

use std::sync::Arc;

use alloy::primitives::Address;
use async_trait::async_trait;
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfKeyMaterial};

use crate::services::oprf_key_material_store::OprfKeyMaterialStore;

#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "postgres")]
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
    /// Loads the EVM `Address` of this node.
    async fn load_address(&self) -> eyre::Result<Address>;

    /// Loads the DLog secrets and creates a [`OprfKeyMaterialStore`].
    async fn load_secrets(&self) -> eyre::Result<OprfKeyMaterialStore>;

    /// Returns the [`OprfKeyMaterial`] for the given [`OprfKeyId`] and [`ShareEpoch`] if it exists.
    ///
    /// Returns `None` if it doesn't exist or the key-material exists, but is not in the correct epoch.
    async fn get_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> eyre::Result<Option<OprfKeyMaterial>>;
}
