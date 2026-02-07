//! Secret manager interface for OPRF nodes.
//!
//! This module defines the [`SecretManager`] trait, which is used to
//! persist and retrieve `OprfKeyMaterial`.
//!
//! Current `SecretManager` implementations:
//! - AWS (cloud storage)
//! - Postgres

use std::{collections::HashMap, sync::Arc};

use alloy::primitives::Address;
use async_trait::async_trait;
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfKeyMaterial};

#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "postgres")]
pub mod postgres;

/// Dynamic trait object for secret manager service.
///
/// Must be `Send + Sync` to work with async contexts (e.g., Axum).
pub type SecretManagerService = Arc<dyn SecretManager + Send + Sync>;

/// Error when calling [`SecretManager::get_oprf_key_material`].
#[derive(Debug, thiserror::Error)]
pub enum GetOprfKeyMaterialError {
    /// Cannot find the share with requested oprf-key-id and epoch.
    #[error("Cannot find requested material")]
    NotInDb,
    /// Internal error from DB.
    #[error(transparent)]
    Internal(#[from] eyre::Report),
}

/// Trait that implementations of secret managers must provide.
///
/// Handles persistence of `OprfKeyMaterial`.
#[async_trait]
pub trait SecretManager {
    /// Loads the EVM `Address` of this node.
    async fn load_address(&self) -> eyre::Result<Address>;

    /// Loads the DLog secrets and their associated [`OprfKeyId`]s.
    async fn load_secrets(&self) -> eyre::Result<HashMap<OprfKeyId, OprfKeyMaterial>>;

    /// Returns the [`OprfKeyMaterial`] for the given [`OprfKeyId`] and [`ShareEpoch`] if it exists.
    async fn get_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> Result<OprfKeyMaterial, GetOprfKeyMaterialError>;
}
