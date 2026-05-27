//! Secret manager interface for OPRF nodes.
//!
//! This module defines the [`SecretManager`] trait, which is used to
//! persist and retrieve `OprfKeyMaterial`.
//!
//! Current `SecretManager` implementations:
//! - Postgres

use std::sync::Arc;

use async_trait::async_trait;
use oprf_types::{OprfKeyId, crypto::OprfKeyMaterial, service::NodeInformation};

#[cfg(feature = "postgres")]
pub mod postgres;

/// Dynamic trait object for secret manager service.
///
/// Must be `Send + Sync` to work with async contexts (e.g., Axum).
pub type SecretManagerService = Arc<dyn SecretManager + Send + Sync>;

/// All errors that might occur when interacting with the [`SecretManagerService`].
///
/// Internal errors that are implementation dependent (e.g. Postgres DB errors) shall be wrapped with `eyre::Report::from`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretManagerError {
    /// Unknown [`OprfKeyId`]
    #[error("unknown OPRF key-id: {0}")]
    UnknownOprfKeyId(OprfKeyId),
    /// Deleted [`OprfKeyId`]
    #[error("requested deleted OPRF key-id: {0}")]
    DeletedOprfKeyId(OprfKeyId),
    /// Implementation specific error.
    #[error("internal error: {0:?}")]
    Internal(#[from] eyre::Report),
}

/// Trait that implementations of secret managers must provide.
///
/// Handles persistence of `OprfKeyMaterial`.
#[async_trait]
pub trait SecretManager {
    /// Loads the [`NodeInformation`] for this node.
    async fn load_node_information(&self) -> eyre::Result<NodeInformation>;

    /// Returns the [`OprfKeyMaterial`] for the given [`OprfKeyId`] if it exists.
    async fn get_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> Result<OprfKeyMaterial, SecretManagerError>;
}
