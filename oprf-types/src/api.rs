//! # API module
//!
//! Entry point for all API version modules.
//!
//! Currently exposes the version 1 OPRF API types under [`v1`].

use http::HeaderName;
use serde::{Deserialize, Serialize};

use crate::{ShareEpoch, crypto::OprfPublicKey};
pub mod v1;

/// The [`OprfPublicKey`] with its latest [`ShareEpoch`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OprfPublicKeyWithEpoch {
    /// The key
    pub key: OprfPublicKey,
    /// The current epoch
    pub epoch: ShareEpoch,
}

/// The name of the oprf-protocol-version header.
pub static OPRF_PROTOCOL_VERSION_HEADER: HeaderName =
    http::HeaderName::from_static("x-taceo-oprf-protocol-version");
