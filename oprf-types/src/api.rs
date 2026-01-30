//! This module defines the request and response payloads exchanged
//! between clients and the server for the OPRF protocol, along with
//! identifiers used to reference keys and epochs. Types here wrap
//! cryptographic proofs and points with Serde (de)serialization so
//! they can be sent over the wire.
//!
//! Additionally, it defines the [`OprfRequestAuthenticator`] trait to define an authentication module for TACEO:OPRF.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use http::HeaderName;
use oprf_core::ddlog_equality::shamir::PartialDLogCommitmentsShamir;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    OprfKeyId, ShareEpoch,
    crypto::{OprfPublicKey, PartyId},
};

use ark_serde_compat::babyjubjub;

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

/// TACEO:OPRF specific websocket error codes.
pub mod oprf_error_codes {
    /// An opened session exceeds its life time.
    ///
    /// The OPRF node closed the websocket and the session must be considered void.
    pub const TIMEOUT: u16 = 4001;
    /// Bad request during OPRF computation (e.g. parsing error).
    pub const BAD_REQUEST: u16 = 4002;
}

/// A request sent by a client to perform an OPRF evaluation.
#[derive(Clone, Serialize, Deserialize)]
pub struct OprfRequest<OprfRequestAuth> {
    /// Unique ID of the request (used to correlate responses).
    pub request_id: Uuid,
    /// Input point `B` of the OPRF, serialized as a BabyJubJub affine point.
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    pub blinded_query: ark_babyjubjub::EdwardsAffine,
    /// Identifies the OPRF key
    pub oprf_key_id: OprfKeyId,
    /// The additional authentication info for this request
    pub auth: OprfRequestAuth,
}

/// Server response to an [`OprfRequest`].
#[derive(Debug, Serialize, Deserialize)]
pub struct OprfResponse {
    /// Server’s partial commitments for the discrete log equality proof.
    pub commitments: PartialDLogCommitmentsShamir,
    /// The party ID of the node
    pub party_id: PartyId,
    /// The [`OprfPublicKeyWithEpoch`].
    pub oprf_pub_key_with_epoch: OprfPublicKeyWithEpoch,
}

impl<OprfReqestAuth> fmt::Debug for OprfRequest<OprfReqestAuth> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OprfRequest")
            .field("req_id", &self.request_id)
            .field("blinded_query", &self.blinded_query.to_string())
            .field("key_id", &self.oprf_key_id)
            .finish()
    }
}

/// Trait defining the authentication mechanism for OPRF requests.
///
/// This trait enables the verification of OPRF requests to ensure they are
/// properly authenticated before processing. It is designed to be implemented
/// by authentication services that can validate the authenticity of incoming
/// OPRF requests.
#[async_trait]
pub trait OprfRequestAuthenticator: Send + Sync {
    /// Represents the authentication data type included in the OPRF request.
    type RequestAuth;
    /// The error type that may be returned by the [`OprfRequestAuthenticator`] on [`OprfRequestAuthenticator::verify`].
    ///
    /// This method shall implement `fmt::Display` because a human-readable message will be sent back to the user for troubleshooting.
    ///
    /// **Note:** it is very important that `fmt::Display` does not print any sensitive information. For debugging information, use `fmt::Debug`.
    type RequestAuthError: Send + 'static + std::error::Error;

    /// Verifies the authenticity of an OPRF request.
    async fn verify(
        &self,
        req: &OprfRequest<Self::RequestAuth>,
    ) -> Result<(), Self::RequestAuthError>;
}

/// Dynamic trait object for `OprfRequestAuthenticator` service.
pub type OprfRequestAuthService<RequestAuth, RequestAuthError> = Arc<
    dyn OprfRequestAuthenticator<RequestAuth = RequestAuth, RequestAuthError = RequestAuthError>,
>;
