//! # v1 API types
//!
//! Data transfer objects for the version 1 OPRF API.
//!
//! This module defines the request and response payloads exchanged
//! between clients and the server for the OPRF protocol, along with
//! identifiers used to reference keys and epochs. Types here wrap
//! cryptographic proofs and points with Serde (de)serialization so
//! they can be sent over the wire.
use std::fmt;

use oprf_core::ddlog_equality::shamir::PartialDLogCommitmentsShamir;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    OprfKeyId, ShareEpoch,
    crypto::{OprfPublicKey, PartyId},
};
use ark_serde_compat::babyjubjub;

/// TACEO:Oprf specific websocket error codes.
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
    /// Identifies the OPRF public-key and the epoch of the used share
    pub share_identifier: ShareIdentifier,
    /// The additional authentication info for this request
    pub auth: OprfRequestAuth,
}

/// Identifies the nullifier share to use for the OPRF computation by relying party ([`OprfKeyId`]) and [`ShareEpoch`].
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ShareIdentifier {
    /// ID of OPRF public-key
    pub oprf_key_id: OprfKeyId,
    /// Epoch of the key.
    pub share_epoch: ShareEpoch,
}

/// Server response to an [`OprfRequest`].
#[derive(Debug, Serialize, Deserialize)]
pub struct OprfResponse {
    /// Server’s partial commitments for the discrete log equality proof.
    pub commitments: PartialDLogCommitmentsShamir,
    /// The party ID of the node
    pub party_id: PartyId,
    /// The `OprfPublicKey` for the requested `OprfKeyId`.
    pub oprf_public_key: OprfPublicKey,
}

impl<OprfReqestAuth> fmt::Debug for OprfRequest<OprfReqestAuth> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OprfRequest")
            .field("req_id", &self.request_id)
            .field("blinded_query", &self.blinded_query.to_string())
            .field("share_identifier", &self.share_identifier)
            .finish()
    }
}
