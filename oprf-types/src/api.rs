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

/// Maximum byte length allowed for a WebSocket close frame message, per the RFC.
pub const CLOSE_FRAME_MAX_LENGTH: usize = 123;

/// Constructs a [`crate::api::CloseFrameMessage`] from a string literal with a compile-time length check.
///
/// Panics at compile time if the string exceeds [`crate::api::CLOSE_FRAME_MAX_LENGTH`] bytes.
#[macro_export]
macro_rules! close_frame_message {
    ($s: expr) => {{
        use $crate::api::CloseFrameMessage;
        const {
            assert!(
                $s.len() <= $crate::api::CLOSE_FRAME_MAX_LENGTH,
                "CloseFrame message must be lower than 123 bytes"
            );
        }
        CloseFrameMessage::try_from($s).expect("length validated at compile time")
    }};
}

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
///
/// Error codes are split into two ranges:
/// - **4001–4499**: Service-level errors, defined and reserved by the OPRF service.
/// - **4500–4999**: Authentication errors, defined by the [`OprfRequestAuthenticator`],
///   Implementations **must** use codes in this range or valid RFC 6455 codes when constructing an [`OprfRequestAuthenticatorError`].
pub mod oprf_error_codes {
    /// An opened session exceeds its life time.
    ///
    /// The OPRF node closed the websocket and the session must be considered void.
    pub const TIMEOUT: u16 = 4001;
    /// Unexpected or corrupted message during OPRF computation (e.g. corrupt json/cbor or wrong message).
    pub const CORRUPTED_MESSAGE: u16 = 4002;
    /// Session already in use
    pub const SESSION_REUSE: u16 = 4003;
    /// Unknown OPRF-key ID
    pub const UNKNOWN_OPRF_KEY_ID: u16 = 4004;
    /// Blinded query was identity which is not allowed
    pub const BLINDED_QUERY_IS_IDENTITY: u16 = 4005;
    /// Contributing parties did not match threshold
    pub const COEFFICIENTS_DOES_NOT_EQUAL_THRESHOLD: u16 = 4006;
    /// Coefficients of node not in challenge
    pub const MISSING_MY_COEFFICIENT: u16 = 4007;
    /// Unsorted contributing parties
    pub const UNSORTED_CONTRIBUTING_PARTIES: u16 = 4008;
    /// Found a duplicate coefficient
    pub const DUPLICATE_COEFFICIENT: u16 = 4009;
}

/// A typed classification of an OPRF WebSocket close code.
///
/// Converts a raw `u16` close code (e.g. from a received `CloseFrame`)
/// into a structured variant via [`From<u16>`]. Codes in 4001–4499 map to service-level variants;
/// codes in 4500–4999 map to [`OprfErrorKind::Auth`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OprfErrorKind {
    /// Session timed out. Corresponds to [`oprf_error_codes::TIMEOUT`].
    Timeout,
    /// Unexpected or corrupted message. Corresponds to [`oprf_error_codes::CORRUPTED_MESSAGE`].
    CorruptedMessage,
    /// Session ID already in use. Corresponds to [`oprf_error_codes::SESSION_REUSE`].
    SessionReuse,
    /// The requested OPRF key ID is not known. Corresponds to [`oprf_error_codes::UNKNOWN_OPRF_KEY_ID`].
    UnknownOprfKeyId,
    /// Blinded query was the identity element. Corresponds to [`oprf_error_codes::BLINDED_QUERY_IS_IDENTITY`].
    BlindedQueryIsIdentity,
    /// Number of contributing parties does not equal threshold. Corresponds to [`oprf_error_codes::COEFFICIENTS_DOES_NOT_EQUAL_THRESHOLD`].
    CoefficientsDoesNotEqualThreshold,
    /// This node's coefficient was not in the challenge. Corresponds to [`oprf_error_codes::MISSING_MY_COEFFICIENT`].
    MissingMyCoefficient,
    /// Contributing parties were not sorted in ascending order. Corresponds to [`oprf_error_codes::UNSORTED_CONTRIBUTING_PARTIES`].
    UnsortedContributingParties,
    /// Contributing parties contained a duplicate coefficient. Corresponds to [`oprf_error_codes::DUPLICATE_COEFFICIENT`].
    DuplicateCoefficient,
    /// Authentication failed. Close code was in the 4500–4999 range defined by the [`OprfRequestAuthenticator`].
    Auth,
    /// Away code as specified in RFC 6455 (1001)
    Away,
    /// Protocol code as specified in RFC 6455 (1002)
    Protocol,
    /// Unsupported code as specified in RFC 6455 (1003)
    Unsupported,
    /// Invalid code as specified in RFC 6455 (1007)
    Invalid,
    /// Policy code as specified in RFC 6455 (1008)
    Policy,
    /// Size code as specified in RFC 6455 (1009)
    Size,
    /// Error code as specified in RFC 6455 (1011)
    Internal,
    /// Again code as specified in RFC 6455 (1013)
    Again,
    /// Close code did not match any known OPRF error code.
    Unknown,
}

impl OprfErrorKind {
    /// Returns `true` if this error originated from the [`OprfRequestAuthenticator`] (code 4500–4999).
    #[must_use]
    pub fn is_auth(&self) -> bool {
        *self == OprfErrorKind::Auth
    }
}

impl fmt::Display for OprfErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("timeout"),
            Self::CorruptedMessage => f.write_str("corrupted message"),
            Self::SessionReuse => f.write_str("session reuse"),
            Self::UnknownOprfKeyId => f.write_str("unknown OPRF key id"),
            Self::BlindedQueryIsIdentity => f.write_str("blinded query is identity"),
            Self::CoefficientsDoesNotEqualThreshold => {
                f.write_str("coefficients does not equal threshold")
            }
            Self::MissingMyCoefficient => f.write_str("missing my coefficient"),
            Self::UnsortedContributingParties => f.write_str("unsorted contributing parties"),
            Self::DuplicateCoefficient => f.write_str("duplicate coefficient"),
            Self::Auth => f.write_str("auth error"),
            Self::Away => f.write_str("away"),
            Self::Protocol => f.write_str("protocol error"),
            Self::Unsupported => f.write_str("unsupported"),
            Self::Invalid => f.write_str("invalid data"),
            Self::Policy => f.write_str("policy violation"),
            Self::Size => f.write_str("message too large"),
            Self::Internal => f.write_str("internal error"),
            Self::Again => f.write_str("try again later"),
            Self::Unknown => f.write_str("unknown error"),
        }
    }
}

impl From<u16> for OprfErrorKind {
    fn from(value: u16) -> Self {
        match value {
            oprf_error_codes::TIMEOUT => Self::Timeout,
            oprf_error_codes::CORRUPTED_MESSAGE => Self::CorruptedMessage,
            oprf_error_codes::SESSION_REUSE => Self::SessionReuse,
            oprf_error_codes::UNKNOWN_OPRF_KEY_ID => Self::UnknownOprfKeyId,
            oprf_error_codes::BLINDED_QUERY_IS_IDENTITY => Self::BlindedQueryIsIdentity,
            oprf_error_codes::COEFFICIENTS_DOES_NOT_EQUAL_THRESHOLD => {
                Self::CoefficientsDoesNotEqualThreshold
            }
            oprf_error_codes::MISSING_MY_COEFFICIENT => Self::MissingMyCoefficient,
            oprf_error_codes::UNSORTED_CONTRIBUTING_PARTIES => Self::UnsortedContributingParties,
            oprf_error_codes::DUPLICATE_COEFFICIENT => Self::DuplicateCoefficient,
            4500..=4999 => Self::Auth,
            1001 => Self::Away,
            1002 => Self::Protocol,
            1003 => Self::Unsupported,
            1007 => Self::Invalid,
            1008 => Self::Policy,
            1009 => Self::Size,
            1011 => Self::Internal,
            1013 => Self::Again,
            _ => Self::Unknown,
        }
    }
}

/// A request sent by a client to perform an OPRF evaluation.
#[derive(Clone, Serialize, Deserialize)]
pub struct OprfRequest<OprfRequestAuth> {
    /// Unique ID of the request (used to correlate responses).
    pub request_id: Uuid,
    /// Input point `B` of the OPRF, serialized as a `BabyJubJub` affine point.
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    pub blinded_query: ark_babyjubjub::EdwardsAffine,
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
            .finish()
    }
}

/// Trait defining the authentication mechanism for OPRF requests.
///
/// This trait enables the verification of OPRF requests to ensure they are
/// properly authenticated before processing and returns the [`OprfKeyId`] that shall be used for the distributed OPRF protocol. It is designed to be implemented
/// by authentication services that can validate the authenticity of incoming
/// OPRF requests.
///
/// # Error codes
///
/// When authentication fails, implementations must return an [`OprfRequestAuthenticatorError`]
/// with a WebSocket close code that is either in the **4500–4999** auth range or a valid
/// RFC 6455 close code. Codes in the range 4001–4499 are
/// reserved for service-level errors; using them in auth errors will cause ambiguous close codes.
///
/// Use [`oprf_error_codes`] constants and [`OprfRequestAuthenticatorError::new`] /
/// [`OprfRequestAuthenticatorError::with_message`] to construct the error.
#[async_trait]
pub trait OprfRequestAuthenticator: Send + Sync {
    /// Represents the authentication data type included in the OPRF request.
    type RequestAuth;

    /// Verifies the authenticity of an OPRF request and returns the [`OprfKeyId`] which the service shall use for the distributed OPRF protocol.
    ///
    /// On failure, returns an [`OprfRequestAuthenticatorError`] whose `code` must be either in
    /// the range **4500–4999** or a valid RFC 6455 close code.
    /// The code and message are forwarded verbatim to the client as a
    /// WebSocket close frame, so the message must not contain sensitive information.
    async fn authenticate(
        &self,
        req: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError>;
}

/// Represents an authentication error returned by an [`OprfRequestAuthenticator`].
///
/// The `code` and `message` are forwarded verbatim to the client as the WebSocket close frame.
///
/// # Error code range
///
/// Implementations **must** use a `code` that is either in the **4500–4999** auth range or a valid RFC 6455 close code. Codes 4001–4499 are reserved for service-level errors (see [`oprf_error_codes`]) and must not be used here.
///
/// # Message safety
///
/// The `message` field is sent to the client as-is. It must **not** contain sensitive information.
/// For debugging, use the `Debug` representation. Messages are bounded to at most [`CLOSE_FRAME_MAX_LENGTH`] bytes; use the [`crate::close_frame_message!`] macro to construct them with a compile-time length check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OprfRequestAuthenticatorError {
    code: u16,
    message: CloseFrameMessage,
}

impl std::error::Error for OprfRequestAuthenticatorError {}

impl core::fmt::Display for OprfRequestAuthenticatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "AuthError(code={}, msg={})",
            self.code, self.message
        ))
    }
}

/// A WebSocket close frame message string, bounded to [`CLOSE_FRAME_MAX_LENGTH`] bytes.
///
/// Use the [`crate::close_frame_message!`] macro for compile-time length validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseFrameMessage(&'static str);

impl core::fmt::Display for CloseFrameMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl TryFrom<&'static str> for CloseFrameMessage {
    type Error = String;

    fn try_from(value: &'static str) -> Result<Self, Self::Error> {
        if value.len() <= CLOSE_FRAME_MAX_LENGTH {
            Ok(CloseFrameMessage(value))
        } else {
            Err(value.to_string())
        }
    }
}

impl CloseFrameMessage {
    /// Creates a new [`CloseFrameMessage`], returning an error if `s` exceeds [`CLOSE_FRAME_MAX_LENGTH`] bytes.
    ///
    /// Prefer the [`crate::close_frame_message!`] macro for compile-time validation.
    ///
    /// # Errors
    /// Returns the owned version of `s` as an error if it exceeds [`CLOSE_FRAME_MAX_LENGTH`].
    pub fn new(s: &'static str) -> Result<Self, String> {
        Self::try_from(s)
    }

    /// Returns the inner `&'static str`.
    #[must_use]
    pub fn inner(&self) -> &'static str {
        self.0
    }
}

impl OprfRequestAuthenticatorError {
    /// Creates a new error with the given `code` and an empty message.
    #[must_use]
    pub fn new(code: u16) -> Self {
        Self::with_message(code, CloseFrameMessage(""))
    }

    /// Creates a new error with the given `code` and `message`.
    #[must_use]
    pub fn with_message(code: u16, message: CloseFrameMessage) -> Self {
        debug_assert!(
            (4500..=4999).contains(&code)
                || matches!(code, 1001..=1003 | 1007..=1009 | 1011 | 1013),
            "Auth error code must be in 4500–4999 or a valid RFC 6455 close code, got {code}"
        );
        Self { code, message }
    }

    /// Returns the WebSocket close code.
    #[must_use]
    pub fn code(&self) -> u16 {
        self.code
    }

    /// Returns the WebSocket close frame message.
    #[must_use]
    pub fn message(&self) -> &'static str {
        self.message.0
    }
}

/// Dynamic trait object for `OprfRequestAuthenticator` service.
pub type OprfRequestAuthService<RequestAuth> =
    Arc<dyn OprfRequestAuthenticator<RequestAuth = RequestAuth>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oprf_error_kind_from_service_codes() {
        assert_eq!(
            OprfErrorKind::from(oprf_error_codes::TIMEOUT),
            OprfErrorKind::Timeout
        );
        assert_eq!(
            OprfErrorKind::from(oprf_error_codes::CORRUPTED_MESSAGE),
            OprfErrorKind::CorruptedMessage
        );
        assert_eq!(
            OprfErrorKind::from(oprf_error_codes::SESSION_REUSE),
            OprfErrorKind::SessionReuse
        );
        assert_eq!(
            OprfErrorKind::from(oprf_error_codes::UNKNOWN_OPRF_KEY_ID),
            OprfErrorKind::UnknownOprfKeyId
        );
        assert_eq!(
            OprfErrorKind::from(oprf_error_codes::BLINDED_QUERY_IS_IDENTITY),
            OprfErrorKind::BlindedQueryIsIdentity
        );
        assert_eq!(
            OprfErrorKind::from(oprf_error_codes::COEFFICIENTS_DOES_NOT_EQUAL_THRESHOLD),
            OprfErrorKind::CoefficientsDoesNotEqualThreshold
        );
        assert_eq!(
            OprfErrorKind::from(oprf_error_codes::MISSING_MY_COEFFICIENT),
            OprfErrorKind::MissingMyCoefficient
        );
        assert_eq!(
            OprfErrorKind::from(oprf_error_codes::UNSORTED_CONTRIBUTING_PARTIES),
            OprfErrorKind::UnsortedContributingParties
        );
        assert_eq!(
            OprfErrorKind::from(oprf_error_codes::DUPLICATE_COEFFICIENT),
            OprfErrorKind::DuplicateCoefficient
        );
    }

    #[test]
    fn oprf_error_kind_from_rfc6455_codes() {
        assert_eq!(OprfErrorKind::from(1001), OprfErrorKind::Away);
        assert_eq!(OprfErrorKind::from(1002), OprfErrorKind::Protocol);
        assert_eq!(OprfErrorKind::from(1003), OprfErrorKind::Unsupported);
        assert_eq!(OprfErrorKind::from(1007), OprfErrorKind::Invalid);
        assert_eq!(OprfErrorKind::from(1008), OprfErrorKind::Policy);
        assert_eq!(OprfErrorKind::from(1009), OprfErrorKind::Size);
        assert_eq!(OprfErrorKind::from(1011), OprfErrorKind::Internal);
        assert_eq!(OprfErrorKind::from(1013), OprfErrorKind::Again);
    }

    #[test]
    fn oprf_error_kind_from_auth_range() {
        assert_eq!(OprfErrorKind::from(4500), OprfErrorKind::Auth);
        assert_eq!(OprfErrorKind::from(4750), OprfErrorKind::Auth);
        assert_eq!(OprfErrorKind::from(4999), OprfErrorKind::Auth);
    }

    #[test]
    fn oprf_error_kind_from_unknown_codes() {
        // Gap between service codes and auth range
        assert_eq!(OprfErrorKind::from(4010), OprfErrorKind::Unknown);
        assert_eq!(OprfErrorKind::from(4499), OprfErrorKind::Unknown);
        // RFC 6455 codes not explicitly mapped
        assert_eq!(OprfErrorKind::from(1000), OprfErrorKind::Unknown);
        assert_eq!(OprfErrorKind::from(1004), OprfErrorKind::Unknown);
        assert_eq!(OprfErrorKind::from(1005), OprfErrorKind::Unknown);
        assert_eq!(OprfErrorKind::from(1010), OprfErrorKind::Unknown);
        // Out-of-range
        assert_eq!(OprfErrorKind::from(0), OprfErrorKind::Unknown);
        assert_eq!(OprfErrorKind::from(999), OprfErrorKind::Unknown);
        assert_eq!(OprfErrorKind::from(5000), OprfErrorKind::Unknown);
        assert_eq!(OprfErrorKind::from(u16::MAX), OprfErrorKind::Unknown);
    }

    #[test]
    fn oprf_error_kind_is_auth() {
        assert!(OprfErrorKind::Auth.is_auth());
        assert!(!OprfErrorKind::Timeout.is_auth());
        assert!(!OprfErrorKind::Unknown.is_auth());
    }
}
