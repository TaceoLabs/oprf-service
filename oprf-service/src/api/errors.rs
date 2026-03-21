//! This module defines the [`Error`] the websocket connection may encounter during a OPRF request. It further provides a method to transform the encountered errors into a close frame if necessary.

use std::io::ErrorKind;

use axum::extract::ws::{CloseFrame, Utf8Bytes, close_code};
use oprf_types::{
    OprfKeyId,
    api::{OprfRequestAuthenticatorError, oprf_error_codes},
};
use tracing::instrument;
use tungstenite::error::ProtocolError;
use uuid::Uuid;

macro_rules! to_close_frame_bytes {
    ($s: expr) => {
        Utf8Bytes::from_static(oprf_types::close_frame_message!($s).inner())
    };
}

/// All errors that may occur during an OPRF request.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("Session {0} already exists")]
    SessionReuse(Uuid),
    #[error("OprfKeyId {0} does not exist")]
    UnknownOprfKeyId(OprfKeyId),
    #[error("Connection closed by peer")]
    ConnectionClosed,
    #[error(transparent)]
    Axum(#[from] axum::Error),
    #[error("unexpected message")]
    UnexpectedMessage,
    #[error("cannot authenticate: {0}")]
    Auth(#[from] OprfRequestAuthenticatorError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Cbor(#[from] ciborium::de::Error<std::io::Error>),
    #[error("blinded query must not be identity")]
    BlindedQueryIsIdentity,
    #[error("expected {threshold} contributing parties but got {num_coeffs}")]
    ThresholdContributingPartiesMissmatch { threshold: usize, num_coeffs: usize },
    #[error("contributing parties does not contain my coefficient")]
    MissingMyCoefficient,
    #[error("contributing parties are not sorted")]
    ContributionsNotSorted,
    #[error("contributing parties contains duplicate coefficients")]
    DuplicateCoefficients,
}

impl Error {
    /// Transforms the error into a [`CloseFrame`](https://docs.rs/axum/latest/axum/extract/ws/struct.CloseFrame.html) if necessary.
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn into_close_frame(self) -> Option<CloseFrame> {
        tracing::debug!("{self:?}");
        match self {
            Error::ConnectionClosed => {
                // nothing to do here
                None
            }
            Error::BlindedQueryIsIdentity => Some(CloseFrame {
                code: oprf_error_codes::BLINDED_QUERY_IS_IDENTITY,
                reason: to_close_frame_bytes!("blinded query must not be identity"),
            }),
            Error::UnknownOprfKeyId(_) => Some(CloseFrame {
                code: oprf_error_codes::UNKNOWN_OPRF_KEY_ID,
                reason: to_close_frame_bytes!("unknown OPRF key id"),
            }),
            Error::SessionReuse(_) => Some(CloseFrame {
                code: oprf_error_codes::SESSION_REUSE,
                reason: to_close_frame_bytes!("session already in use"),
            }),
            Error::Axum(axum_error) => {
                let inner = axum_error.into_inner();
                if let Some(err) = inner.downcast_ref::<tungstenite::Error>() {
                    match err {
                        tungstenite::Error::Protocol(
                            ProtocolError::ResetWithoutClosingHandshake,
                        ) => {
                            tracing::trace!(
                                "nothing to do client closed session (tungstenite error)"
                            );
                            return None;
                        }
                        tungstenite::Error::Capacity(_) => {
                            return Some(CloseFrame {
                                code: close_code::SIZE,
                                reason: to_close_frame_bytes!("size exceeds max frame length"),
                            });
                        }
                        _ => {}
                    }
                } else if let Some(io_err) = inner.downcast_ref::<std::io::Error>()
                    && io_err.kind() == ErrorKind::ConnectionReset
                {
                    tracing::trace!("nothing to do client closed session (Os error)");
                    return None;
                }

                Some(CloseFrame {
                    code: close_code::ERROR,
                    reason: to_close_frame_bytes!("unexpected error"),
                })
            }
            Error::UnexpectedMessage => Some(CloseFrame {
                code: close_code::UNSUPPORTED,
                reason: to_close_frame_bytes!("unexpected ws message"),
            }),
            Error::Auth(err) => Some(CloseFrame {
                code: err.code(),
                reason: Utf8Bytes::from_static(err.message()),
            }),
            Error::Json(_) => Some(CloseFrame {
                code: oprf_error_codes::CORRUPTED_MESSAGE,
                reason: to_close_frame_bytes!("invalid json"),
            }),
            Error::Cbor(_) => Some(CloseFrame {
                code: oprf_error_codes::CORRUPTED_MESSAGE,
                reason: to_close_frame_bytes!("invalid cbor"),
            }),
            Error::ThresholdContributingPartiesMissmatch {
                threshold: _,
                num_coeffs: _,
            } => Some(CloseFrame {
                code: oprf_error_codes::COEFFICIENTS_DOES_NOT_EQUAL_THRESHOLD,
                reason: to_close_frame_bytes!("not exactly threshold many contributions"),
            }),
            Error::ContributionsNotSorted => Some(CloseFrame {
                code: oprf_error_codes::UNSORTED_CONTRIBUTING_PARTIES,
                reason: to_close_frame_bytes!("contributing parties are not sorted"),
            }),
            Error::DuplicateCoefficients => Some(CloseFrame {
                code: oprf_error_codes::DUPLICATE_COEFFICIENT,
                reason: to_close_frame_bytes!(
                    "contributing parties contains duplicate coefficients"
                ),
            }),
            Error::MissingMyCoefficient => Some(CloseFrame {
                code: oprf_error_codes::MISSING_MY_COEFFICIENT,
                reason: to_close_frame_bytes!(
                    "contributing parties does not contain my coefficient"
                ),
            }),
        }
    }
}
