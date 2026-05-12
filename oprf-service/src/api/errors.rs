//! This module defines the [`Error`] the websocket connection may encounter during a OPRF request. It further provides a method to transform the encountered errors into a close frame if necessary.

use std::io::ErrorKind;

use axum::extract::ws::{CloseFrame, Utf8Bytes, close_code};
use oprf_types::{
    OprfKeyId,
    api::{OprfRequestAuthenticatorError, oprf_error_codes},
};
use tungstenite::error::ProtocolError;
use uuid::Uuid;

macro_rules! to_close_frame_bytes {
    ($s: expr) => {
        Utf8Bytes::from(oprf_types::close_frame_message!($s).inner())
    };
}

/// All errors that may occur during an OPRF request.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("Session {0} already exists")]
    SessionReuse(Uuid),
    #[error("OprfKeyId {0} does not exist")]
    UnknownOprfKeyId(OprfKeyId),
    #[error("Connection closed by client")]
    ConnectionClosed,
    #[error(transparent)]
    Axum(#[from] axum::Error),
    #[error("unexpected message - received PING/PONG or user switched encoding between messages")]
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
    pub(crate) fn into_close_frame(self) -> Option<CloseFrame> {
        // Prepare the error log line as we need to consume self.
        let maybe_log_line = format!("{self}");
        let close_frame = match self {
            // for Axum and auth error we short circuit and don't print the log line
            // * handle axum error log in the dedicated method
            // * handle auth error log in downstream crate
            Error::Axum(axum_error) => return handle_axum_error(axum_error),
            Error::Auth(err) => {
                return Some(CloseFrame {
                    code: err.code(),
                    reason: Utf8Bytes::from(err.message()),
                });
            }
            // For all other errors, we print it before returning the CloseFrame.
            Error::ConnectionClosed => {
                // nothing to do here
                tracing::debug!("nothing to do client closed session");
                return None;
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
            Error::UnexpectedMessage => Some(CloseFrame {
                code: close_code::UNSUPPORTED,
                reason: to_close_frame_bytes!("unexpected ws message"),
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
        };
        tracing::warn!(user_error = true, "{maybe_log_line}");
        close_frame
    }
}

fn handle_axum_error(err: axum::Error) -> Option<CloseFrame> {
    let inner = err.into_inner();
    if let Some(err) = inner.downcast_ref::<tungstenite::Error>() {
        match err {
            tungstenite::Error::Protocol(ProtocolError::ResetWithoutClosingHandshake) => {
                tracing::debug!("nothing to do client closed session");
                return None;
            }
            tungstenite::Error::Io(io_err) if io_err.kind() == ErrorKind::ConnectionReset => {
                tracing::debug!("nothing to do client closed session");
                return None;
            }
            tungstenite::Error::Capacity(_) => {
                tracing::warn!(user_error=true, %err, "websocket message too large");
                return Some(CloseFrame {
                    code: close_code::SIZE,
                    reason: to_close_frame_bytes!("size exceeds max frame length"),
                });
            }
            _ => {}
        }
    }
    // There was an unknown Axum error
    tracing::error!(err = %inner, "unknown axum error");
    Some(CloseFrame {
        code: close_code::ERROR,
        reason: to_close_frame_bytes!("unexpected error"),
    })
}
