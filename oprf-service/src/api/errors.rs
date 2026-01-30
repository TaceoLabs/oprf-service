//! This module defines the [`Error`] the websocket connection may encounter during a OPRF request. It further provides a method to transform the encountered errors into a close frame if necessary.

use std::io::ErrorKind;

use crate::services::oprf_key_material_store::OprfKeyMaterialStoreError;
use axum::extract::ws::{CloseFrame, close_code};
use oprf_types::api::oprf_error_codes;
use tracing::instrument;
use tungstenite::error::ProtocolError;
use uuid::Uuid;

/// All errors that may occur during an OPRF request.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("Session {0} already exists")]
    SessionReuse(Uuid),
    #[error("Connection closed by peer")]
    ConnectionClosed,
    #[error(transparent)]
    Axum(#[from] axum::Error),
    #[error("unexpected message")]
    UnexpectedMessage,
    #[error("cannot authenticate: {0}")]
    Auth(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Cbor(#[from] ciborium::de::Error<std::io::Error>),
    #[error("bad request: {0}")]
    BadRequest(String),
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
            Error::SessionReuse(session_id) => Some(CloseFrame {
                code: close_code::POLICY,
                reason: format!("session {session_id} already exists").into(),
            }),
            Error::Axum(axum_error) => {
                // try down casting if close-without-handshake
                let inner = axum_error.into_inner();
                if let Some(tungstenite::Error::Protocol(
                    ProtocolError::ResetWithoutClosingHandshake,
                )) = inner.downcast_ref()
                {
                    tracing::trace!("nothing to do client closed session (tungstenite error)");
                    None
                } else if let Some(io_err) = inner.downcast_ref::<std::io::Error>()
                    && io_err.kind() == ErrorKind::ConnectionReset
                {
                    tracing::trace!("nothing to do client closed session (Os error)");
                    None
                } else {
                    Some(CloseFrame {
                        code: close_code::ERROR,
                        reason: "unexpected error".into(),
                    })
                }
            }
            Error::UnexpectedMessage => Some(CloseFrame {
                code: close_code::UNSUPPORTED,
                reason: "unexpected message".into(),
            }),
            Error::Auth(err) => Some(CloseFrame {
                code: close_code::POLICY,
                reason: err.into(),
            }),
            Error::BadRequest(err) => Some(CloseFrame {
                code: oprf_error_codes::BAD_REQUEST,
                reason: err.into(),
            }),
            Error::Json(err) => Some(CloseFrame {
                code: oprf_error_codes::BAD_REQUEST,
                reason: err.to_string().into(),
            }),
            Error::Cbor(err) => Some(CloseFrame {
                code: oprf_error_codes::BAD_REQUEST,
                reason: err.to_string().into(),
            }),
        }
    }
}

impl From<OprfKeyMaterialStoreError> for Error {
    fn from(value: OprfKeyMaterialStoreError) -> Self {
        // we bind it like this in case we add an error later, the compiler will scream at us.
        match value {
            OprfKeyMaterialStoreError::UnknownOprfKeyId(oprf_key_id) => {
                Self::BadRequest(format!("unknown OPRF key id: {oprf_key_id}"))
            }
        }
    }
}
