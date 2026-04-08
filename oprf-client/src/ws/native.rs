//! Websocket session management for the client.
//!
//! This module exposes functionality for handling a single web-socket connection with tungstenite. The sessions are very thin and handle errors very conservatively. If the implementation encounters anything that is unexpected, the session will be immediately terminated.
//!
//! What is more, we implement the closing handshake at a best-effort basis. This means we try to send `Close` frames if we close the connection, but if there are problems with sending the `Close` frame we simply ignore the errors.

use crate::{NodeError, ServiceError};
use futures::{SinkExt, StreamExt};
use http::Uri;
use oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream,
    tungstenite::{
        self, ClientRequestBuilder,
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};

impl From<tungstenite::Error> for NodeError {
    fn from(value: tungstenite::Error) -> Self {
        NodeError::WsError(Box::new(value))
    }
}

type WebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// The opened session. Thin wrapper around tungstenite web-socket stream.
///
/// When [`WebSocketSession::send`] or [`WebSocketSession::read`] returns an error, the implementation will try to send a `Close` frame. You don't need to do that at callsite.
pub(crate) struct WebSocketSession {
    pub(crate) service: String,
    inner: WebSocket,
}

impl WebSocketSession {
    /// Tries to close the websocket on a best effort basis by sending a close-frame to the server and initiating tear down.
    async fn best_effort_close(&mut self, code: CloseCode, reason: impl Into<String>) {
        if let Err(err) = self
            .inner
            .close(Some(CloseFrame {
                code,
                reason: reason.into().into(),
            }))
            .await
        {
            tracing::trace!(
                "Received an error when trying to best effort close {}: {err:?}",
                self.service
            );
        }
    }

    /// Tries to close the websocket on a best effort basis without sending a close-frame to the server and initiating tear down.
    async fn silent_close(&mut self) {
        if let Err(err) = self.inner.close(None).await {
            tracing::trace!(
                "Received an error when trying to best effort close {}: {err:?}",
                self.service
            );
        }
    }

    /// Calls [`Self::best_effort_close`] and returns an [`NodeError::UnexpectedMessage`] with the provided reason.
    async fn protocol_error<T>(&mut self, reason: T) -> NodeError
    where
        String: From<T>,
    {
        let reason = String::from(reason);
        self.best_effort_close(CloseCode::Unsupported, reason.clone())
            .await;

        NodeError::UnexpectedMessage { reason }
    }
    /// Creates a new session at the provided endpoint.
    pub(crate) async fn new(endpoint: Uri, connector: Connector) -> Result<Self, NodeError> {
        let version = env!("CARGO_PKG_VERSION");
        let service = endpoint
            .authority()
            .map_or_else(|| "unknown authority".to_string(), ToString::to_string);
        tracing::trace!("> sending request to {service}..");
        let request = ClientRequestBuilder::new(endpoint)
            .with_header(OPRF_PROTOCOL_VERSION_HEADER.as_str(), version);

        let (ws, _) =
            tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
                .await?;
        Ok(Self { service, inner: ws })
    }

    /// Attempts to send the provided message to the web-socket.
    ///
    /// On error tries to send a `Close` frame.
    pub(crate) async fn send<Msg: Serialize>(&mut self, msg: Msg) -> Result<(), NodeError> {
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).expect("Can serialize msg");
        if let Err(err) = self.inner.send(tungstenite::Message::binary(buf)).await {
            self.best_effort_close(CloseCode::Error, "error during ws send")
                .await;
            Err(NodeError::WsError(Box::new(err)))
        } else {
            Ok(())
        }
    }

    /// Attempts to read the provided message from the web-socket.
    ///
    /// On error tries to send a `Close` frame.
    pub(crate) async fn read<Msg: for<'de> Deserialize<'de>>(&mut self) -> Result<Msg, NodeError> {
        let msg = match self.inner.next().await {
            Some(Ok(msg)) => msg,
            Some(Err(err)) => {
                self.best_effort_close(CloseCode::Error, err.to_string())
                    .await;
                return Err(err.into());
            }
            None => {
                return Err(NodeError::WsError(Box::new(tungstenite::Error::Io(
                    std::io::Error::other("server closed connection without sending close-frame"),
                ))));
            }
        };

        match msg {
            tungstenite::Message::Binary(bytes) => match ciborium::from_reader(bytes.as_ref()) {
                Ok(msg) => Ok(msg),
                Err(_) => Err(self
                    .protocol_error("could not parse message from server")
                    .await),
            },

            tungstenite::Message::Close(frame) => {
                self.silent_close().await;

                if let Some(frame) = frame
                    && frame.code != CloseCode::Normal
                {
                    Err(NodeError::ServiceError(ServiceError {
                        error_code: u16::from(frame.code),
                        msg: (!frame.reason.is_empty()).then(|| frame.reason.to_string()),
                        kind: oprf_types::api::OprfErrorKind::from(u16::from(frame.code)),
                    }))
                } else {
                    Err(NodeError::WsError(Box::new(tungstenite::Error::Io(
                        std::io::Error::other(
                            "Server closed websocket without finishing protocol - EOF",
                        ),
                    ))))
                }
            }

            tungstenite::Message::Text(_) => Err(self.protocol_error("text frame received").await),

            _ => Err(self.protocol_error("non-binary frame received").await),
        }
    }

    /// Gracefully closes the web-socket by sending a `Close` frame with `CloseCode::Normal`.
    pub(crate) async fn graceful_close(mut self) {
        self.best_effort_close(CloseCode::Normal, "success").await;
    }
}
