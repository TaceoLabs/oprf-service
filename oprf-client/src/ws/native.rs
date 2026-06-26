//! Websocket session management for the client.
//!
//! This module exposes functionality for handling a single web-socket connection with tungstenite. The sessions are very thin and handle errors very conservatively. If the implementation encounters anything that is unexpected, the session will be immediately terminated.
//!
//! The client does not send close frames. The server drives the teardown: after the protocol completes (or on error/timeout) the server sends a close frame and drains the socket until the client drops.

use crate::{NodeError, ServiceError};
use futures::{SinkExt, StreamExt};
use http::Uri;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream,
    tungstenite::{self, protocol::frame::coding::CloseCode},
};
use uuid::Uuid;

impl From<tungstenite::Error> for NodeError {
    fn from(value: tungstenite::Error) -> Self {
        NodeError::WsError(Box::new(value))
    }
}

type WebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// The opened session. Thin wrapper around tungstenite web-socket stream.
pub(crate) struct WebSocketSession {
    pub(crate) service: String,
    inner: WebSocket,
}

impl WebSocketSession {
    /// Creates a new session at the provided endpoint.
    pub(crate) async fn new(
        endpoint: Uri,
        request_id: Uuid,
        connector: Connector,
    ) -> Result<Self, NodeError> {
        let service = endpoint
            .authority()
            .map_or_else(|| "unknown authority".to_string(), ToString::to_string);
        tracing::trace!("> sending request to {service}..");
        let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(
            super::append_client_version_to_query(&endpoint, request_id),
            None,
            false,
            Some(connector),
        )
        .await?;
        Ok(Self { service, inner: ws })
    }

    /// Attempts to send the provided message to the web-socket.
    pub(crate) async fn send<Msg: Serialize>(&mut self, msg: Msg) -> Result<(), NodeError> {
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).expect("Can serialize msg");
        if let Err(err) = self.inner.send(tungstenite::Message::binary(buf)).await {
            Err(NodeError::WsError(Box::new(err)))
        } else {
            Ok(())
        }
    }

    /// Attempts to read the provided message from the web-socket.
    pub(crate) async fn read<Msg: for<'de> Deserialize<'de>>(&mut self) -> Result<Msg, NodeError> {
        let msg = match self.inner.next().await {
            Some(Ok(msg)) => msg,
            Some(Err(err)) => {
                return Err(err.into());
            }
            None => {
                tracing::trace!(
                    "Server closed connection during protocol while waiting for another message"
                );
                return Err(NodeError::WsError(Box::new(tungstenite::Error::Io(
                    std::io::Error::other("unexpected connection close by server"),
                ))));
            }
        };

        match msg {
            tungstenite::Message::Binary(bytes) => match ciborium::from_reader(bytes.as_ref()) {
                Ok(msg) => Ok(msg),
                Err(_) => Err(NodeError::UnexpectedMessage {
                    reason: "could not parse message from server",
                }),
            },
            tungstenite::Message::Close(frame) => {
                tracing::trace!("server send close frame - tearing down connection");
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
            tungstenite::Message::Text(_) => Err(NodeError::UnexpectedMessage {
                reason: "text frame received",
            }),
            _ => Err(NodeError::UnexpectedMessage {
                reason: "non-binary frame received",
            }),
        }
    }
}
