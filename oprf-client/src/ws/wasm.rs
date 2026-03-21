//! WASM WebSocket session using gloo-net.
//!
//! Provides the same `WebSocketSession` interface as the native implementation,
//! backed by the browser's WebSocket API via `gloo-net`.
//!
//! ## Differences from native
//!
//! - **TLS**: Handled transparently by the browser. The [`Connector`] parameter
//!   is a no-op placeholder for API compatibility.
//! - **Protocol version**: The browser WebSocket API does not support custom HTTP
//!   headers during the upgrade handshake. The protocol version is sent as a
//!   query parameter (`?version=<version>`) instead.
//! - **Close frames**: The browser manages the WebSocket close handshake. Unlike
//!   the native implementation, we do not explicitly send close frames on errors.

use crate::{Connector, NodeError, ServiceError};
use futures::{SinkExt, StreamExt};
use gloo_net::websocket::{Message, WebSocketError, futures::WebSocket};
use http::Uri;
use serde::{Deserialize, Serialize};

const CLOSE_CODE_NORMAL: u16 = 1000;

/// The opened session. Thin wrapper around a gloo-net WebSocket stream.
///
/// Mirrors the native `WebSocketSession` interface.
pub(crate) struct WebSocketSession {
    pub(crate) service: String,
    write: futures::stream::SplitSink<WebSocket, Message>,
    read: futures::stream::SplitStream<WebSocket>,
}

impl WebSocketSession {
    /// Creates a new session at the provided endpoint.
    ///
    /// Expects a valid `ws://` or `wss://` URI  
    #[allow(
        clippy::unused_async,
        reason = "Want to have async to have equivalent signature with native"
    )]
    pub(crate) async fn new(endpoint: Uri, _connector: Connector) -> Result<Self, NodeError> {
        let version = env!("CARGO_PKG_VERSION");
        let has_query = endpoint.query().is_some();
        let mut endpoint = endpoint.to_string();

        endpoint.push(if has_query { '&' } else { '?' });
        endpoint.push_str("version=");
        endpoint.push_str(version);

        let service = endpoint.clone();
        tracing::trace!("> sending request to {service}..");

        let ws = WebSocket::open(&endpoint).map_err(|e| {
            NodeError::WsError(Box::new(std::io::Error::other(format!(
                "failed to open {endpoint}: {e:?}"
            ))))
        })?;
        let (write, read) = ws.split();

        Ok(Self {
            service,
            write,
            read,
        })
    }

    /// Attempts to send the provided message to the web-socket.
    pub(crate) async fn send<Msg: Serialize>(&mut self, msg: Msg) -> Result<(), NodeError> {
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).expect("Can serialize msg");
        self.write.send(Message::Bytes(buf)).await.map_err(|e| {
            NodeError::WsError(Box::new(std::io::Error::other(format!(
                "send failed: {e:?}"
            ))))
        })?;
        Ok(())
    }

    /// Attempts to read the provided message from the web-socket.
    pub(crate) async fn read<Msg: for<'de> Deserialize<'de>>(&mut self) -> Result<Msg, NodeError> {
        match self.read.next().await {
            Some(Ok(Message::Bytes(bytes))) => {
                if let Ok(response) = ciborium::from_reader::<Msg, _>(bytes.as_slice()) {
                    Ok(response)
                } else {
                    tracing::trace!("could not parse message...");
                    Err(NodeError::UnexpectedMessage {
                        reason: "could not parse message from server".to_owned(),
                    })
                }
            }
            Some(Ok(Message::Text(_))) => {
                tracing::trace!("did get text instead of binary...");
                Err(NodeError::UnexpectedMessage {
                    reason: "text frame received".to_owned(),
                })
            }
            Some(Err(WebSocketError::ConnectionClose(event))) => {
                tracing::trace!("did get close frame: code={}", event.code);
                if event.code == CLOSE_CODE_NORMAL {
                    Err(NodeError::UnexpectedMessage {
                        reason: "Server closed websocket".to_owned(),
                    })
                } else {
                    Err(NodeError::ServiceError(ServiceError {
                        error_code: event.code,
                        msg: (!event.reason.is_empty()).then_some(event.reason),
                        kind: oprf_types::api::OprfErrorKind::from(event.code),
                    }))
                }
            }
            Some(Err(e)) => Err(NodeError::WsError(Box::new(std::io::Error::other(
                format!("read failed: {e:?}"),
            )))),
            None => Err(NodeError::UnexpectedMessage {
                reason: "Server closed connection".to_owned(),
            }),
        }
    }

    /// Gracefully closes the web-socket.
    pub(crate) async fn graceful_close(mut self) {
        // Close the sink, which triggers the browser's WebSocket close handshake.
        // We ignore the result as this is best effort close anyways.
        let _result = self.write.close().await;
    }
}
