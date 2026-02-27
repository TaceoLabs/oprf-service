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
//!   query parameter (`?x-oprf-protocol-version=<version>`) instead. The server
//!   must be updated to accept the version from query parameters.
//! - **Close frames**: The browser manages the WebSocket close handshake. Unlike
//!   the native implementation, we do not explicitly send close frames on errors.

use crate::{Connector, Error};
use futures::{SinkExt, StreamExt};
use gloo_net::websocket::{Message, WebSocketError, futures::WebSocket};
use oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER;
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
    /// Creates a new session at the provided service.
    ///
    /// Note: Browser WebSocket API does not support custom HTTP headers during
    /// the upgrade handshake. The protocol version is sent as a query parameter
    /// instead of the `OPRF_PROTOCOL_VERSION_HEADER` header.
    pub(crate) async fn new(
        service: String,
        module: String,
        _connector: Connector,
    ) -> Result<Self, Error> {
        let version = env!("CARGO_PKG_VERSION");
        let endpoint =
            format!("{service}/api/{module}/oprf?{OPRF_PROTOCOL_VERSION_HEADER}={version}")
                .replacen("http", "ws", 1);

        tracing::trace!("> sending request to {endpoint}..");

        let ws = WebSocket::open(&endpoint)
            .map_err(|e| Error::WsError(format!("failed to open {endpoint}: {e:?}")))?;
        let (write, read) = ws.split();

        Ok(Self {
            service,
            write,
            read,
        })
    }

    /// Attempts to send the provided message to the web-socket.
    pub(crate) async fn send<Msg: Serialize>(&mut self, msg: Msg) -> Result<(), Error> {
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).expect("Can serialize msg");
        self.write
            .send(Message::Bytes(buf))
            .await
            .map_err(|e| Error::WsError(format!("send failed: {e:?}")))?;
        Ok(())
    }

    /// Attempts to read the provided message from the web-socket.
    pub(crate) async fn read<Msg: for<'de> Deserialize<'de>>(&mut self) -> Result<Msg, Error> {
        match self.read.next().await {
            Some(Ok(Message::Bytes(bytes))) => {
                if let Ok(response) = ciborium::from_reader::<Msg, _>(bytes.as_slice()) {
                    Ok(response)
                } else {
                    tracing::trace!("could not parse message...");
                    Err(Error::UnexpectedMsg)
                }
            }
            Some(Ok(Message::Text(_))) => {
                tracing::trace!("did get text instead of binary...");
                Err(Error::UnexpectedMsg)
            }
            Some(Err(WebSocketError::ConnectionClose(event))) => {
                tracing::trace!("did get close frame: code={}", event.code);
                if event.code != CLOSE_CODE_NORMAL {
                    Err(Error::ServerError(format!(
                        "{}: {}",
                        event.code, event.reason
                    )))
                } else {
                    Err(Error::Eof)
                }
            }
            Some(Err(e)) => Err(Error::WsError(format!("read failed: {e:?}"))),
            None => Err(Error::Eof),
        }
    }

    /// Gracefully closes the web-socket.
    pub(crate) async fn graceful_close(mut self) {
        // Close the sink, which triggers the browser's WebSocket close handshake.
        let _ = self.write.close().await;
    }
}
