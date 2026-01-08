//! Websocket session management for the client.
//!
//! This module exposes functionality for handling a single web-socket connection with tungstenite. The sessions are very thin and handle errors very conservatively. If the implementation encounters anything that is unexpected, the session will be immediately terminated.
//!
//! What is more, we implement the closing handshake at a best-effort basis. This means we try to send `Close` frames if we close the connection, but if there are problems with sending the `Close` frame we simply ignore the errors.

use crate::Error;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream,
    tungstenite::{
        self,
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};

type WebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// The opened session. Thin wrapper around tungstenite web-socket stream.
///
/// When [`WebSocketSession::send`] or [`WebSocketSession::read`] returns an error, the implementation will try to send a `Close` frame. You don't need to do that at callsite.
pub(crate) struct WebSocketSession {
    pub(crate) service: String,
    inner: WebSocket,
}

impl WebSocketSession {
    /// Creates a new session at the provided service. Replaces `http` and `https` protocol prefixes with `ws` or `wss` respectively.
    ///
    /// The service string should only contain how to connect to the host, the implementation will append `/api/v1/oprf`.
    pub(crate) async fn new(service: String, connector: Connector) -> Result<Self, Error> {
        let endpoint = format!("{service}/api/v1/oprf")
            .replace("https", "wss")
            .replace("http", "ws");
        tracing::trace!("> sending request to {endpoint}..");

        let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(
            endpoint,
            None,
            false,
            Some(connector),
        )
        .await?;
        Ok(Self { service, inner: ws })
    }

    /// Attempts to send the provided message to the web-socket.
    ///
    /// On error tries to send a `Close` frame.
    pub(crate) async fn send<Msg: Serialize>(&mut self, msg: Msg) -> Result<(), Error> {
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).expect("Can serialize msg");
        if let Err(err) = self.inner.send(tungstenite::Message::binary(buf)).await {
            // we close only on best effort basis
            let _ = self
                .inner
                .close(Some(CloseFrame {
                    code: CloseCode::Error,
                    reason: "error during ws send".into(),
                }))
                .await;
            Err(Error::WsError(err))
        } else {
            Ok(())
        }
    }

    /// Attempts to read the provided message from the web-socket.
    ///
    /// On error tries to send a `Close` frame.
    pub(crate) async fn read<Msg: for<'de> Deserialize<'de>>(&mut self) -> Result<Msg, Error> {
        match self.inner.next().await {
            Some(Ok(msg)) => {
                // we only expect ciborium
                if let tungstenite::Message::Binary(bytes) = msg {
                    if let Ok(response) = ciborium::from_reader(bytes.as_ref()) {
                        Ok(response)
                    } else {
                        tracing::trace!("could not parse message...");
                        // we close the websocket on best-effort basis
                        let _ = self.inner.close(None).await;
                        Err(Error::UnexpectedMsg)
                    }
                } else {
                    // we close the websocket on best-effort basis
                    tracing::trace!("did get something else than binary...");
                    let _ = self
                        .inner
                        .close(Some(CloseFrame {
                            code: CloseCode::Unsupported,
                            reason: "expects only binary".into(),
                        }))
                        .await;
                    Err(Error::UnexpectedMsg)
                }
            }
            Some(Err(err)) => {
                // we close the websocket on best-effort basis
                let _ = self
                    .inner
                    .close(Some(CloseFrame {
                        code: CloseCode::Error,
                        reason: err.to_string().into(),
                    }))
                    .await;
                Err(Error::WsError(err))
            }
            None => {
                // other side closed connection
                Err(Error::Eof)
            }
        }
    }

    /// Gracefully closes the web-socket by sending a `Close` frame with `CloseCode::Normal`.
    pub(crate) async fn graceful_close(mut self) {
        // we close the websocket on best-effort basis
        let _ = self
            .inner
            .close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "success".into(),
            }))
            .await;
    }
}
