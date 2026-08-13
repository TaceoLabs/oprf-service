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
    tungstenite::{self, ClientRequestBuilder, protocol::frame::coding::CloseCode},
};
use uuid::Uuid;

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

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
        let endpoint = super::append_client_version_to_query(&endpoint, request_id)
            .parse()
            .map_err(|err| NodeError::WsError(Box::new(err)))?;
        let request = ClientRequestBuilder::new(endpoint)
            .with_header(http::header::USER_AGENT.as_str(), USER_AGENT);
        let (ws, _) =
            tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
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

#[cfg(test)]
mod tests {
    use http::header;
    use tokio::net::TcpListener;
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::handshake::server::{Request, Response},
    };

    use super::{USER_AGENT, WebSocketSession};

    #[tokio::test]
    #[allow(
        clippy::result_large_err,
        reason = "tungstenite defines the handshake callback's response error type"
    )]
    async fn sends_user_agent_during_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("can bind test listener");
        let address = listener.local_addr().expect("test listener has an address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("can accept test connection");
            let mut user_agent = None;
            accept_hdr_async(stream, |request: &Request, response: Response| {
                user_agent = Some(
                    request
                        .headers()
                        .get(header::USER_AGENT)
                        .expect("websocket handshake contains a user-agent")
                        .to_str()
                        .expect("user-agent is valid text")
                        .to_owned(),
                );
                Ok(response)
            })
            .await
            .expect("can complete websocket handshake");
            user_agent
        });

        let endpoint = format!("ws://{address}/api/test/oprf")
            .parse()
            .expect("test endpoint is a valid URI");
        let _session = WebSocketSession::new(
            endpoint,
            uuid::Uuid::new_v4(),
            tokio_tungstenite::Connector::Plain,
        )
        .await
        .expect("can open websocket session");
        let received_user_agent = server.await.expect("test server completes successfully");

        assert_eq!(received_user_agent.as_deref(), Some(USER_AGENT));
    }
}
