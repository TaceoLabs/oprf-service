use crate::api::errors::Error;
use crate::services::open_sessions::OpenSessions;
use crate::{OprfRequestAuthService, services::oprf_key_material_store::OprfKeyMaterialStore};
use axum::{
    Router,
    extract::{
        WebSocketUpgrade,
        ws::{self, CloseFrame, WebSocket, close_code},
    },
    routing::any,
};
use oprf_core::ddlog_equality::shamir::DLogCommitmentsShamir;
use oprf_types::{
    api::v1::{OprfRequest, OprfResponse, oprf_error_codes},
    crypto::PartyId,
};
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;
use tracing::instrument;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HumanReadable {
    Yes,
    No,
}

struct WebSocketArgs<ReqAuth, ReqAuthError> {
    ws: WebSocketUpgrade,
    party_id: PartyId,
    threshold: usize,
    open_sessions: OpenSessions,
    oprf_material_store: OprfKeyMaterialStore,
    req_auth_service: OprfRequestAuthService<ReqAuth, ReqAuthError>,
    max_message_size: usize,
    max_connection_lifetime: Duration,
}

/// Web-socket handler.
///
/// Sets the `max_message_size` for the web-socket to the provided value. Implementations are encouraged to use a very conservative value here. We only expect exactly two kinds of messages, and those are very small (of course depending on your authentication request), therefore we can reject larger requests pretty handily.
///
/// The created web-socket connection holds all the information bound to the session. At the very start of the session, tries to lock the requested session-id with the [`OpenSessions`] service, as no two sessions with the same id must be handled at the same time.
///
/// The generated randomness (which is not allowed to be used twice and shall not leak) only lives in the created task and is consumed when the session finishes (also releases the session-id lock).
///
/// Furthermore, every web-socket only live for `max_connection_lifetime`. As soon as the upgrade finishes, we start the timer. If a sessions takes longer than this defined amount, the server will send a `Close` frame and deconstructs the session (also deleting all cryptographic material bound to the session).
///
/// Adds a `failed_upgrade` handler that logs the error.
///
/// See [`partial_oprf`] for the flow of the web-socket connection. If the session finishes successfully, encounters an error, the user closes the connection, or we run into a timeout, the implementation will try to initiate a graceful shutdown of the web-socket connection (closing handshake). We do this at a best-effort basis but are very restrictive on what we expect. We close any session that sends invalid requests/authentication. If the sending of the `Close` frame fails, we simply ignore the error and destruct everything associated with the session.
async fn ws<
    ReqAuth: for<'de> Deserialize<'de> + Send + 'static,
    ReqAuthError: Send + 'static + std::error::Error,
>(
    args: WebSocketArgs<ReqAuth, ReqAuthError>,
) -> axum::response::Response {
    args.ws
        .max_message_size(args.max_message_size)
        .on_failed_upgrade(|err| {
            tracing::warn!("could not establish websocket connection: {err:?}");
        })
        .on_upgrade(move |mut ws| async move {
            let close_frame = match tokio::time::timeout(
                args.max_connection_lifetime,
                partial_oprf::<ReqAuth, ReqAuthError>(
                    &mut ws,
                    args.party_id,
                    args.threshold,
                    args.open_sessions,
                    args.oprf_material_store,
                    args.req_auth_service,
                ),
            )
            .await
            {
                Ok(Ok(_)) => Some(CloseFrame {
                    code: close_code::NORMAL,
                    reason: "success".into(),
                }),
                Ok(Err(err)) => err.into_close_frame(),

                Err(_) => Some(CloseFrame {
                    code: oprf_error_codes::TIMEOUT,
                    reason: "timeout".into(),
                }),
            };
            if let Some(close_frame) = close_frame {
                tracing::trace!(" < sending close frame");
                // In their example, axum just sends the frame and ignores the error afterwards and also don't wait for the peers close frame. Therefore we do the same,
                let _ = ws.send(ws::Message::Close(Some(close_frame))).await;
            }
        })
}

/// The whole life-cycle of a single user session.
///
/// 1) Read the [`OprfRequest`] of the user. Accepts `Text` and `Binary` frames and deserializes the request with `json` or `cbor` respectively.
/// 2) Verifies the implementation dependent authentication part with the provided [`OprfRequestAuthService`].
/// 3) Computes the nodes partial contribution for the session. The created randomness does not leave the task.
/// 4) Sends the commitment back to the user (using same serialization as the user).
/// 5) Read the [`DLogCommitmentsShamir`] of the user. Accepts `Text` and `Binary` frames and deserializes the request with `json` or `cbor` respectively.
/// 6) Finalizes the proof share for the session and sends it back to the user (same serialization as the initial request of the user).
///
/// Clients may and will close the connection at any point because they only need `threshold` amount of sessions, therefore it is very much expected that sane clients send a `Close` frame at any point (or simply drop the connection). This method handles this gracefully at any point.
#[instrument(level="debug", skip_all, fields(request_id=tracing::field::Empty))]
async fn partial_oprf<
    ReqAuth: for<'de> Deserialize<'de> + Send + 'static,
    ReqAuthError: Send + 'static + std::error::Error,
>(
    socket: &mut WebSocket,
    party_id: PartyId,
    threshold: usize,
    open_sessions: OpenSessions,
    oprf_material_store: OprfKeyMaterialStore,
    req_auth_service: OprfRequestAuthService<ReqAuth, ReqAuthError>,
) -> Result<(), Error> {
    tracing::trace!("> new oprf session - reading request...");
    let (init_request, human_readable) = read_request::<OprfRequest<ReqAuth>>(socket).await?;
    let request_id = init_request.request_id;

    tracing::debug!("starting with request id: {request_id}");
    let _session_guard = open_sessions.insert_new_session(init_request.request_id)?;

    let oprf_span = tracing::Span::current();
    oprf_span.record("request_id", request_id.to_string());

    tracing::debug!("verifying request with auth service...");
    req_auth_service
        .verify(&init_request)
        .await
        .map_err(|err| {
            tracing::debug!("Could not auth request: {err:?}");
            Error::Auth(err.to_string())
        })?;

    // check that blinded query (B) is not the identity element
    if init_request.blinded_query.is_zero() {
        return Err(Error::BadRequest(
            "blinded query must not be identity".to_owned(),
        ));
    }

    tracing::debug!(
        "initiating session with share epoch {:?}...",
        init_request.share_identifier
    );
    let (session, commitments) = oprf_material_store
        .partial_commit(init_request.blinded_query, init_request.share_identifier)?;

    let response = OprfResponse {
        commitments,
        party_id,
    };

    tracing::debug!("sending response...");
    write_response(response, human_readable, socket).await?;

    tracing::debug!("reading challenge...");
    let (challenge, _) = read_request::<DLogCommitmentsShamir>(socket).await?;

    let coeffs = challenge.get_contributing_parties();
    let num_coeffs = coeffs.len();
    if num_coeffs != threshold {
        return Err(Error::BadRequest(format!(
            "expected {threshold} contributing parties but got {num_coeffs}",
        )));
    }
    let my_coeff = party_id.into_inner() + 1;
    if !coeffs.contains(&my_coeff) {
        return Err(Error::BadRequest(format!(
            "contributing parties does not contain my coefficient ({my_coeff})",
        )));
    }
    let mut unique_coeffs = coeffs.to_vec();
    if !unique_coeffs.is_sorted() {
        return Err(Error::BadRequest(
            "contributing parties are not sorted".to_owned(),
        ));
    }
    unique_coeffs.dedup();
    if unique_coeffs.len() != num_coeffs {
        return Err(Error::BadRequest(
            "contributing parties contains duplicate coefficients".to_owned(),
        ));
    }

    tracing::debug!("finalizing session...");
    let proof_share = oprf_material_store.challenge(
        request_id,
        party_id,
        session,
        challenge,
        init_request.share_identifier,
    )?;

    tracing::debug!("sending challenge response to client...");
    write_response(proof_share, human_readable, socket).await?;
    Ok(())
}

/// Attempts to read a `Msg` from the web-socket. Accepts `Text` and `Binary` frames and tries to deserialize the message with either `json` or `cbor`.
///
/// # Errors
/// Returns the corresponding error if either the peer closes the connection (gracefully with a `Close` frame or not) or if the `Msg` cannot be serialized with the corresponding format.
async fn read_request<Msg: for<'de> Deserialize<'de>>(
    socket: &mut WebSocket,
) -> Result<(Msg, HumanReadable), Error> {
    let res = match socket.recv().await.ok_or(Error::ConnectionClosed)?? {
        ws::Message::Text(json) => (
            serde_json::from_slice::<Msg>(json.as_bytes()).map_err(|_| Error::UnexpectedMessage)?,
            HumanReadable::Yes,
        ),
        ws::Message::Binary(cbor) => (
            ciborium::from_reader(cbor.as_ref()).map_err(|_| Error::UnexpectedMessage)?,
            HumanReadable::No,
        ),
        ws::Message::Close(_) => return Err(Error::ConnectionClosed),
        _ => return Err(Error::UnexpectedMessage),
    };
    Ok(res)
}

/// Attempts to write a `Msg` to the web-socket. Depending on `human_readable` either sends a `Text` (`json`) frame or `Binary` (`cbor`) frame.
async fn write_response<Msg: Serialize>(
    response: Msg,
    human_readable: HumanReadable,
    socket: &mut WebSocket,
) -> Result<(), Error> {
    let msg = match human_readable {
        HumanReadable::Yes => {
            let msg = serde_json::to_string(&response).expect("Can serialize response");
            ws::Message::text(msg)
        }
        HumanReadable::No => {
            let mut buf = Vec::new();
            ciborium::into_writer(&response, &mut buf).expect("Can serialize response");
            ws::Message::binary(buf)
        }
    };
    socket.send(msg).await?;
    Ok(())
}

/// Creates a `Router` with a single `/oprf` route.
///
/// The clients will upgrade their connection via the web-socket upgrade protocol. Axum basically supports HTTP/1.1 and HTTP/2.0 web-socket connections, therefore we accept connections with `any`.
///
/// If you want to enable HTTP/2.0, you either have to do it by hand or by calling `axum::serve`, which enabled HTTP/2.0 by default. Have a look at [Axum's HTTP2.0 example](https://github.com/tokio-rs/axum/blob/aeff16e91af6fa76efffdee8f3e5f464b458785b/examples/websockets-http2/src/main.rs#L57).
pub fn routes<
    ReqAuth: for<'de> Deserialize<'de> + Send + 'static,
    ReqAuthError: Send + 'static + std::error::Error,
>(
    party_id: PartyId,
    threshold: usize,
    oprf_material_store: OprfKeyMaterialStore,
    open_sessions: OpenSessions,
    req_auth_service: OprfRequestAuthService<ReqAuth, ReqAuthError>,
    max_message_size: usize,
    max_connection_lifetime: Duration,
) -> Router {
    Router::new().route(
        "/oprf",
        any(move |websocket_upgrade| {
            ws::<ReqAuth, ReqAuthError>(WebSocketArgs {
                ws: websocket_upgrade,
                party_id,
                threshold,
                open_sessions,
                oprf_material_store,
                req_auth_service,
                max_message_size,
                max_connection_lifetime,
            })
        }),
    )
}
