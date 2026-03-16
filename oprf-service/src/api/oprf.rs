use crate::api::errors::Error;
use crate::api::version_header::{ProtocolVersion, ProtocolVersionQuery};
use crate::metrics::{
    METRICS_ID_NODE_OPRF_SUCCESS, METRICS_ID_NODE_PART_1_DURATION, METRICS_ID_NODE_PART_1_FINISH,
    METRICS_ID_NODE_PART_1_START, METRICS_ID_NODE_PART_2_DURATION, METRICS_ID_NODE_PART_2_FINISH,
    METRICS_ID_NODE_PART_2_START, METRICS_ID_NODE_REQUEST_AUTH_START,
    METRICS_ID_NODE_REQUEST_AUTH_VERIFIED, METRICS_ID_NODE_REQUEST_VERIFY_DURATION,
    METRICS_ID_NODE_SESSIONS_TIMEOUT,
};
use crate::oprf_key_material_store::OprfSession;
use crate::services::open_sessions::OpenSessions;
use crate::services::oprf_key_material_store::OprfKeyMaterialStore;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::{
    Router,
    extract::{
        WebSocketUpgrade,
        ws::{self, CloseFrame, WebSocket, close_code},
    },
    routing::any,
};
use axum_extra::TypedHeader;
use http::StatusCode;
use oprf_core::ddlog_equality::shamir::{DLogCommitmentsShamir, DLogProofShareShamir};
use oprf_types::api::OprfRequestAuthService;
use oprf_types::{
    api::{OprfRequest, OprfResponse, oprf_error_codes},
    crypto::PartyId,
};
use semver::VersionReq;
use serde::Deserialize;
use serde::Serialize;
use std::time::{Duration, Instant};
use uuid::Uuid;

use tracing::{Instrument, instrument};

pub(crate) struct OprfModuleState<ReqAuth, ReqAuthError> {
    pub(crate) party_id: PartyId,
    pub(crate) threshold: usize,
    pub(crate) oprf_material_store: OprfKeyMaterialStore,
    pub(crate) open_sessions: OpenSessions,
    pub(crate) req_auth_service: OprfRequestAuthService<ReqAuth, ReqAuthError>,
    pub(crate) version_req: VersionReq,
    pub(crate) max_message_size: usize,
    pub(crate) max_connection_lifetime: Duration,
}

impl<ReqAuth, ReqAuthError> Clone for OprfModuleState<ReqAuth, ReqAuthError> {
    fn clone(&self) -> Self {
        Self {
            party_id: self.party_id,
            threshold: self.threshold,
            oprf_material_store: self.oprf_material_store.clone(),
            open_sessions: self.open_sessions.clone(),
            req_auth_service: self.req_auth_service.clone(),
            version_req: self.version_req.clone(),
            max_message_size: self.max_message_size,
            max_connection_lifetime: self.max_connection_lifetime,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HumanReadable {
    Yes,
    No,
}

/// # Web-socket Handler
///
/// Handles the creation and lifecycle of a web-socket session for OPRF requests.
///
/// ## Max Message Size
///
/// Sets the `max_message_size` for the web-socket to the provided value. Implementations are encouraged to use a very conservative value here. We only expect exactly two kinds of messages, and those are very small (depending on your authentication request), therefore we can reject larger requests efficiently.
///
/// ## Session Locking
///
/// The created web-socket connection holds all the information bound to the session. At the very start of the session, it tries to lock the requested session-id with the [`OpenSessions`] service, as no two sessions with the same id must be handled at the same time.
///
/// ## Client Protocol Version Requirement
///
/// Clients are required to announce the protocol version they implement using [Semantic Versioning (semver)].
///
/// The version must be provided either:
/// - via the custom HTTP header [`oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER`], or
/// - as a query parameter of the request URL.
///
/// If both mechanisms are present and valid, the HTTP header takes precedence over the query parameter. If either of the versions is corrupted, it will reject the request.
///
/// Connections that do not provide a valid protocol version are rejected before the web-socket session is established.
///
/// ## Randomness & Session Data
///
/// The generated randomness (which is not allowed to be used twice and shall not leak) only lives in the created task and is consumed when the session finishes (also releasing the session-id lock).
///
/// ## Connection Lifetime
///
/// Every web-socket only lives for `max_connection_lifetime`. As soon as the upgrade finishes, the timer starts. If a session takes longer than this defined amount, the server will send a `Close` frame and deconstructs the session (also deleting all cryptographic material bound to the session).
///
/// ## Error Handling
///
/// Adds a `failed_upgrade` handler that logs the error.
///
/// ## Session Flow
///
/// See [`partial_oprf`] for the flow of the web-socket connection. If the session finishes successfully, encounters an error, the user closes the connection, or we run into a timeout, the implementation will try to initiate a graceful shutdown of the web-socket connection (closing handshake). We do this on a best-effort basis but are very restrictive on what we expect. We close any session that sends invalid requests/authentication. If sending the `Close` frame fails, we simply ignore the error and destruct everything associated with the session.
#[instrument(level = "debug", skip_all,name="request", fields(client_version=tracing::field::Empty))]
async fn oprf_ws_handler<
    ReqAuth: for<'de> Deserialize<'de> + Send + 'static,
    ReqAuthError: Send + 'static + std::error::Error,
>(
    State(state): State<OprfModuleState<ReqAuth, ReqAuthError>>,
    websocket_upgrade: WebSocketUpgrade,
    header_version: Option<TypedHeader<ProtocolVersion>>,
    query_version: Query<ProtocolVersionQuery>,
) -> axum::response::Response {
    let Some(client_version) = parse_client_header(header_version, query_version) else {
        return (StatusCode::BAD_REQUEST, "missing client version").into_response();
    };
    let parent_span = tracing::Span::current();
    parent_span.record("client_version", format!("{client_version}"));
    if state.version_req.matches(&client_version) {
        websocket_upgrade
            .max_message_size(state.max_message_size)
            .on_failed_upgrade(|err| {
                tracing::warn!("could not establish websocket connection: {err:?}");
            })
            .on_upgrade(move |mut ws| {
                async move {
                    let close_frame = match tokio::time::timeout(
                        state.max_connection_lifetime,
                        partial_oprf::<ReqAuth, ReqAuthError>(
                            &mut ws,
                            state.party_id,
                            state.threshold,
                            state.open_sessions,
                            state.oprf_material_store,
                            state.req_auth_service,
                        ),
                    )
                    .await
                    {
                        Ok(Ok(())) => {
                            ::metrics::counter!(METRICS_ID_NODE_OPRF_SUCCESS).increment(1);
                            Some(CloseFrame {
                                code: close_code::NORMAL,
                                reason: "success".into(),
                            })
                        }
                        Ok(Err(err)) => err.into_close_frame(),
                        Err(_) => {
                            ::metrics::counter!(METRICS_ID_NODE_SESSIONS_TIMEOUT).increment(1);
                            Some(CloseFrame {
                                code: oprf_error_codes::TIMEOUT,
                                reason: "timeout".into(),
                            })
                        }
                    };
                    if let Some(close_frame) = close_frame {
                        tracing::trace!(" < sending close frame");
                        // In their example, axum just sends the frame and ignores the error afterwards and also don't wait for the peers close frame. Therefore we do the same,
                        #[allow(clippy::let_underscore_must_use, reason="we don't care about this error as we close the connection anyways and only send close frame on best effort")]
                        let _ = ws.send(ws::Message::Close(Some(close_frame))).await;
                    }
                }
                .instrument(parent_span)
            })
    } else {
        tracing::trace!("rejecting because version mismatch");
        (
            StatusCode::BAD_REQUEST,
            format!("invalid version, expected: {}", state.version_req),
        )
            .into_response()
    }
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
#[instrument(level="debug", skip_all, fields(request_id=tracing::field::Empty, oprf_key_id=tracing::field::Empty))]
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
    ::metrics::counter!(METRICS_ID_NODE_PART_1_START).increment(1);
    let (init_request, human_readable) = read_request::<OprfRequest<ReqAuth>>(socket)
        .instrument(tracing::debug_span!("read_init_request"))
        .await?;

    // Some setup before we start processing - setup span and reserve the session ID
    let request_id = init_request.request_id;
    tracing::debug!("starting with request id: {request_id}");
    let oprf_span = tracing::Span::current();
    oprf_span.record("request_id", request_id.to_string());

    // this session guard need to live throughout the whole run. Do not touch except you really know what you are doing (you really don't want to move this, this must be at the very top of the method).
    let _session_guard = open_sessions.insert_new_session(request_id)?;

    let (session, response) = init_session(
        init_request,
        party_id,
        &req_auth_service,
        &oprf_material_store,
    )
    .await?;
    // record the key-id for the span
    oprf_span.record("oprf_key_id", session.key_id().to_string());

    write_response(response, human_readable, socket)
        .instrument(tracing::debug_span!("write_init_response"))
        .await?;
    ::metrics::counter!(METRICS_ID_NODE_PART_1_FINISH).increment(1);

    let (challenge_request, _) = read_request::<DLogCommitmentsShamir>(socket)
        .instrument(tracing::debug_span!("read_challenge_request"))
        .await?;
    ::metrics::counter!(METRICS_ID_NODE_PART_2_START).increment(1);

    let proof_share =
        challenge(challenge_request, request_id, party_id, threshold, session).await?;

    tracing::debug!("sending challenge response to client...");
    write_response(proof_share, human_readable, socket)
        .instrument(tracing::debug_span!("write_challenge_response"))
        .await?;
    ::metrics::counter!(METRICS_ID_NODE_PART_2_FINISH).increment(1);
    Ok(())
}

#[instrument(level = "debug", skip_all)]
async fn init_session<
    ReqAuth: for<'de> Deserialize<'de> + Send + 'static,
    ReqAuthError: Send + 'static + std::error::Error,
>(
    init_request: OprfRequest<ReqAuth>,
    party_id: PartyId,
    req_auth_service: &OprfRequestAuthService<ReqAuth, ReqAuthError>,
    oprf_material_store: &OprfKeyMaterialStore,
) -> Result<(OprfSession, OprfResponse), Error> {
    let start_part_one = Instant::now();
    tracing::trace!("checking that blinded query is not zero...");
    // check that blinded query (B) is not the identity element
    if init_request.blinded_query.is_zero() {
        return Err(Error::BadRequest(
            "blinded query must not be identity".to_owned(),
        ));
    }

    tracing::debug!("verifying request with auth service...");
    ::metrics::counter!(METRICS_ID_NODE_REQUEST_AUTH_START).increment(1);
    let start_verify = Instant::now();
    let oprf_key_id = req_auth_service
        .authenticate(&init_request)
        .await
        .map_err(|err| {
            tracing::debug!("Could not auth request: {err:?}");
            Error::Auth(err.to_string())
        })?;
    let duration_verify = start_verify.elapsed();
    ::metrics::counter!(METRICS_ID_NODE_REQUEST_AUTH_VERIFIED).increment(1);
    ::metrics::histogram!(METRICS_ID_NODE_REQUEST_VERIFY_DURATION)
        .record(duration_verify.as_millis() as f64);

    tracing::debug!("initiating session with key id {oprf_key_id:?}...");
    let (session, commitments) = oprf_material_store
        .partial_commit(init_request.blinded_query, oprf_key_id)
        .ok_or_else(|| Error::UnknownOprfKeyId(oprf_key_id))?;

    let response = OprfResponse {
        commitments,
        party_id,
        oprf_pub_key_with_epoch: session.public_key_with_epoch(),
    };
    let duration_part_one = start_part_one.elapsed();
    ::metrics::histogram!(METRICS_ID_NODE_PART_1_DURATION)
        .record(duration_part_one.as_millis() as f64);
    Ok((session, response))
}

#[instrument(level = "debug", skip_all)]
async fn challenge(
    challenge: DLogCommitmentsShamir,
    request_id: Uuid,
    party_id: PartyId,
    threshold: usize,
    session: OprfSession,
) -> Result<DLogProofShareShamir, Error> {
    let start_part_two = Instant::now();
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
    let proof_share = OprfKeyMaterialStore::challenge(request_id, party_id, session, challenge);

    let duration_part_two = start_part_two.elapsed();
    ::metrics::histogram!(METRICS_ID_NODE_PART_2_DURATION)
        .record(duration_part_two.as_millis() as f64);
    Ok(proof_share)
}

/// Attempts to read a `Msg` from the web-socket. Accepts `Text` and `Binary` frames and tries to deserialize the message with either `json` or `cbor`.
///
/// # Errors
/// Returns the corresponding error if either the peer closes the connection (gracefully with a `Close` frame or not) or if the `Msg` cannot be serialized with the corresponding format.
async fn read_request<Msg: for<'de> Deserialize<'de>>(
    socket: &mut WebSocket,
) -> Result<(Msg, HumanReadable), Error> {
    tracing::trace!(" > read request");
    let res = match socket.recv().await.ok_or(Error::ConnectionClosed)?? {
        ws::Message::Text(json) => (
            serde_json::from_slice::<Msg>(json.as_bytes())?,
            HumanReadable::Yes,
        ),
        ws::Message::Binary(cbor) => (ciborium::from_reader(cbor.as_ref())?, HumanReadable::No),
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
    tracing::trace!(" > write response");
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

/// Tries to determine the client version of the request by checking the http header and query parameters. At least one of those must be present. The header takes precedence.
///
/// Returns `None` if none of those are present.
fn parse_client_header(
    header_version: Option<TypedHeader<ProtocolVersion>>,
    Query(query_version): Query<ProtocolVersionQuery>,
) -> Option<semver::Version> {
    // http header has precedence
    if let Some(TypedHeader(ProtocolVersion(client_version))) = header_version {
        Some(client_version)
    } else if let Some(ProtocolVersion(client_version)) = query_version.version {
        Some(client_version)
    } else {
        None
    }
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
    args: OprfModuleState<ReqAuth, ReqAuthError>,
) -> Router {
    Router::new()
        .route("/oprf", any(oprf_ws_handler))
        .with_state(args)
}
