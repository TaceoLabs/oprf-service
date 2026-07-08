use std::num::NonZeroU16;

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::post,
};
use http::{StatusCode, Uri};
use oprf_client::Connector;
use oprf_types::api::{DelegateOprfResponse, OprfPublicKeyWithEpoch, OprfRequest};
use semver::VersionReq;
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::{
    api::version_header::{ProtocolVersion, ProtocolVersionQuery},
    metrics,
};

#[derive(Clone)]
pub(crate) struct DelegateOprfState {
    pub(crate) threshold: NonZeroU16,
    pub(crate) services: Vec<Uri>,
    pub(crate) version_req: VersionReq,
    pub(crate) connector: Connector,
}

/// # Delegate Handler
///
/// Handles a single `POST /delegate` request by running the distributed OPRF protocol on
/// behalf of the client against the configured threshold-signing services, so that clients
/// that cannot talk to the services directly can delegate the whole flow to this endpoint.
///
/// ## Client Protocol Version Requirement
///
/// Clients are required to announce the protocol version they implement using [Semantic
/// Versioning (semver)] as a query parameter of the request URL. Requests without a version,
/// or with a version that does not satisfy `state.version_req`, are rejected with `400 Bad
/// Request` before any work is done.
///
/// ## Delegation
///
/// The request body is forwarded as-is to [`oprf_client::distributed_oprf_core`], which talks
/// to `state.services` and collects `state.threshold` responses. On success, the OPRF public
/// key/epoch, challenge, and per-service responses are returned to the client as `200 OK` so it
/// can finish the protocol itself.
///
/// ## Error Handling
///
/// - A [`oprf_client::Error::ThresholdServiceError`] is surfaced to the client as `400 Bad
///   Request`, since it indicates a problem with the request itself.
/// - Networking, session, epoch-mismatch, and node-disagreement errors are treated as transient
///   and returned as `503 Service Unavailable`.
/// - Any other error is unexpected and returned as `500 Internal Server Error`.
///
/// Error responses do not use a JSON body. The version-check and threshold-service errors above
/// carry a plain-text body: a human-readable message for the missing/invalid version case, and
/// the stringified numeric `error_code` reported by the failing service for the threshold-service
/// case. The `503` and `500` responses have no body at all; details are only available in the
/// server logs.
#[instrument(level = "info", skip_all, fields(request_id = %req.request_id))]
async fn delegate_oprf_handler<ReqAuth>(
    State(state): State<DelegateOprfState>,
    Query(query_version): Query<ProtocolVersionQuery>,
    Json(req): Json<OprfRequest<ReqAuth>>,
) -> impl IntoResponse
where
    ReqAuth: Serialize + for<'de> Deserialize<'de> + Clone + Send + 'static,
{
    if let Some(ProtocolVersion(client_version)) = query_version.version {
        tracing::trace!(%client_version, "received delegate OPRF request with version");
        if !state.version_req.matches(&client_version) {
            let msg = format!(
                "invalid version, expected: {} got: {client_version}",
                state.version_req
            );
            tracing::warn!(user_error = true, "{msg}");
            metrics::request::inc_client_version_mismatch();
            return (StatusCode::BAD_REQUEST, msg).into_response();
        }
    } else {
        tracing::warn!(user_error = true, "missing client version");
        return (StatusCode::BAD_REQUEST, "missing client version").into_response();
    }

    tracing::trace!("received delegate OPRF request");
    metrics::request::inc_delegate_request();
    match oprf_client::distributed_oprf_core(
        &state.services,
        u16::from(state.threshold) as usize,
        req,
        state.connector,
    )
    .await
    {
        Ok((oprf_public_key, epoch, challenge, responses)) => {
            tracing::trace!("delegate OPRF request successful");
            metrics::request::inc_delegate_success();
            let response = DelegateOprfResponse {
                challenge,
                responses,
                oprf_pub_key_with_epoch: OprfPublicKeyWithEpoch {
                    key: oprf_public_key,
                    epoch,
                },
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(oprf_client::Error::ThresholdServiceError(service_error)) => {
            tracing::warn!(
                ?service_error,
                "delegate OPRF request failed: {service_error}"
            );
            (
                StatusCode::BAD_REQUEST,
                service_error.error_code.to_string(),
            )
                .into_response()
        }
        Err(
            err @ (oprf_client::Error::Networking(_)
            | oprf_client::Error::CannotFinishSession(_)
            | oprf_client::Error::EpochMismatch(_)
            | oprf_client::Error::NodeErrorDisagreement(_)),
        ) => {
            tracing::warn!(?err, "delegate OPRF request failed: {err}");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Err(err) => {
            // This is an unexpected error, log it as an error instead of a warning
            tracing::error!(?err, "delegate OPRF request failed: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub fn routes<ReqAuth>(state: DelegateOprfState) -> Router
where
    ReqAuth: Serialize + for<'de> Deserialize<'de> + Clone + Send + 'static,
{
    Router::new()
        .route("/delegate", post(delegate_oprf_handler::<ReqAuth>))
        .with_state(state)
}
