//! Health Check Endpoints
//!
//! This module defines the health endpoint for the OPRF key gen API.
//! These endpoints provide simple HTTP status responses to indicate the service's status.
//!
//! - `/health` – general health check
//!
//! The endpoints include a `Cache-Control: no-cache` header to prevent caching of responses.

use axum::{
    Router,
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use nodes_common::StartedServices;
use tower_http::set_header::SetResponseHeaderLayer;

/// Create a router containing the health endpoints.
///
/// All endpoints have `Cache-Control: no-cache` set.
pub(crate) fn routes(started_services: StartedServices) -> Router {
    Router::new()
        .route("/health", get(move || health(started_services)))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
}

/// General health check endpoint.
///
/// Returns `200 OK` with a plain `"healthy"` response if all services already started.
/// Returns `503 Service Unavailable` with a plain `"starting"`response if one of the services did not start yet.
async fn health(started_services: StartedServices) -> impl IntoResponse {
    if started_services.all_started() {
        (StatusCode::OK, "healthy")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "starting")
    }
}
