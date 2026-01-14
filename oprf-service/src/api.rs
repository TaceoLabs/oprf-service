//! API module for the OPRF node service.
//!
//! This module defines all HTTP endpoints an OPRF node must serve to participate in TACEO:Oprf and organizes them into submodules:
//!
//! - [`errors`] – Defines API error types and conversions from internal service errors.
//! - [`health`] – Provides health endpoints (`/health`).
//! - [`info`] – Info about the service (`/version`, `/wallet` and `/oprf_pub/{id}`).
//! - [`v1`] – Version 1 of the OPRF WebSocket endpoint `/oprf`.

use crate::{
    OprfRequestAuthService,
    services::{
        StartedServices, open_sessions::OpenSessions, oprf_key_material_store::OprfKeyMaterialStore,
    },
};
use alloy::primitives::Address;
use axum::Router;
use oprf_types::crypto::PartyId;
use semver::VersionReq;
use serde::Deserialize;
use std::time::Duration;
use tower_http::trace::TraceLayer;

pub(crate) mod errors;
pub(crate) mod health;
pub(crate) mod info;
pub(crate) mod v1;

/// The arguments to start the api routes.
pub(crate) struct ApiRoutesArgs<
    RequestAuth: for<'de> Deserialize<'de> + Send + 'static,
    RequestAuthError: Send + 'static + std::error::Error,
> {
    pub(crate) party_id: PartyId,
    pub(crate) threshold: usize,
    pub(crate) oprf_material_store: OprfKeyMaterialStore,
    pub(crate) req_auth_service: OprfRequestAuthService<RequestAuth, RequestAuthError>,
    pub(crate) version_req: VersionReq,
    pub(crate) wallet_address: Address,
    pub(crate) max_message_size: usize,
    pub(crate) max_connection_lifetime: Duration,
    pub(crate) started_services: StartedServices,
}

/// Builds the main API router for the OPRF node service.
///
/// This function sets up:
///
/// - The `/api/v1/oprf` endpoint from [`v1`].
/// - The health and readiness endpoints from [`health`].
/// - General info about the deployment from [`info`].
/// - An HTTP trace layer via [`TraceLayer`].
///
/// The returned [`Router`] can be incorporated into another router or be served directly by axum. Implementations don't need to configure anything in their `State`, the service is inlined as [`Extension`](https://docs.rs/axum/latest/axum/struct.Extension.html).
pub fn routes<
    RequestAuth: for<'de> Deserialize<'de> + Send + 'static,
    RequestAuthError: Send + 'static + std::error::Error,
>(
    api_routes_args: ApiRoutesArgs<RequestAuth, RequestAuthError>,
) -> Router {
    let ApiRoutesArgs {
        party_id,
        threshold,
        version_req,
        oprf_material_store,
        req_auth_service,
        wallet_address,
        max_message_size,
        max_connection_lifetime,
        started_services: services_healthy,
    } = api_routes_args;
    // Create the bookkeeping service for the open-sessions. If we add a v2 at some point, we need to reuse this service, therefore we create it here.
    let open_sessions = OpenSessions::default();
    Router::new()
        .nest(
            "/api/v1",
            v1::routes(v1::V1Args {
                party_id,
                threshold,
                oprf_material_store: oprf_material_store.clone(),
                open_sessions: open_sessions.clone(),
                req_auth_service: req_auth_service.clone(),
                version_req,
                max_message_size,
                max_connection_lifetime,
            }),
        )
        .merge(health::routes(services_healthy))
        .merge(info::routes(oprf_material_store.clone(), wallet_address))
        .layer(TraceLayer::new_for_http())
}
