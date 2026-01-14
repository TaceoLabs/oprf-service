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
use axum_extra::headers::{self, Header};
use http::{HeaderName, HeaderValue};
use oprf_types::crypto::PartyId;
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::time::Duration;
use tower_http::trace::TraceLayer;

pub(crate) mod errors;
pub(crate) mod health;
pub(crate) mod info;
pub(crate) mod v1;

static OPRF_PROTOCOL_VERSION_HEADER: HeaderName =
    http::HeaderName::from_static("x-taceo-oprf-protocol-version");

#[derive(Debug, Clone)]
pub(crate) struct ProtocolVersion(Version);

impl Header for ProtocolVersion {
    fn name() -> &'static http::HeaderName {
        &OPRF_PROTOCOL_VERSION_HEADER
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, axum_extra::headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i http::HeaderValue>,
    {
        let version_req = values
            .next()
            .ok_or_else(headers::Error::invalid)?
            .to_str()
            .map_err(|err| {
                tracing::trace!("could not convert header to string: {err:?}");

                headers::Error::invalid()
            })?;
        println!("got {version_req}");
        if values.next().is_some() {
            Err(headers::Error::invalid())
        } else {
            let version = Version::parse(version_req).map_err(|err| {
                tracing::trace!("could not parse header version: {err:?}");
                headers::Error::invalid()
            })?;
            Ok(ProtocolVersion(version))
        }
    }

    fn encode<E: Extend<http::HeaderValue>>(&self, values: &mut E) {
        let encoded = HeaderValue::from_bytes(self.0.to_string().as_bytes())
            .expect("Cannot encode header version");
        values.extend(std::iter::once(encoded));
    }
}

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
