//! API module for the OPRF key gen instance.
//!
//! This module defines all HTTP endpoints an OPRF key gen instance must serve to participate in TACEO:OPRF and organizes them into submodules:
//!
//! - [`health`] – Provides health endpoints (`/health`).
//! - [`info`] – Info about the service (`/version`, `/wallet`).

use alloy::primitives::Address;
use axum::Router;
use nodes_common::StartedServices;
use tower_http::trace::TraceLayer;

pub(crate) mod health;
pub(crate) mod info;

/// Builds the main API router for the OPRF key gen instance.
///
/// This function sets up:
///
/// - The health and readiness endpoints from [`health`].
/// - General info about the deployment from [`info`].
/// - An HTTP trace layer via [`TraceLayer`].
///
/// The returned [`Router`] can be incorporated into another router or be served directly by axum. Implementations don't need to configure anything in their `State`, the service is inlined as [`Extension`](https://docs.rs/axum/latest/axum/struct.Extension.html).
pub fn routes(wallet_address: Address, started_services: StartedServices) -> Router {
    Router::new()
        .merge(health::routes(started_services))
        .merge(info::routes(wallet_address))
        .layer(TraceLayer::new_for_http())
}
