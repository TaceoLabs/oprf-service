//! API module for the OPRF key gen instance.
//!
//! This module defines all HTTP endpoints an OPRF key gen instance must serve to participate in TACEO:OPRF and organizes them into submodules:
//!
//! - [`info`] – Info about the service (`/version`, `/wallet`).

use alloy::primitives::Address;
use axum::Router;
use nodes_common::StartedServices;

pub(crate) mod info;

/// Builds the main API router for the OPRF key gen instance.
///
/// This function sets up:
///
/// - General info about the deployment from [`info`].
/// - Call to `nodes_common::api::routes_with_services`.
///
/// The returned [`Router`] can be incorporated into another router or be served directly by axum.
pub fn routes(wallet_address: Address, started_services: StartedServices) -> Router {
    let version_str = nodes_common::version_info!();
    Router::new().merge(info::routes(wallet_address)).merge(
        nodes_common::api::routes_with_services(started_services, version_str),
    )
}
