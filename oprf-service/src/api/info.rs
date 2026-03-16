//! Info Endpoint
//!
//! Exposes the following API endpoints:
//!
//! - `/wallet` – returns the wallet address
//! - `/oprf_pub/{id}` – returns the [`oprf_types::crypto::OprfPublicKey`] associated with the [`OprfKeyId`] if the OPRF node has the information stored.
//!
//! The endpoints include a `Cache-Control: no-cache` header to prevent caching of responses.
use crate::services::oprf_key_material_store::OprfKeyMaterialStore;
use alloy::primitives::Address;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use oprf_types::OprfKeyId;
use tower_http::set_header::SetResponseHeaderLayer;

#[derive(Clone)]
struct InfoState {
    wallet_address: Address,
    oprf_material_store: OprfKeyMaterialStore,
}

/// Create a router containing the info endpoints.
///
/// All endpoints have `Cache-Control: no-cache` set.
pub(crate) fn routes(oprf_material_store: OprfKeyMaterialStore, wallet_address: Address) -> Router {
    Router::new()
        .route("/wallet", get(wallet))
        .route("/oprf_pub/{id}", get(oprf_key_available))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
        .with_state(InfoState {
            wallet_address,
            oprf_material_store,
        })
}

/// Responds with the wallet address of the oprf node
///
/// Returns `200 OK` with a string response.
async fn wallet(State(info_state): State<InfoState>) -> impl IntoResponse {
    (StatusCode::OK, info_state.wallet_address.to_string())
}

/// Checks whether a OPRF public-key associated with the [`OprfKeyId`] is registered at the service. If yes, returns the [`oprf_types::api::OprfPublicKeyWithEpoch`] containing the latest epoch currently stored at the service.
///
/// Returns `200 OK` with [`oprf_types::api::OprfPublicKeyWithEpoch`].
/// Returns `404 Not Found` if not registered.
async fn oprf_key_available(
    State(info_state): State<InfoState>,
    Path(id): Path<OprfKeyId>,
) -> impl IntoResponse {
    if let Some(public_material) = info_state
        .oprf_material_store
        .oprf_public_key_with_epoch(id)
    {
        (StatusCode::OK, Json(public_material)).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}
