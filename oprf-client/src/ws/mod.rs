#[cfg(not(target_arch = "wasm32"))]
mod native;
use http::Uri;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use native::WebSocketSession;

#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub(crate) use wasm::WebSocketSession;

pub(crate) fn append_client_version_to_query(endpoint: &Uri) -> String {
    let version = env!("CARGO_PKG_VERSION");
    let has_query = endpoint.query().is_some();
    let mut endpoint = endpoint.to_string();

    endpoint.push(if has_query { '&' } else { '?' });
    endpoint.push_str("version=");
    endpoint.push_str(version);
    endpoint
}
