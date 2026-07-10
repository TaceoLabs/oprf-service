#![deny(missing_docs)]
#![deny(clippy::all, clippy::pedantic)]
#![deny(
    clippy::allow_attributes_without_reason,
    clippy::assertions_on_result_states,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::exhaustive_enums,
    clippy::iter_over_hash_type,
    clippy::let_underscore_must_use,
    clippy::missing_assert_message,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_safety_comment,
    clippy::unwrap_used
)]
#![allow(
    clippy::missing_errors_doc,
    reason = "We allow missing error sections in this crate"
)]

//! This crate provides utility functions for clients of the distributed OPRF protocol.
//!
//! Most implementations will only need the [`distributed_oprf`] method, or [`delegate_distributed_oprf`] if a single
//! delegate node should perform the distributed OPRF protocol on the client's behalf. For more
//! fine-grained workflows, we expose all necessary functions.
use core::fmt;
use std::collections::{HashMap, HashSet};

use ark_ec::AffineRepr as _;
use futures::stream::{FuturesUnordered, StreamExt as _};
use oprf_core::{
    ddlog_equality::shamir::{DLogCommitmentsShamir, DLogProofShareShamir},
    dlog_equality::DLogEqualityProof,
    oprf::{BlindedOprfRequest, BlindedOprfResponse, BlindingFactor},
};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    api::{DelegateOprfResponse, OprfErrorKind, OprfPublicKeyWithEpoch, OprfRequest},
    crypto::OprfPublicKey,
};
use serde::Serialize;
use tracing::instrument;
use url::Url;
use uuid::Uuid;

mod sessions;
mod ws;

/// The version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use http::Uri;
pub use http::uri::InvalidUri;
pub use sessions::OprfSessions;
pub use sessions::finish_sessions;
pub use sessions::init_sessions;

/// WebSocket connector configuration for native targets.
///
/// Re-exports [`tokio_tungstenite::Connector`] (e.g. `Plain`, `Rustls`) used
/// to configure transport/TLS behavior for native WebSocket connections.
#[cfg(not(target_arch = "wasm32"))]
pub use tokio_tungstenite::Connector;

/// No-op WebSocket connector used on `wasm32` targets.
///
/// In browsers, TLS and socket configuration are controlled by the WebSocket
/// implementation provided by the runtime, so there is no equivalent to
/// `tokio_tungstenite::Connector`.
///
/// This type exists only to keep a cross-platform API shape for
/// [`distributed_oprf`]. The value is ignored by the WASM transport.
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
pub struct Connector;

/// Builds a WebSocket OPRF [`Uri`] for a given service base URL and authentication module.
///
/// This function:
/// - Converts the scheme: `http://` → `ws://`, `https://` → `wss://`
/// - Normalizes trailing slashes
/// - Appends `/api/{auth}/oprf`
///
/// # Arguments
/// - `service`: Base URL of the service (e.g., `"https://example.com"`)
/// - `auth`: Authentication module (e.g., `"issuer"`)
///
/// # Returns
/// `Result<Uri, InvalidUri>`
///
/// # Errors
/// Returns `InvalidUri` when it is not possible to convert to URI.
///
/// # Example
/// ```
/// # use http::Uri;
/// # use http::uri::InvalidUri;
/// # use taceo_oprf_client::to_oprf_uri;
/// let uri = to_oprf_uri("https://example.com", "issuer")?;
/// assert_eq!(uri.to_string(), "wss://example.com/api/issuer/oprf");
/// # Ok::<(), InvalidUri>(())
/// ```
pub fn to_oprf_uri<Auth: fmt::Display>(service: &str, auth: Auth) -> Result<Uri, InvalidUri> {
    // Determine ws/wss scheme
    let ws_base = if service.starts_with("http") {
        service.replacen("http", "ws", 1)
    } else {
        service.to_string()
    };

    // Remove trailing slash if any
    let ws_base = ws_base.trim_end_matches('/');

    let uri_str = format!("{ws_base}/api/{auth}/oprf");
    uri_str.parse::<Uri>()
}

/// Builds WebSocket OPRF [`Uri`]s for multiple services.
///
/// Calls [`to_oprf_uri`] for each service and collects the results. Returns the first encountered error if any service URL is invalid.
///
/// # Arguments
/// - `services`: Iterable of service base URLs
/// - `auth`: Authentication module
///
/// # Returns
/// `Result<Vec<Uri>, InvalidUri>`
///
/// # Errors
/// Returns `InvalidUri` when one of the service cannot be converted to URI.
///
/// # Example
/// ```
/// # use http::Uri;
/// # use http::uri::InvalidUri;
/// # use taceo_oprf_client::to_oprf_uri_many;
/// let services = vec!["https://a.example.com", "https://b.example.com"];
/// let uris = to_oprf_uri_many(services, "issuer")?;
/// assert_eq!(uris.len(), 2);
/// # Ok::<(), InvalidUri>(())
/// ```
pub fn to_oprf_uri_many<S, I, A>(services: I, auth: A) -> Result<Vec<Uri>, InvalidUri>
where
    S: AsRef<str>,
    I: IntoIterator<Item = S>,
    A: fmt::Display,
{
    let auth = auth.to_string();
    services
        .into_iter()
        .map(|s| to_oprf_uri(s.as_ref(), &auth))
        .collect()
}

/// Builds the delegate OPRF endpoint [`Url`].
///
/// Builds the URL for the delegate OPRF endpoint:
/// - Normalizes trailing slashes
/// - Appends `/api/{auth}/delegate`
///
/// # Arguments
/// - `service`: Base URL of the service (e.g., `"https://example.com"`)
/// - `auth`: Authentication module (e.g., `"issuer"`)
///
/// # Returns
/// `Result<Url, url::ParseError>`
///
/// # Errors
/// Returns `url::ParseError` when it is not possible to convert to [`Url`].
///
/// # Example
/// ```
/// # use url::Url;
/// # use url::ParseError;
/// # use taceo_oprf_client::to_delegate_oprf_url;
/// let url = to_delegate_oprf_url("https://example.com", "issuer")?;
/// assert_eq!(url.to_string(), "https://example.com/api/issuer/delegate");
/// # Ok::<(), ParseError>(())
/// ```
pub fn to_delegate_oprf_url<Auth: fmt::Display>(
    service: &str,
    auth: Auth,
) -> Result<Url, url::ParseError> {
    // Remove trailing slash if any
    let http_base = service.trim_end_matches('/');

    let uri_str = format!("{http_base}/api/{auth}/delegate");
    uri_str.parse::<Url>()
}

/// Builds the OPRF public-key info endpoint [`Url`].
///
/// Builds the URL for the endpoint exposing the [`OprfPublicKeyWithEpoch`].
/// - Normalizes trailing slashes
/// - Appends `/oprf_pub`
///
/// # Arguments
/// - `service`: Base URL of the service (e.g., `"https://example.com"`)
///
/// # Returns
/// `Result<Url, url::ParseError>`
///
/// # Errors
/// Returns `url::ParseError` when it is not possible to convert to [`Url`].
///
/// # Example
/// ```
/// # use url::Url;
/// # use url::ParseError;
/// # use taceo_oprf_client::to_oprf_pub_key_url;
/// let url = to_oprf_pub_key_url("https://example.com")?;
/// assert_eq!(url.to_string(), "https://example.com/oprf_pub");
/// # Ok::<(), ParseError>(())
/// ```
pub fn to_oprf_pub_key_url(service: &str) -> Result<Url, url::ParseError> {
    // Remove trailing slash if any
    let http_base = service.trim_end_matches('/');

    let uri_str = format!("{http_base}/oprf_pub");
    uri_str.parse::<Url>()
}

/// Builds the OPRF public-key info endpoint [`Url`]s for multiple services.
///
/// Calls [`to_oprf_pub_key_url`] for each service and collects the results. Returns the first encountered error if any service URL is invalid.
///
/// # Arguments
/// - `services`: Iterable of service base URLs
///
/// # Returns
/// `Result<Vec<Url>, url::ParseError>`
///
/// # Errors
/// Returns `url::ParseError` when one of the service cannot be converted to URL.
///
/// # Example
/// ```
/// # use url::Url;
/// # use url::ParseError;
/// # use taceo_oprf_client::to_oprf_pub_key_url_many;
/// let services = vec!["https://a.example.com", "https://b.example.com"];
/// let urls = to_oprf_pub_key_url_many(services)?;
/// assert_eq!(urls.len(), 2);
/// # Ok::<(), ParseError>(())
/// ```
pub fn to_oprf_pub_key_url_many<S, I>(services: I) -> Result<Vec<Url>, url::ParseError>
where
    S: AsRef<str>,
    I: IntoIterator<Item = S>,
{
    services
        .into_iter()
        .map(|s| to_oprf_pub_key_url(s.as_ref()))
        .collect()
}

/// The error of a single node.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NodeError {
    /// Application level error. Contains a [`ServiceError`].
    #[error(transparent)]
    ServiceError(#[from] ServiceError),
    /// Generic WebSocket error like connection lost or cannot reach host. For the Rust impl will wraps tungstenite-errors.
    #[error("Error during WebSocket connection: {0}")]
    WsError(#[source] Box<dyn core::error::Error + Send + Sync + 'static>),
    /// The server send an invalid/unexpected message
    #[error("Server sent unexpected message: {reason}")]
    UnexpectedMessage {
        /// Reason for closing websocket from our side
        reason: &'static str,
    },
    /// The servers could not agree on a [`ShareEpoch`].
    ///
    /// This node sent back the wrapped epoch.
    #[error("ShareEpoch mismatch - got epoch: {0}")]
    EpochMismatch(ShareEpoch),
    /// Represents an unknown or unexpected error.
    ///
    /// Primarily included for forward compatibility and future-proofing.
    #[error("Unknown error: {0}")]
    Unknown(#[source] Box<dyn core::error::Error + Send + Sync + 'static>),
}

impl PartialEq for NodeError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::ServiceError(lhs), Self::ServiceError(rhs)) => lhs == rhs,
            (Self::UnexpectedMessage { reason: lhs }, Self::UnexpectedMessage { reason: rhs }) => {
                lhs == rhs
            }
            (Self::EpochMismatch(lhs), Self::EpochMismatch(rhs)) => lhs == rhs,
            _ => false,
        }
    }
}

/// The application level error from a node. We expect callsite to understand the provided `error_code`.
/// The `msg` is for debugging purposes. It should not be shown to the user.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ServiceError {
    /// The `close_code` recorded from the close frame.
    pub error_code: u16,
    /// An optional message recorded from the close frame. Intended for debugging and not to show to the user.
    pub msg: Option<String>,
    /// The [`OprfErrorKind`] classification derived from the WebSocket close code.
    /// Use this for programmatic error handling instead of matching on raw `error_code`.
    pub kind: OprfErrorKind,
}

impl ServiceError {
    /// Returns `true` if this error was returned by the [`OprfRequestAuthenticator`](oprf_types::api::OprfRequestAuthenticator) (close code 4500–4999).
    #[must_use]
    pub fn is_auth(&self) -> bool {
        self.kind.is_auth()
    }
}

impl core::error::Error for ServiceError {}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.msg {
            Some(m) => write!(f, "error code: {} with message: {}", self.error_code, m),
            None => write!(f, "error code: {} (no message)", self.error_code),
        }
    }
}

/// Errors returned by the distributed OPRF protocol.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Services must be unique
    #[error("Services must be unique")]
    NonUniqueServices,
    /// Services did not report an error but different epochs
    #[error("The nodes could not agree on an epoch")]
    EpochMismatch(Vec<ShareEpoch>),
    /// Invalid threshold for provided URIs.
    #[error(
        "Invalid combination num_peers {num_peers} and threshold {threshold}. Must be 0 < threshold <= num_peers"
    )]
    InvalidThreshold {
        /// The number of peers (URIs) provided
        num_peers: usize,
        /// The requested threshold
        threshold: usize,
    },
    /// The `DLog` equality proof failed verification.
    #[error("DLog proof could not be verified")]
    InvalidDLogProof,
    /// OPRF nodes returned different public keys
    #[error("OPRF nodes returned different public keys")]
    InconsistentOprfPublicKeys,
    /// Threshold many OPRF nodes sent back this [`ServiceError`].
    #[error("Threshold nodes sent back error: {0}")]
    ThresholdServiceError(ServiceError),
    /// Unable to reach threshold many nodes due to networking issues
    #[error("Unable to reach threshold many nodes due to networking issues")]
    Networking(Vec<Box<dyn core::error::Error + Send + Sync + 'static>>),
    /// Threshold many OPRF nodes sent an unexpected message. This most likely indicates a client version problem
    #[error("Received an unexpected message from threshold many nodes: {reason}")]
    UnexpectedMessage {
        /// A human-readable explanation why the client rejected the message
        reason: &'static str,
    },
    /// One of the OPRF nodes returned an error during finalize (2nd round of the protocol).
    #[error("One of the nodes failed during finalize: {0}")]
    CannotFinishSession(#[source] NodeError),
    /// Represents a disagreement between nodes: no error reached the required threshold for consensus.
    ///
    /// The order of errors in the contained `Vec<NodeError>` does **not** reflect the order of URIs passed to [`distributed_oprf`].
    #[error("Nodes could not agree on error")]
    NodeErrorDisagreement(Vec<NodeError>),
    /// Represents an unknown or unexpected error.
    ///
    /// Primarily included for forward compatibility and future-proofing.
    #[error("Unknown error: {0}")]
    Unknown(#[source] Box<dyn core::error::Error + Send + Sync + 'static>),
    /// Represents a `reqwest` error when sending the request to the delegate service.
    #[error(transparent)]
    DelegateRequest(#[from] reqwest::Error),
    /// Error that happened during the delegate request.
    ///
    /// If the nodes agreed on a [`ServiceError`] and returned it, the delegate service will forward that error to the client.
    /// In that case, the client will return a [`Error::ThresholdServiceError`] instead.
    #[error("Delegate service returned a error: status: {status}, reason: {reason}")]
    DelegateServerError {
        /// The HTTP status code returned by the delegate service.
        status: reqwest::StatusCode,
        /// The body of the response returned by the delegate service.
        reason: String,
    },
}

/// Aggregates errors returned by nodes.
///
/// - If `threshold` nodes returned the same `ServiceError`, returns a consensus service error.
/// - If `threshold` nodes returned the same `UnexpectedMessage`, returns that consensus.
/// - If `threshold` nodes returned `WsError`s, collects them into a networking error.
/// - If `threshold` nodes returned `EpochMismatch`, we return `EpochMismatch` containing all reported epochs.
/// - Otherwise, returns `NodeErrorDisagreement`.
///
/// Internal use only.
fn aggregate_error(threshold: usize, errors: Vec<NodeError>) -> Error {
    let mut service_errors = HashMap::new();
    let mut ws_errors_counters = 0;
    let mut unexpected_message = HashMap::new();
    let mut epoch_mismatches = Vec::with_capacity(errors.len());

    for err in &errors {
        match err {
            NodeError::ServiceError(service_error) => {
                let count = service_errors.entry(service_error).or_insert(0);
                *count += 1;
                if *count >= threshold {
                    return Error::ThresholdServiceError(service_error.to_owned());
                }
            }
            NodeError::WsError(_) => {
                // can't check generic error for equality therefore we just collect them
                ws_errors_counters += 1;
            }
            NodeError::UnexpectedMessage { reason } => {
                let count = unexpected_message.entry(reason).or_insert(0);
                *count += 1;
                if *count >= threshold {
                    return Error::UnexpectedMessage { reason };
                }
            }
            NodeError::EpochMismatch(epoch) => {
                epoch_mismatches.push(*epoch);
            }
            // we ignore unknown for aggregation
            _ => {}
        }
    }

    if epoch_mismatches.len() >= threshold {
        return Error::EpochMismatch(epoch_mismatches);
    } else if ws_errors_counters >= threshold {
        return Error::Networking(
            errors
                .into_iter()
                .filter_map(|err| {
                    if let NodeError::WsError(error) = err {
                        Some(error)
                    } else {
                        None
                    }
                })
                .collect(),
        );
    }

    Error::NodeErrorDisagreement(errors.into_iter().collect())
}

/// The result of the distributed OPRF protocol.
#[derive(Debug, Clone)]
pub struct VerifiableOprfOutput {
    /// The generated OPRF output.
    pub output: ark_babyjubjub::Fq,
    /// The `DLog` equality proof.
    pub dlog_proof: DLogEqualityProof,
    /// The blinded OPRF request.
    pub blinded_request: ark_babyjubjub::EdwardsAffine,
    /// The blinded OPRF response.
    pub blinded_response: ark_babyjubjub::EdwardsAffine,
    /// The unblinded OPRF response.
    pub unblinded_response: ark_babyjubjub::EdwardsAffine,
    /// The `OprfPublicKey` for the used `OprfKeyId`.
    pub oprf_public_key: OprfPublicKey,
    /// The `ShareEpoch` which was used.
    pub epoch: ShareEpoch,
}

/// Executes the distributed OPRF protocol.
///
/// This function performs the full client-side workflow of the distributed OPRF protocol:
/// 1. Blinds the input query using the provided blinding factor.
/// 2. Initializes sessions with the specified OPRF services, sending the blinded query and authentication information.
/// 3. Generates the `DLog` equality challenge based on the commitments received from the services.
/// 4. Finishes the sessions by sending the challenge to the services and collecting their responses
/// 5. Verifies the combined `DLog` equality proof from the services.
/// 6. Unblinds the combined OPRF response using the blinding factor.
/// 7. Computes the final OPRF output by hashing the original query and the unblinded response.
///
/// # Returns
/// The final [`VerifiableOprfOutput`] containing the OPRF output, the `DLog` equality proof, the blinded and unblinded responses.
///
/// # Arguments
/// - `services`: List of WebSocket URIs of the OPRF nodes to contact (must be unique). See the helper functions [`to_oprf_uri`] and [`to_oprf_uri_many`].
/// - `threshold`: Number of nodes required to complete the protocol
/// - `query`: The OPRF input value to evaluate
/// - `blinding_factor`: The blinding factor used to blind the query
/// - `domain_separator`: Domain separator used in the final Poseidon hash to derive the output
/// - `auth`: Implementation specific authentication request forwarded to each OPRF node as part of the request
/// - `connector`: TLS connector configuration for the WebSocket connections
///
/// # Timeout and Cancellation
///
/// This method does not implement any timeout policy. Callers are expected to
/// enforce timeouts at a higher level (e.g., via `tokio::time::timeout` or
/// equivalent mechanisms).
///
/// All network operations are executed using structured concurrency (no detached
/// tasks are spawned). As a result, dropping the returned future (e.g., due to
/// cancellation or timeout at the call-site) will also drop all in-flight
/// requests initiated by this method.
///
/// However, whether cancellation fully aborts underlying work depends on the
/// behavior of the contacted OPRF nodes. In particular:
///
/// - If a request has already been processed by a node, that work cannot be
///   undone.
/// - Some node implementations may persist request-related state (e.g., nonces
///   included in the `auth` argument). Retrying the same request after
///   cancellation may therefore be rejected by the nodes.
///
/// Callers should treat this operation as potentially having side effects and
/// design retry logic accordingly.
///
/// # Errors
/// See the [`Error`] enum for all potential errors of this function.
#[instrument(level = "debug", skip_all, fields(request_id = tracing::field::Empty))]
#[allow(
    clippy::missing_panics_doc,
    reason = "Can't really panic due to promises from called method"
)]
pub async fn distributed_oprf<OprfRequestAuth>(
    services: &[Uri],
    threshold: usize,
    query: ark_babyjubjub::Fq,
    blinding_factor: BlindingFactor,
    domain_separator: ark_babyjubjub::Fq,
    auth: OprfRequestAuth,
    connector: Connector,
) -> Result<VerifiableOprfOutput, Error>
where
    OprfRequestAuth: Clone + Serialize + 'static,
{
    tracing::trace!("starting distributed oprf. my version: {}", VERSION);

    let request_id = Uuid::new_v4();
    let distributed_oprf_span = tracing::Span::current();
    distributed_oprf_span.record("request_id", request_id.to_string());
    tracing::debug!("starting with request id: {request_id}");

    let blinded_request = oprf_core::oprf::client::blind_query(query, blinding_factor);
    let oprf_req = OprfRequest {
        request_id,
        blinded_query: blinded_request.blinded_query(),
        auth,
    };

    let (oprf_public_key, epoch, challenge, responses) =
        distributed_oprf_core(services, threshold, oprf_req, connector).await?;

    finalize_distributed_oprf(FinalizeDistributedOprfArgs {
        request_id,
        query,
        blinding_factor,
        domain_separator,
        blinded_request,
        challenge,
        responses,
        oprf_public_key,
        epoch,
    })
}

/// Executes the distributed OPRF protocol via a single delegate node over HTTP.
///
/// Instead of the client directly contacting every OPRF node and driving [`distributed_oprf_core`]
/// itself, this function sends the (blinded) [`OprfRequest`] to a single delegate service (proxy). That
/// proxy acts as the client of the distributed OPRF protocol on the client's behalf: it runs
/// [`distributed_oprf_core`] against the OPRF nodes and forwards the combined result back to the client
/// as a [`DelegateOprfResponse`].
///
/// This function performs the following steps:
/// 1. Blinds the input query using the provided blinding factor.
/// 2. Sends the blinded query and authentication information to the delegate service via a single HTTP POST request.
/// 3. Verifies the combined `DLog` equality proof from the services.
/// 4. Unblinds the combined OPRF response using the blinding factor.
/// 5. Computes the final OPRF output by hashing the original query and the unblinded response.
///
/// # Security Considerations
/// The proxy learns the same information as the nodes: the blinded query and authentication material.
/// If the proxy is untrusted a client should verify its returned public key against a trusted source - either by
/// fetching it directly from the contract or querying threshold-many nodes (see [`fetch_oprf_public_key`]).
///
/// If the public key does not match, a client _MUST_ abort the request. Generally, a diligent client should always verify the
/// created upstream proof with the expected public inputs. This ensures a malicious proxy cannot
/// produce an incorrect result undetected.
///
/// # Returns
/// The final [`VerifiableOprfOutput`] containing the OPRF output, the `DLog` equality proof, and the blinded and unblinded responses.
///
/// # Arguments
/// - `service`: URL of the delegate service that will run the distributed OPRF protocol on our behalf
/// - `query`: The OPRF input value to evaluate
/// - `blinding_factor`: The blinding factor used to blind the query
/// - `domain_separator`: Domain separator used in the final Poseidon hash to derive the output
/// - `auth`: Implementation specific authentication request forwarded to the delegate service as part of the request
/// - `client`: The [`reqwest::Client`] used to send the request to the delegate service
///
/// # Timeout and Cancellation
///
/// This method does not implement any timeout policy. Callers are expected to
/// enforce timeouts at a higher level (e.g., via `tokio::time::timeout`, by setting
/// timeouts in `reqwest::Client` or equivalent mechanisms).
///
/// For more details on cancellation and side effects, see the documentation of [`distributed_oprf`].
///
/// # Errors
/// See the [`Error`] enum for all potential errors of this function.
#[instrument(level = "debug", skip_all, fields(request_id = tracing::field::Empty))]
pub async fn delegate_distributed_oprf<OprfRequestAuth>(
    service: &Url,
    query: ark_babyjubjub::Fq,
    blinding_factor: BlindingFactor,
    domain_separator: ark_babyjubjub::Fq,
    auth: OprfRequestAuth,
    client: &reqwest::Client,
) -> Result<VerifiableOprfOutput, Error>
where
    OprfRequestAuth: Clone + Serialize + 'static,
{
    tracing::trace!("starting distributed oprf. my version: {}", VERSION);

    let request_id = Uuid::new_v4();
    let distributed_oprf_span = tracing::Span::current();
    distributed_oprf_span.record("request_id", request_id.to_string());
    tracing::debug!("starting with request id: {request_id}");

    let blinded_request = oprf_core::oprf::client::blind_query(query, blinding_factor);
    let oprf_req = OprfRequest {
        request_id,
        blinded_query: blinded_request.blinded_query(),
        auth,
    };

    // add client version to query params so the delegate service can check for compatibility
    let mut service = service.clone();
    service.query_pairs_mut().append_pair("version", VERSION);

    let response = client.post(service).json(&oprf_req).send().await?;
    let status = response.status();
    tracing::debug!("delegate service returned status: {status}");

    let response = if status.is_success() {
        response.json::<DelegateOprfResponse>().await?
    } else {
        let body = response.text().await?;

        // If the delegate service returned a `ServiceError` (with a code), we wrap it in a `ThresholdServiceError`.
        // If the nodes disagreed on an error, or if a unexpected (e.g. Networking) error occurred, the delegate service will return a generic error. We wrap that in a `DelegateServerError`.
        if let Ok(error_code) = body.parse::<u16>() {
            return Err(Error::ThresholdServiceError(ServiceError {
                error_code,
                msg: None,
                kind: error_code.into(),
            }));
        }

        return Err(Error::DelegateServerError {
            status,
            reason: body,
        });
    };

    finalize_distributed_oprf(FinalizeDistributedOprfArgs {
        request_id,
        query,
        blinding_factor,
        domain_separator,
        blinded_request,
        challenge: response.challenge,
        responses: response.responses,
        oprf_public_key: response.oprf_pub_key_with_epoch.key,
        epoch: response.oprf_pub_key_with_epoch.epoch,
    })
}

/// Executes the core, network-facing part of the distributed OPRF protocol against a set of nodes.
///
/// This is the lower-level building block used by [`distributed_oprf`] and by [`delegate_distributed_oprf`]'s
/// delegate node. Unlike [`distributed_oprf`], it does not blind the query itself (the caller supplies
/// an already-built [`OprfRequest`]) and it does not unblind the response or derive the final OPRF
/// output; it stops right after the combined `DLog` equality proof has been verified.
///
/// Concretely, this function:
/// 1. Initializes sessions with the specified OPRF services, sending the blinded query and authentication information.
/// 2. Checks that all responding nodes agree on the same [`OprfPublicKey`].
/// 3. Generates the `DLog` equality challenge based on the commitments received from the services.
/// 4. Finishes the sessions by sending the challenge to the services and collecting their responses.
/// 5. Combines and verifies the `DLog` equality proof from the services.
///
/// # Returns
/// A tuple of the [`OprfPublicKey`] used, the [`ShareEpoch`] the nodes agreed on, the combined [`BlindedOprfResponse`], and the verified [`DLogEqualityProof`].
///
/// # Arguments
/// - `services`: List of WebSocket URIs of the OPRF nodes to contact (must be unique). See the helper functions [`to_oprf_uri`] and [`to_oprf_uri_many`].
/// - `threshold`: Number of nodes required to complete the protocol
/// - `request_id`: The UUID identifying this OPRF request, forwarded to all nodes
/// - `req`: The already-blinded [`OprfRequest`] to send to every node
/// - `connector`: TLS connector configuration for the WebSocket connections
///
/// # Timeout and Cancellation
/// Same considerations as [`distributed_oprf`] apply: no timeout is enforced internally, and dropping
/// the returned future drops all in-flight requests, but work already processed by a node cannot be undone.
///
/// # Errors
/// See the [`Error`] enum for all potential errors of this function.
#[instrument(level = "debug", skip_all, fields(request_id = %req.request_id))]
#[allow(
    clippy::missing_panics_doc,
    reason = "Can't really panic due to promises from called method"
)]
pub async fn distributed_oprf_core<OprfRequestAuth>(
    services: &[Uri],
    threshold: usize,
    req: OprfRequest<OprfRequestAuth>,
    connector: Connector,
) -> Result<
    (
        OprfPublicKey,
        ShareEpoch,
        DLogCommitmentsShamir,
        Vec<DLogProofShareShamir>,
    ),
    Error,
>
where
    OprfRequestAuth: Clone + Serialize + 'static,
{
    if threshold == 0 || threshold > services.len() {
        return Err(Error::InvalidThreshold {
            num_peers: services.len(),
            threshold,
        });
    }
    let services_dedup = services.iter().collect::<HashSet<_>>();
    if services_dedup.len() != services.len() {
        return Err(Error::NonUniqueServices);
    }

    let request_id = req.request_id;

    tracing::debug!("initializing sessions at {} services", services.len());
    let sessions = sessions::init_sessions(request_id, services, threshold, req, connector)
        .await
        .map_err(|errors| aggregate_error(threshold, errors))?;

    let oprf_public_key = sessions
        .oprf_public_keys
        .first()
        .copied()
        .expect("at least one session");
    if !sessions
        .oprf_public_keys
        .iter()
        .all(|pk| *pk == oprf_public_key)
    {
        tracing::error!("inconsistent OPRF public keys received from nodes");
        return Err(Error::InconsistentOprfPublicKeys);
    }

    let epoch = sessions.epoch;
    tracing::debug!("Will use epoch: {epoch}");
    tracing::debug!("compute the challenges for the services..");
    let challenge = generate_challenge_request(&sessions);

    tracing::debug!("finishing the sessions at the remaining services..");
    let responses = sessions::finish_sessions(sessions, challenge.clone())
        .await
        .map_err(Error::CannotFinishSession)?;

    Ok((oprf_public_key, epoch, challenge, responses))
}

/// Arguments required to finalize the distributed OPRF protocol after the network-facing part has completed.
pub struct FinalizeDistributedOprfArgs {
    /// The UUID identifying this OPRF request.
    pub request_id: Uuid,
    /// The OPRF input value to evaluate.
    pub query: ark_babyjubjub::Fq,
    /// The blinding factor used to blind the query.
    pub blinding_factor: BlindingFactor,
    /// Domain separator used in the final Poseidon hash to derive the output.
    pub domain_separator: ark_babyjubjub::Fq,
    /// The blinded query sent to the OPRF nodes.
    pub blinded_request: BlindedOprfRequest,
    /// The combined `DLog` commitments used to generate the challenge.
    pub challenge: DLogCommitmentsShamir,
    /// The proof shares collected from each node.
    pub responses: Vec<DLogProofShareShamir>,
    /// The public key of the OPRF, must be consistent across all nodes.
    pub oprf_public_key: OprfPublicKey,
    /// The `ShareEpoch` the nodes agreed on.
    pub epoch: ShareEpoch,
}

/// Finalizes the distributed OPRF protocol after the network-facing part has completed.
///
/// Unblinds the combined blinded response using the blinding factor, verifies the combined
/// `DLog` equality proof against the collected proof shares, and derives the final OPRF output
/// by hashing the domain separator, the original query, and the unblinded response.
///
/// # Returns
/// The final [`VerifiableOprfOutput`] containing the OPRF output, the `DLog` equality proof, and the blinded and unblinded responses.
///
/// # Arguments
/// - `args`: The [`FinalizeDistributedOprfArgs`] collected from the network-facing part of the protocol.
///
/// # Errors
/// Returns [`Error::InvalidDLogProof`] if the combined `DLog` equality proof fails verification.
pub fn finalize_distributed_oprf(
    FinalizeDistributedOprfArgs {
        request_id,
        query,
        blinding_factor,
        domain_separator,
        blinded_request,
        challenge,
        responses,
        oprf_public_key,
        epoch,
    }: FinalizeDistributedOprfArgs,
) -> Result<VerifiableOprfOutput, Error> {
    let blinding_factor_prepared = blinding_factor.prepare();
    let blinded_response = BlindedOprfResponse::new(challenge.blinded_response());
    let unblinded_response = blinded_response.unblind_response(&blinding_factor_prepared);

    let dlog_proof = verify_dlog_equality(
        request_id,
        oprf_public_key,
        &blinded_request,
        &responses,
        challenge.clone(),
    )?;

    let digest = poseidon2::bn254::t4::permutation(&[
        domain_separator,
        query,
        unblinded_response.x,
        unblinded_response.y,
    ]);

    let output = digest[1];

    Ok(VerifiableOprfOutput {
        output,
        blinded_request: blinded_request.blinded_query(),
        blinded_response: blinded_response.response(),
        dlog_proof,
        unblinded_response,
        oprf_public_key,
        epoch,
    })
}

/// Combines the [`DLogProofShareShamir`]s of the OPRF nodes and computes the final [`DLogEqualityProof`].
///
/// Verifies the proof and returns an [`Error`] iff the proof is invalid.
///
/// # Arguments
/// - `request_id`: The UUID of the OPRF request
/// - `oprf_public_key`: The public key of the OPRF, must be consistent across all nodes
/// - `blinded_request`: The blinded query sent to the OPRF nodes
/// - `proofs`: The proof shares collected from each node
/// - `challenge`: The combined `DLog` commitments used to generate the challenge
#[instrument(level = "debug", skip_all, fields(request_id = %request_id))]
pub fn verify_dlog_equality(
    request_id: Uuid,
    oprf_public_key: OprfPublicKey,
    blinded_request: &BlindedOprfRequest,
    proofs: &[DLogProofShareShamir],
    challenge: DLogCommitmentsShamir,
) -> Result<DLogEqualityProof, Error> {
    let blinded_response = challenge.blinded_response();
    let dlog_proof = challenge.combine_proofs(
        request_id,
        proofs,
        oprf_public_key.inner(),
        blinded_request.blinded_query(),
    );
    dlog_proof
        .verify(
            oprf_public_key.inner(),
            blinded_request.blinded_query(),
            blinded_response,
            ark_babyjubjub::EdwardsAffine::generator(),
        )
        .map_err(|_| Error::InvalidDLogProof)?;
    Ok(dlog_proof)
}

/// Generates the [`DLogCommitmentsShamir`] for the OPRF nodes used for the second step of the distributed OPRF protocol, respecting the returned set of sessions.
///
/// # Arguments
/// - `sessions`: The active OPRF sessions returned by [`init_sessions`]
#[instrument(level = "debug", skip(sessions))]
pub fn generate_challenge_request(sessions: &OprfSessions) -> DLogCommitmentsShamir {
    let contributing_parties = sessions
        .party_ids
        .iter()
        .map(|id| id.into_inner() + 1)
        .collect::<Vec<_>>();
    // Combine commitments from all sessions and create a single challenge
    DLogCommitmentsShamir::combine_commitments(&sessions.commitments, contributing_parties)
}

/// Fetches the [`OprfPublicKeyWithEpoch`] for the given [`OprfKeyId`] from a single service.
async fn fetch_oprf_public_key_from_service(
    url: &Url,
    oprf_key_id: OprfKeyId,
    client: &reqwest::Client,
) -> Result<Option<OprfPublicKeyWithEpoch>, reqwest::Error> {
    // Get rid of existing trailing slash, if any, and append a trailing slash to the path segments.
    let mut url = url.clone();
    url.path_segments_mut()
        .expect("url should not be cannot-be-a-base")
        .pop_if_empty()
        .push("");

    let response = client
        .get(
            url.join(oprf_key_id.to_string().as_str())
                .expect("OprfKeyId to_string() should produce a valid URL"),
        )
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    let response = response.error_for_status()?;

    Ok(Some(response.json::<OprfPublicKeyWithEpoch>().await?))
}

/// Fetches the [`OprfPublicKeyWithEpoch`] for a given [`OprfKeyId`] from a set of OPRF nodes,
/// returning it if `threshold` many nodes agree on the same value.
/// If `threshold` many nodes return `404 Not Found`, returns `Ok(None)`.
///
/// Nodes are queried concurrently via `GET {service}/oprf_pub/{key_id}` (see [`to_oprf_pub_key_url`]).
///
/// # Arguments
/// - `services`: Base URLs (up to `/oprf_pub`) of the OPRF nodes to query (must be unique)
/// - `threshold`: Number of nodes required to agree on the same [`OprfPublicKeyWithEpoch`]
/// - `key_id`: The [`OprfKeyId`] to fetch the public key for
/// - `client`: The [`reqwest::Client`] used to send the requests
///
/// # Errors
/// - [`Error::InvalidThreshold`] if `threshold` is `0` or greater than `services.len()`.
/// - [`Error::NonUniqueServices`] if `services` contains duplicate URLs.
/// - [`Error::Networking`] if `threshold` many nodes could not be reached, or returned an unexpected response.
/// - [`Error::InconsistentOprfPublicKeys`] if no single response reached `threshold` agreement.
#[instrument(level = "debug", skip(client))]
pub async fn fetch_oprf_public_key(
    urls: &[Url],
    threshold: usize,
    key_id: OprfKeyId,
    client: &reqwest::Client,
) -> Result<Option<OprfPublicKeyWithEpoch>, Error> {
    if threshold == 0 || threshold > urls.len() {
        return Err(Error::InvalidThreshold {
            num_peers: urls.len(),
            threshold,
        });
    }

    let urls_dedup = urls.iter().collect::<HashSet<_>>();
    if urls_dedup.len() != urls.len() {
        return Err(Error::NonUniqueServices);
    }

    let mut futures: FuturesUnordered<_> = urls
        .iter()
        .map(|url| fetch_oprf_public_key_from_service(url, key_id, client))
        .collect();

    let mut agreement: HashMap<OprfPublicKeyWithEpoch, usize> = HashMap::new();
    let mut not_found_count = 0usize;
    let mut network_errors = Vec::new();

    while let Some(result) = futures.next().await {
        match result {
            Ok(Some(response)) => {
                let count = agreement.entry(response.clone()).or_insert(0);
                *count += 1;
                if *count >= threshold {
                    return Ok(Some(response));
                }
            }
            Ok(None) => {
                not_found_count += 1;
                if not_found_count >= threshold {
                    return Ok(None);
                }
            }
            Err(err) => {
                network_errors.push(Box::new(err).into());
                if network_errors.len() >= threshold {
                    return Err(Error::Networking(network_errors));
                }
            }
        }
    }

    Err(Error::InconsistentOprfPublicKeys)
}

#[cfg(test)]
mod tests {
    use ark_ec::AdditiveGroup;
    use rand::Rng;

    use super::*;
    #[test]
    fn test_threshold_service_error() {
        let err_a1 = NodeError::ServiceError(ServiceError {
            error_code: 1,
            msg: Some("A".into()),
            kind: OprfErrorKind::Unknown,
        });
        let err_a2 = NodeError::ServiceError(ServiceError {
            error_code: 1,
            msg: Some("A".into()),
            kind: OprfErrorKind::Unknown,
        });
        let err_b = NodeError::ServiceError(ServiceError {
            error_code: 2,
            msg: Some("B".into()),
            kind: OprfErrorKind::Unknown,
        });

        let errors = vec![err_a1, err_a2, err_b];
        if let Error::ThresholdServiceError(ServiceError {
            error_code,
            msg,
            kind: typed_error,
        }) = aggregate_error(2, errors)
        {
            assert_eq!(error_code, 1);
            assert_eq!(msg.expect("Should have a message"), "A");
            assert_eq!(typed_error, OprfErrorKind::Unknown);
        } else {
            panic!("did not receive service error but expected it");
        }
    }

    #[test]
    fn test_threshold_unexpected_message() {
        let errors = vec![
            NodeError::UnexpectedMessage { reason: "oops1" },
            NodeError::UnexpectedMessage { reason: "oops1" },
            NodeError::UnexpectedMessage { reason: "oops2" },
        ];

        if let Error::UnexpectedMessage { reason } = aggregate_error(2, errors) {
            assert_eq!(reason, "oops1");
        } else {
            panic!("Expected UnexpectedMessage");
        }
    }

    #[test]
    fn test_threshold_ws_error() {
        let ws1: Box<dyn core::error::Error + Send + Sync> = Box::new(std::io::Error::other("ws1"));
        let ws2: Box<dyn core::error::Error + Send + Sync> = Box::new(std::io::Error::other("ws2"));
        let ws3: Box<dyn core::error::Error + Send + Sync> = Box::new(std::io::Error::other("ws3"));

        let errors = vec![
            NodeError::WsError(ws1),
            NodeError::ServiceError(ServiceError {
                error_code: 1,
                msg: Some("A".into()),
                kind: OprfErrorKind::Unknown,
            }),
            NodeError::WsError(ws2),
            NodeError::UnexpectedMessage { reason: "oops" },
            NodeError::WsError(ws3),
        ];

        let res = aggregate_error(3, errors);
        if let Error::Networking(ws_errors) = res {
            assert!(
                ws_errors.len() >= 3,
                "Expected at least 3 ws errors collected"
            );
        } else {
            panic!("Expected Networking error");
        }
    }

    #[test]
    fn test_node_error_disagreement() {
        let errors = vec![
            NodeError::ServiceError(ServiceError {
                error_code: 1,
                msg: Some("A".into()),
                kind: OprfErrorKind::Unknown,
            }),
            NodeError::ServiceError(ServiceError {
                error_code: 2,
                msg: Some("B".into()),
                kind: OprfErrorKind::Unknown,
            }),
            NodeError::UnexpectedMessage { reason: "oops" },
            NodeError::WsError(Box::new(std::io::Error::other("ws"))),
            NodeError::Unknown(Box::new(std::io::Error::other("unknown"))),
        ];
        let len = errors.len();

        let res = aggregate_error(3, errors);
        if let Error::NodeErrorDisagreement(all) = res {
            assert_eq!(all.len(), len, "All errors should be returned");
        } else {
            panic!("Expected NodeErrorDisagreement");
        }
    }

    #[test]
    fn test_unknown_ignored() {
        let errors = vec![
            NodeError::Unknown(Box::new(std::io::Error::other("unknown1"))),
            NodeError::Unknown(Box::new(std::io::Error::other("unknown2"))),
        ];
        let len = errors.len();

        let res = aggregate_error(1, errors);
        if let Error::NodeErrorDisagreement(all) = res {
            assert_eq!(all.len(), len);
        } else {
            panic!("Expected NodeErrorDisagreement since unknowns are ignored");
        }
    }

    #[test]
    fn test_threshold_epoch_mismatch() {
        let epoch_a = ShareEpoch::from(1u32);
        let epoch_b = ShareEpoch::from(2u32);
        let epoch_c = ShareEpoch::from(3u32);

        let errors = vec![
            NodeError::EpochMismatch(epoch_a),
            NodeError::EpochMismatch(epoch_b),
            NodeError::EpochMismatch(epoch_c),
        ];

        if let Error::EpochMismatch(epochs) = aggregate_error(3, errors) {
            assert_eq!(epochs.len(), 3);
            assert!(epochs.contains(&epoch_a));
            assert!(epochs.contains(&epoch_b));
            assert!(epochs.contains(&epoch_c));
        } else {
            panic!("Expected EpochMismatch error");
        }
    }

    #[test]
    fn test_epoch_mismatch_below_threshold_falls_through() {
        let epoch_a = ShareEpoch::from(1u32);
        let epoch_b = ShareEpoch::from(2u32);

        // Only 2 epoch mismatches but threshold is 3 — should not return EpochMismatch
        let errors = vec![
            NodeError::EpochMismatch(epoch_a),
            NodeError::EpochMismatch(epoch_b),
            NodeError::Unknown(Box::new(std::io::Error::other("unknown"))),
        ];

        let res = aggregate_error(3, errors);
        assert!(
            matches!(res, Error::NodeErrorDisagreement(_)),
            "Below-threshold epoch mismatches should fall through to NodeErrorDisagreement"
        );
    }

    #[test]
    fn test_epoch_mismatch_counts_nodes_not_distinct_epochs() {
        let epoch_1 = ShareEpoch::from(1u32);
        let epoch_2 = ShareEpoch::from(2u32);

        let errors = vec![
            NodeError::EpochMismatch(epoch_1),
            NodeError::EpochMismatch(epoch_1),
            NodeError::EpochMismatch(epoch_2),
            NodeError::EpochMismatch(epoch_2),
            NodeError::WsError(Box::new(std::io::Error::other("ws"))),
        ];

        if let Error::EpochMismatch(epochs) = aggregate_error(3, errors) {
            assert_eq!(
                epochs.len(),
                4,
                "Should contain one entry per node, not per distinct epoch"
            );
            assert_eq!(epochs.iter().filter(|&&e| e == epoch_1).count(), 2);
            assert_eq!(epochs.iter().filter(|&&e| e == epoch_2).count(), 2);
        } else {
            panic!("Expected EpochMismatch — got NodeErrorDisagreement");
        }
    }

    #[tokio::test]
    async fn test_services_dedup() {
        let mut rng = rand::thread_rng();

        let uri1: Uri = "https://example.com/api/issuer/oprf"
            .parse()
            .expect("Is a valid URI");
        let uri2: Uri = "https://example1.com/api/issuer/oprf"
            .parse()
            .expect("Is a valid URI"); // duplicate

        let services = &[uri1, uri2.clone(), uri2];
        let is_error = super::distributed_oprf(
            services,
            2,
            rng.r#gen(),
            BlindingFactor::rand(&mut rng),
            ark_babyjubjub::Fq::ZERO,
            (),
            Connector::Plain,
        )
        .await
        .expect_err("Should be an error");
        assert!(
            matches!(is_error, super::Error::NonUniqueServices),
            "Should be Error::NonUniqueServices"
        );
    }
}
