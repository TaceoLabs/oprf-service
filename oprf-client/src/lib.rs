#![deny(missing_docs, clippy::unwrap_used)]
//! This crate provides utility functions for clients of the distributed OPRF protocol.
//!
//! Most implementations will only need the [`distributed_oprf`] method. For more fine-grained workflows, we expose all necessary functions.
use core::fmt;
use std::collections::{HashMap, HashSet};

use ark_ec::AffineRepr as _;
use oprf_core::{
    ddlog_equality::shamir::{DLogCommitmentsShamir, DLogProofShareShamir},
    dlog_equality::DLogEqualityProof,
    oprf::{BlindedOprfRequest, BlindedOprfResponse, BlindingFactor},
};
use oprf_types::{ShareEpoch, api::OprfRequest, crypto::OprfPublicKey};
use serde::Serialize;
use tracing::instrument;
use uuid::Uuid;

mod sessions;
mod ws;

pub use http::Uri;
pub use http::uri::InvalidUri;
pub use sessions::OprfSessions;
pub use sessions::finish_sessions;
pub use sessions::init_sessions;
pub use tokio_tungstenite::Connector;

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

    let uri_str = format!("{}/api/{}/oprf", ws_base, auth);
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
        reason: String,
    },
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
    /// The DLog equality proof failed verification.
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
        reason: String,
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
}

/// Aggregates errors returned by nodes.
///
/// - If `threshold` nodes returned the same `ServiceError`, returns a consensus service error.
/// - If `threshold` nodes returned the same `UnexpectedMessage`, returns that consensus.
/// - If `threshold` nodes returned `WsError`s, collects them into a networking error.
/// - Otherwise, returns `NodeErrorDisagreement`.
///
/// Internal use only.
fn aggregate_error(threshold: usize, errors: Vec<NodeError>) -> Error {
    let mut service_errors = HashMap::new();
    let mut ws_errors_counters = 0;
    let mut unexpected_message = HashMap::new();

    for err in errors.iter() {
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
                if ws_errors_counters >= threshold {
                    break;
                }
            }
            NodeError::UnexpectedMessage { reason } => {
                let count = unexpected_message.entry(reason).or_insert(0);
                *count += 1;
                if *count >= threshold {
                    return Error::UnexpectedMessage {
                        reason: reason.to_owned(),
                    };
                }
            }
            // we ignore unknown for aggregation
            _ => {}
        }
    }

    if ws_errors_counters >= threshold {
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
    /// The DLog equality proof.
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
/// 3. Generates the DLog equality challenge based on the commitments received from the services.
/// 4. Finishes the sessions by sending the challenge to the services and collecting their responses
/// 5. Verifies the combined DLog equality proof from the services.
/// 6. Unblinds the combined OPRF response using the blinding factor.
/// 7. Computes the final OPRF output by hashing the original query and the unblinded response.
///
/// # Returns
/// The final [`VerifiableOprfOutput`] containing the OPRF output, the DLog equality proof, the blinded and unblinded responses.
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
/// # Errors
/// See the [`Error`] enum for all potential errors of this function.
#[instrument(level = "debug", skip_all, fields(request_id = tracing::field::Empty))]
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
    OprfRequestAuth: Clone + Serialize + Send + 'static,
{
    tracing::trace!(
        "starting distributed oprf. my version: {}",
        env!("CARGO_PKG_VERSION")
    );
    let services_dedup = services.iter().collect::<HashSet<_>>();
    if services_dedup.len() != services.len() {
        return Err(Error::NonUniqueServices);
    }

    let request_id = Uuid::new_v4();
    let distributed_oprf_span = tracing::Span::current();
    distributed_oprf_span.record("request_id", request_id.to_string());
    tracing::debug!("starting with request id: {request_id}");

    let blinded_request = oprf_core::oprf::client::blind_query(query, blinding_factor.clone());
    let oprf_req = OprfRequest {
        request_id,
        blinded_query: blinded_request.blinded_query(),
        auth,
    };

    tracing::debug!("initializing sessions at {} services", services.len());
    let sessions = sessions::init_sessions(services, threshold, oprf_req, connector)
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

    let dlog_proof = verify_dlog_equality(
        request_id,
        oprf_public_key,
        &blinded_request,
        responses,
        challenge.clone(),
    )?;

    let blinded_response = challenge.blinded_response();
    let blinding_factor_prepared = blinding_factor.clone().prepare();
    let oprf_blinded_response = BlindedOprfResponse::new(blinded_response);
    let unblinded_response = oprf_blinded_response.unblind_response(&blinding_factor_prepared);

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
        blinded_response,
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
/// - `challenge`: The combined DLog commitments used to generate the challenge
#[instrument(level = "debug", skip_all, fields(request_id = %request_id))]
pub fn verify_dlog_equality(
    request_id: Uuid,
    oprf_public_key: OprfPublicKey,
    blinded_request: &BlindedOprfRequest,
    proofs: Vec<DLogProofShareShamir>,
    challenge: DLogCommitmentsShamir,
) -> Result<DLogEqualityProof, Error> {
    let blinded_response = challenge.blinded_response();
    let dlog_proof = challenge.combine_proofs(
        request_id,
        &proofs,
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
        });
        let err_a2 = NodeError::ServiceError(ServiceError {
            error_code: 1,
            msg: Some("A".into()),
        });
        let err_b = NodeError::ServiceError(ServiceError {
            error_code: 2,
            msg: Some("B".into()),
        });

        let errors = vec![err_a1, err_a2, err_b];
        if let Error::ThresholdServiceError(ServiceError { error_code, msg }) =
            aggregate_error(2, errors)
        {
            assert_eq!(error_code, 1);
            assert_eq!(msg.expect("Should have a message"), "A");
        } else {
            panic!("did not receive service error but expected it");
        }
    }

    #[test]
    fn test_threshold_unexpected_message() {
        let errors = vec![
            NodeError::UnexpectedMessage {
                reason: "oops1".into(),
            },
            NodeError::UnexpectedMessage {
                reason: "oops1".into(),
            },
            NodeError::UnexpectedMessage {
                reason: "oops2".into(),
            },
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
            }),
            NodeError::WsError(ws2),
            NodeError::UnexpectedMessage {
                reason: "oops".into(),
            },
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
            }),
            NodeError::ServiceError(ServiceError {
                error_code: 2,
                msg: Some("B".into()),
            }),
            NodeError::UnexpectedMessage {
                reason: "oops".into(),
            },
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
