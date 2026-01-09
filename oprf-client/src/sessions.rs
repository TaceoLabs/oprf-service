//! Handles session management of the client.
//!
//! See [`init_sessions`] and [`finish_sessions`] for more information.

use crate::ws::WebSocketSession;

use super::Error;
use oprf_core::ddlog_equality::shamir::DLogCommitmentsShamir;
use oprf_core::ddlog_equality::shamir::DLogProofShareShamir;
use oprf_core::ddlog_equality::shamir::PartialDLogCommitmentsShamir;
use oprf_types::api::v1::OprfRequest;
use oprf_types::api::v1::OprfResponse;
use oprf_types::crypto::PartyId;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_tungstenite::Connector;
use tracing::instrument;

/// Holds the active OPRF sessions with multiple nodes.
pub struct OprfSessions {
    pub(super) ws: Vec<WebSocketSession>,
    pub(super) party_ids: Vec<PartyId>,
    pub(super) commitments: Vec<PartialDLogCommitmentsShamir>,
}

impl OprfSessions {
    /// Creates an empty [`OprfSessions`] with preallocated capacity.
    ///
    fn with_capacity(capacity: usize) -> Self {
        Self {
            ws: Vec::with_capacity(capacity),
            party_ids: Vec::with_capacity(capacity),
            commitments: Vec::with_capacity(capacity),
        }
    }

    /// Adds a node's response to the sessions.
    fn push(&mut self, ws: WebSocketSession, response: OprfResponse) -> Result<(), String> {
        let OprfResponse {
            commitments,
            party_id,
        } = response;
        if let Some(position) = self
            .party_ids
            .iter()
            .position(|hay| *hay == response.party_id)
        {
            return Err(self.ws[position].service.clone());
        }
        self.ws.push(ws);
        self.party_ids.push(party_id);
        self.commitments.push(commitments);
        Ok(())
    }

    /// Returns the number of sessions currently stored.
    fn len(&self) -> usize {
        self.ws.len()
    }

    /// Sorts the sessions, party IDs and commitments by party ID in ascending order.
    fn sort_by_party_id(&mut self) {
        let mut combined: Vec<(WebSocketSession, PartyId, PartialDLogCommitmentsShamir)> = self
            .ws
            .drain(..)
            .zip(self.party_ids.drain(..))
            .zip(self.commitments.drain(..))
            .map(|((ws, party_id), commitments)| (ws, party_id, commitments))
            .collect();
        combined.sort_by_key(|(_, party_id, _)| *party_id);
        for (ws, party_id, commitments) in combined {
            self.ws.push(ws);
            self.party_ids.push(party_id);
            self.commitments.push(commitments);
        }
    }
}

/// Tries to establish a web-socket connection to the given service. On success sends the provided `req` to the service and reads the [`OprfResponse`].
///
/// Returns the [`WebSocketSession`] and the response on success.
#[instrument(level = "trace", skip(req, connector))]
async fn init_session<Auth: Serialize>(
    service: String,
    req: OprfRequest<Auth>,
    connector: Connector,
) -> Result<(WebSocketSession, OprfResponse), super::Error> {
    let mut session = WebSocketSession::new(service, connector).await?;
    session.send(req).await?;
    let response = session.read::<OprfResponse>().await?;
    Ok((session, response))
}

/// Write the `req` request to the provided [`WebSocketSession`].
///
/// On success, returns the parsed [`DLogProofShareShamir`] and gracefully closes the web-socket.
#[instrument(level = "trace", skip_all)]
async fn finish_session(
    mut session: WebSocketSession,
    req: DLogCommitmentsShamir,
) -> Result<DLogProofShareShamir, Error> {
    session.send(req).await?;
    let resp = session.read().await?;
    session.graceful_close().await;
    Ok(resp)
}

/// Completes all OPRF sessions in parallel by sending the provided [`DLogCommitmentsShamir`] to the open sessions.
///
/// **Important:**
/// - These must be the *same parties* that were used during the initial
///   `init_sessions` call.
/// - The order of the sessions matters: we return responses in the order provided and they need to match the original session list. This is crucial because Lagrange coefficients are computed in the meantime, and they need to match the shares obtained earlier.
///
/// Fails fast if any single request errors.
#[instrument(level = "debug", skip_all)]
pub async fn finish_sessions(
    sessions: OprfSessions,
    req: DLogCommitmentsShamir,
) -> Result<Vec<DLogProofShareShamir>, super::Error> {
    futures::future::try_join_all(
        sessions
            .ws
            .into_iter()
            .map(|service| finish_session(service, req.clone())),
    )
    .await
}

/// Initializes new OPRF sessions by opening a web-socket at `/api/v1/oprf` on a list of nodes, collecting responses until the given `threshold` is met.
///
/// Nodes are queried concurrently. Errors from some services are logged and ignored, unless they prevent reaching the threshold.
///
/// Returns a [`OprfSessions`] ready to be finalized with [`finish_sessions`].
#[instrument(level = "debug", skip_all)]
pub async fn init_sessions<OprfRequestAuth: Clone + Serialize + Send + 'static>(
    oprf_services: &[String],
    threshold: usize,
    req: OprfRequest<OprfRequestAuth>,
    connector: Connector,
) -> Result<OprfSessions, super::Error> {
    // only has one producer
    let (tx, mut rx) = mpsc::channel(1);
    // We spawn a dedicated task so that the dangling web-socket connections can gracefully close when we have threshold amount of sessions and continue with the normal flow.
    tokio::task::spawn({
        let oprf_services = oprf_services.to_vec();
        let mut open_sessions = 0;
        async move {
            let mut join_set = oprf_services
                .into_iter()
                .map(|service| init_session(service, req.clone(), connector.clone()))
                .collect::<JoinSet<_>>();
            while let Some(session_handle) = join_set.join_next().await {
                match session_handle.expect("Can join") {
                    Ok((session, resp)) => {
                        if open_sessions == threshold {
                            // The caller is most likely gone already - just close the connection
                            session.graceful_close().await;
                        } else {
                            open_sessions += 1;
                            if let Err(session) = tx.send((session, resp)).await {
                                tracing::debug!("No one listening anymore?");
                                let (session, _) = session.0;
                                session.graceful_close().await;
                            }
                        }
                    }
                    Err(err) => {
                        // we very much expect certain services to return an error therefore we do not log at warn/error level.
                        tracing::debug!("Got error response: {err:?}");
                    }
                }
            }
        }
    });
    let mut sessions = OprfSessions::with_capacity(threshold);

    while let Some((ws, resp)) = rx.recv().await {
        let service = ws.service.clone();
        tracing::debug!("adding commitment from {service}");
        if let Err(duplicate_service) = sessions.push(ws, resp) {
            tracing::warn!("{duplicate_service} and {service} send same Party ID!");
            continue;
        }
        tracing::debug!("received session {}", sessions.len());
        if sessions.len() == threshold {
            break;
        }
    }
    if sessions.len() == threshold {
        sessions.sort_by_party_id();
        Ok(sessions)
    } else {
        Err(super::Error::NotEnoughOprfResponses {
            n: sessions.len(),
            threshold,
        })
    }
}
