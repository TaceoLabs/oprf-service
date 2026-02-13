//! Handles session management of the client.
//!
//! See [`init_sessions`] and [`finish_sessions`] for more information.

use std::collections::HashMap;

use crate::ws::WebSocketSession;

use super::Error;
use oprf_core::ddlog_equality::shamir::DLogCommitmentsShamir;
use oprf_core::ddlog_equality::shamir::DLogProofShareShamir;
use oprf_core::ddlog_equality::shamir::PartialDLogCommitmentsShamir;
use oprf_types::ShareEpoch;
use oprf_types::api::OprfRequest;
use oprf_types::api::OprfResponse;
use oprf_types::crypto::OprfPublicKey;
use oprf_types::crypto::PartyId;
use serde::Serialize;
use tokio::task::JoinSet;
use tokio_tungstenite::Connector;
use tracing::instrument;

/// Holds the active OPRF sessions with multiple nodes.
#[derive(Default)]
pub struct OprfSessions {
    pub(super) ws: Vec<WebSocketSession>,
    pub(super) party_ids: Vec<PartyId>,
    pub(super) commitments: Vec<PartialDLogCommitmentsShamir>,
    pub(super) oprf_public_keys: Vec<OprfPublicKey>,
    pub(super) epoch: ShareEpoch,
}

impl OprfSessions {
    /// Creates an empty [`OprfSessions`] with preallocated capacity.
    ///
    fn with_capacity(epoch: ShareEpoch, capacity: usize) -> Self {
        Self {
            epoch,
            ws: Vec::with_capacity(capacity),
            party_ids: Vec::with_capacity(capacity),
            commitments: Vec::with_capacity(capacity),
            oprf_public_keys: Vec::with_capacity(capacity),
        }
    }

    /// Adds a node's response to the sessions.
    fn push(&mut self, ws: WebSocketSession, response: OprfResponse) -> Result<(), String> {
        let OprfResponse {
            commitments,
            party_id,
            oprf_pub_key_with_epoch,
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
        self.oprf_public_keys.push(oprf_pub_key_with_epoch.key);
        Ok(())
    }

    /// Returns the number of sessions currently stored.
    fn len(&self) -> usize {
        self.ws.len()
    }

    /// Sorts the sessions, party IDs and commitments by party ID in ascending order.
    fn sort_by_party_id(&mut self) {
        let mut combined = self
            .ws
            .drain(..)
            .zip(self.party_ids.drain(..))
            .zip(self.commitments.drain(..))
            .zip(self.oprf_public_keys.drain(..))
            .map(|(((ws, party_id), commitments), oprf_public_key)| {
                (ws, party_id, commitments, oprf_public_key)
            })
            .collect::<Vec<_>>();
        combined.sort_by_key(|(_, party_id, _, _)| *party_id);
        for (ws, party_id, commitments, oprf_public_key) in combined {
            self.ws.push(ws);
            self.party_ids.push(party_id);
            self.commitments.push(commitments);
            self.oprf_public_keys.push(oprf_public_key);
        }
    }
}

/// Tries to establish a web-socket connection to the given service. On success sends the provided `req` to the service and reads the [`OprfResponse`].
///
/// Returns the [`WebSocketSession`] and the response on success.
#[instrument(level = "trace", skip(req, connector))]
async fn init_session<Auth: Serialize>(
    service: String,
    module: String,
    req: OprfRequest<Auth>,
    connector: Connector,
) -> Result<(WebSocketSession, OprfResponse), super::Error> {
    let mut session = WebSocketSession::new(service, module, connector).await?;
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

/// Initializes new OPRF sessions by opening a web-socket at `/api/{module}/oprf` on a list of nodes, collecting responses until the given `threshold` is met.
///
/// Nodes are queried concurrently. Errors from some services are logged and ignored, unless they prevent reaching the threshold.
///
/// Returns a [`OprfSessions`] ready to be finalized with [`finish_sessions`].
#[instrument(level = "debug", skip_all)]
pub async fn init_sessions<OprfRequestAuth: Clone + Serialize + Send + 'static>(
    oprf_services: &[String],
    module: &str,
    threshold: usize,
    req: OprfRequest<OprfRequestAuth>,
    connector: Connector,
) -> Result<OprfSessions, super::Error> {
    let mut join_set = oprf_services
        .iter()
        .cloned()
        .map(|service| {
            let connector = connector.clone();
            let module = module.to_owned();
            let req = req.clone();
            async move {
                init_session(service.clone(), module, req, connector)
                    .await
                    .map_err(|err| (service, err))
            }
        })
        .collect::<JoinSet<_>>();
    let mut epoch_session_map = HashMap::new();
    let mut session_errors = HashMap::new();
    while let Some(session_handle) = join_set.join_next().await {
        match session_handle {
            Ok(Ok((session, resp))) => {
                let epoch = resp.oprf_pub_key_with_epoch.epoch;
                let epoch_session = epoch_session_map
                    .entry(epoch)
                    .or_insert_with(|| OprfSessions::with_capacity(epoch, threshold));
                tracing::debug!("received session for epoch: {epoch}");
                let service = session.service.clone();
                if let Err(duplicate_service) = epoch_session.push(session, resp) {
                    tracing::warn!("{duplicate_service} and {service} send same Party ID!");
                    continue;
                }
                if epoch_session.len() == threshold {
                    let mut chosen_sessions = std::mem::take(epoch_session);
                    chosen_sessions.sort_by_party_id();
                    tracing::debug!(
                        "Initiated sessions {} with epoch {}",
                        chosen_sessions.len(),
                        chosen_sessions.epoch
                    );
                    return Ok(chosen_sessions);
                }
            }
            Ok(Err((service, err))) => {
                // we very much expect certain services to return an error therefore we do not log at warn/error level.
                tracing::debug!("Got error response from {service}: {err:?}");
                session_errors.insert(service, err);
            }
            Err(_) => {
                tracing::warn!("Could not join init_session task")
            }
        }
    }

    if epoch_session_map.is_empty() {
        tracing::debug!("could not get a single session!");
    } else {
        tracing::debug!("could not get enough sessions. I got the following sessions:");
        for (epoch, sessions) in epoch_session_map {
            tracing::debug!("got for epoch {epoch} {} sessions", sessions.len())
        }
    }
    Err(super::Error::NotEnoughOprfResponses(
        threshold,
        session_errors,
    ))
}
