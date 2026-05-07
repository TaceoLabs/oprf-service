//! Alloy-based Key Generation Event Watcher
//!
//! This module provides [`key_event_watcher_task`], a task that can be spawned to monitor an
//! on-chain `OprfKeyRegistry` contract for key generation events.
//!
//! The watcher loads the persisted [`ChainCursor`]
//! from the [`ChainCursorService`] on startup and
//! passes it to the event stream so backfill resumes from the last processed `(block, log_index)`.
//! After each handled log the cursor is stored unconditionally before propagating any handler error.
//! The watcher subscribes to various key generation events and reports contributions back to the contract.

use std::{
    num::NonZeroU16,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::{
    event_cursor_store::ChainCursorService,
    metrics::{
        METRICS_ATTRID_PROTOCOL, METRICS_ATTRID_ROLE, METRICS_ATTRVAL_PROTOCOL_KEY_GEN,
        METRICS_ATTRVAL_PROTOCOL_RESHARE, METRICS_ATTRVAL_ROLE_CONSUMER,
        METRICS_ATTRVAL_ROLE_PRODUCER, METRICS_ID_KEY_GEN_ABORT, METRICS_ID_KEY_GEN_DELETION,
        METRICS_ID_KEY_GEN_NOT_ENOUGH_PRODUCERS, METRICS_ID_KEY_GEN_ROUND_1_FINISH,
        METRICS_ID_KEY_GEN_ROUND_1_START, METRICS_ID_KEY_GEN_ROUND_2_FINISH,
        METRICS_ID_KEY_GEN_ROUND_2_START, METRICS_ID_KEY_GEN_ROUND_3_FINISH,
        METRICS_ID_KEY_GEN_ROUND_3_START, METRICS_ID_KEY_GEN_ROUND_4_FINISH,
        METRICS_ID_KEY_GEN_ROUND_4_START,
    },
    secret_manager::SecretManagerError,
    services::{
        secret_gen::{Contributions, DLogSecretGenService, SecretGenError},
        transaction_handler::TransactionHandler,
    },
};
use alloy::{
    network::primitives::TransactionFailedError,
    primitives::{Address, LogData, U256},
    providers::DynProvider,
    rpc::types::Log,
    sol_types::SolEvent as _,
    transports::TransportErrorKind,
};
use eyre::Context;
use futures::StreamExt;
use nodes_common::web3::{
    self,
    event_stream::{ChainCursor, EventStreamBuilder, EventStreamConfig},
};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    chain::{
        OprfKeyGen::Round2Contribution,
        OprfKeyRegistry::{
            self, AlreadySubmitted, OprfKeyRegistryErrors, OprfKeyRegistryInstance, WrongRound,
        },
        RevertError,
        Verifier::VerifierErrors,
    },
    crypto::{EphemeralEncryptionPublicKey, OprfPublicKey, SecretGenCiphertext},
};
use tokio_util::sync::CancellationToken;
use tracing::instrument;

#[cfg(test)]
mod tests;

type Result<T> = std::result::Result<T, KeyRegistryEventError>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum KeyRegistryEventError {
    #[error("RevertReason: {0}")]
    Revert(RevertError),
    #[error("Error when interacting with contract - source: {0}")]
    Contract(#[source] alloy::contract::Error),
    #[error(transparent)]
    Rpc(#[from] alloy::transports::RpcError<TransportErrorKind>),
    #[error(transparent)]
    TransactionFailedError(#[from] TransactionFailedError),
    #[error("Cannot handle event due to secret-manager error: {0}")]
    SecretManagerError(#[source] SecretManagerError),
    #[error(transparent)]
    Internal(#[from] eyre::Report),
}

impl From<SecretGenError> for KeyRegistryEventError {
    fn from(value: SecretGenError) -> Self {
        match value {
            SecretGenError::SecretManagerError(secret_manager_error) => {
                if let SecretManagerError::Internal(report) = secret_manager_error {
                    Self::Internal(report)
                } else {
                    Self::SecretManagerError(secret_manager_error)
                }
            }
            SecretGenError::Internal(report) => Self::Internal(report),
        }
    }
}

impl From<alloy::contract::Error> for KeyRegistryEventError {
    fn from(value: alloy::contract::Error) -> Self {
        if let Some(err) = value.as_decoded_interface_error::<OprfKeyRegistryErrors>() {
            KeyRegistryEventError::Revert(RevertError::OprfKeyRegistry(err))
        } else if let Some(err) = value.as_decoded_interface_error::<VerifierErrors>() {
            KeyRegistryEventError::Revert(RevertError::Verifier(err))
        } else {
            KeyRegistryEventError::Contract(value)
        }
    }
}

pub(crate) struct KeyEventWatcherTaskConfig {
    pub(crate) http_rpc_provider: web3::HttpRpcProvider,
    pub(crate) ws_rpc_provider: DynProvider,
    pub(crate) contract_address: Address,
    pub(crate) dlog_secret_gen_service: DLogSecretGenService,
    pub(crate) chain_cursor_service: ChainCursorService,
    pub(crate) start_signal: Arc<AtomicBool>,
    pub(crate) transaction_handler: TransactionHandler,
    pub(crate) event_stream_config: EventStreamConfig,
    pub(crate) cancellation_token: CancellationToken,
}

/// Background task that subscribes to key generation events and handles them.
///
/// Connects to the blockchain via WebSocket and verifies that the
/// `OprfKeyRegistry` contract is ready.
pub(crate) async fn key_event_watcher_task(args: KeyEventWatcherTaskConfig) -> eyre::Result<()> {
    // shutdown service if event watcher encounters an error and drops this guard
    let _drop_guard = args.cancellation_token.clone().drop_guard();
    tracing::info!("start handling events");
    let KeyEventWatcherTaskConfig {
        http_rpc_provider,
        ws_rpc_provider,
        contract_address,
        dlog_secret_gen_service,
        chain_cursor_service,
        start_signal,
        transaction_handler,
        event_stream_config,
        cancellation_token,
    } = args;

    tracing::info!("loading chain-cursor");
    let chain_cursor = chain_cursor_service
        .load_chain_cursor()
        .await
        .context("while loading chain cursor")?;
    tracing::info!("chain cursor at: {chain_cursor}");
    let contract = OprfKeyRegistry::new(contract_address, http_rpc_provider.inner());
    let event_signatures = vec![
        OprfKeyRegistry::SecretGenRound1::SIGNATURE_HASH,
        OprfKeyRegistry::SecretGenRound2::SIGNATURE_HASH,
        OprfKeyRegistry::SecretGenRound3::SIGNATURE_HASH,
        OprfKeyRegistry::SecretGenFinalize::SIGNATURE_HASH,
        OprfKeyRegistry::ReshareRound1::SIGNATURE_HASH,
        OprfKeyRegistry::ReshareRound3::SIGNATURE_HASH,
        OprfKeyRegistry::KeyDeletion::SIGNATURE_HASH,
        OprfKeyRegistry::KeyGenAbort::SIGNATURE_HASH,
        OprfKeyRegistry::NotEnoughProducers::SIGNATURE_HASH,
    ];

    let mut event_stream = EventStreamBuilder::with_config(
        chain_cursor,
        contract_address,
        http_rpc_provider,
        ws_rpc_provider.clone(),
        event_signatures,
        event_stream_config,
    )
    .build()
    .await
    .context("while building event-stream")?;

    start_signal.store(true, Ordering::Relaxed);
    loop {
        let log = tokio::select! {
            log = event_stream.next() => {
                log.ok_or_else(||eyre::eyre!("logs subscribe stream was closed"))?.context("while fetching event from event_stream")?
            }
            () = cancellation_token.cancelled() => {
                break;
            }
        };
        let new_chain_cursor = key_gen_event(
            log,
            &contract,
            &dlog_secret_gen_service,
            &transaction_handler,
        )
        .await?;

        chain_cursor_service
            .store_chain_cursor(new_chain_cursor)
            .await
            .context("while storing new event cursor")?;
    }

    tracing::info!("successfully closed key_event_watcher without error");
    Ok(())
}

#[instrument(level = "info", skip_all, fields(oprf_key_id=tracing::field::Empty, epoch=tracing::field::Empty, event=tracing::field::Empty, block=tracing::field::Empty,index=tracing::field::Empty))]
#[allow(
    clippy::too_many_lines,
    reason = "Is easier to have one large match instead of many single methods"
)]
async fn key_gen_event(
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> Result<ChainCursor> {
    let block = log
        .block_number
        .ok_or_else(|| eyre::eyre!("block number empty in log"))?;
    let index = log
        .log_index
        .ok_or_else(|| eyre::eyre!("index empty in log"))?;

    let handle_span = tracing::Span::current();
    handle_span.record("block", block);
    handle_span.record("index", index);
    let result = match log.topic0() {
        Some(&OprfKeyRegistry::SecretGenRound1::SIGNATURE_HASH) => {
            let OprfKeyRegistry::SecretGenRound1 {
                oprfKeyId,
                threshold,
            } = log
                .log_decode()
                .context("while decoding key-gen round1 event")?
                .inner
                .data;
            handle_span.record("oprf_key_id", oprfKeyId.to_string());
            handle_span.record("epoch", "0");
            handle_span.record("event", "key-gen round 1");
            handle_keygen_round1(
                OprfKeyId::from(oprfKeyId),
                threshold,
                secret_gen,
                transaction_handler,
            )
            .await
        }
        Some(&OprfKeyRegistry::SecretGenRound2::SIGNATURE_HASH) => {
            let OprfKeyRegistry::SecretGenRound2 { oprfKeyId, epoch } = log
                .log_decode()
                .context("while decoding key-gen round2 event")?
                .inner
                .data;
            handle_span.record("oprf_key_id", oprfKeyId.to_string());
            handle_span.record("epoch", epoch.to_string());
            let epoch = ShareEpoch::from(epoch);
            if epoch.is_initial_epoch() {
                handle_span.record("event", "key-gen round 2");
            } else {
                handle_span.record("event", "reshare round 2");
            }
            handle_round2(
                OprfKeyId::from(oprfKeyId),
                epoch,
                contract,
                secret_gen,
                transaction_handler,
            )
            .await
        }
        Some(&OprfKeyRegistry::SecretGenRound3::SIGNATURE_HASH) => {
            let OprfKeyRegistry::SecretGenRound3 { oprfKeyId } = log
                .log_decode()
                .context("while decoding key-gen round3 event")?
                .inner
                .data;
            let oprf_key_id = OprfKeyId::from(oprfKeyId);
            handle_span.record("oprf_key_id", oprf_key_id.to_string());
            handle_span.record("epoch", "0");
            handle_span.record("event", "key-gen round 3");
            handle_keygen_round3(oprf_key_id, contract, secret_gen, transaction_handler).await
        }
        Some(&OprfKeyRegistry::SecretGenFinalize::SIGNATURE_HASH) => {
            let OprfKeyRegistry::SecretGenFinalize { oprfKeyId, epoch } = log
                .log_decode()
                .context("while decoding finalize event")?
                .inner
                .data;
            let oprf_key_id = OprfKeyId::from(oprfKeyId);
            let epoch = ShareEpoch::from(epoch);
            handle_span.record("oprf_key_id", oprf_key_id.to_string());
            handle_span.record("epoch", epoch.to_string());
            handle_span.record("event", "finalize");
            handle_finalize(oprf_key_id, epoch, contract, secret_gen).await
        }
        Some(&OprfKeyRegistry::ReshareRound1::SIGNATURE_HASH) => {
            let OprfKeyRegistry::ReshareRound1 {
                oprfKeyId,
                threshold,
                epoch,
            } = log
                .log_decode()
                .context("while decoding reshare round1 event")?
                .inner
                .data;
            let oprf_key_id = OprfKeyId::from(oprfKeyId);
            let epoch = ShareEpoch::from(epoch);
            handle_span.record("oprf_key_id", oprf_key_id.to_string());
            handle_span.record("epoch", epoch.to_string());
            handle_span.record("event", "reshare round 1");
            handle_reshare_round1(
                oprf_key_id,
                threshold,
                epoch,
                secret_gen,
                transaction_handler,
            )
            .await
        }
        Some(&OprfKeyRegistry::ReshareRound3::SIGNATURE_HASH) => {
            let OprfKeyRegistry::ReshareRound3 {
                oprfKeyId,
                lagrange,
                epoch,
            } = log
                .log_decode()
                .context("while decoding reshare round3 event")?
                .inner
                .data;
            let oprf_key_id = OprfKeyId::from(oprfKeyId);
            let epoch = ShareEpoch::from(epoch);
            handle_span.record("oprf_key_id", oprf_key_id.to_string());
            handle_span.record("epoch", epoch.to_string());
            handle_span.record("event", "reshare round 3");
            handle_reshare_round3(
                oprf_key_id,
                epoch,
                lagrange,
                contract,
                secret_gen,
                transaction_handler,
            )
            .await
        }
        Some(&OprfKeyRegistry::KeyGenAbort::SIGNATURE_HASH) => {
            let OprfKeyRegistry::KeyGenAbort { oprfKeyId } = log
                .log_decode()
                .context("while decoding abort event")?
                .inner
                .data;
            let oprf_key_id = OprfKeyId::from(oprfKeyId);
            handle_span.record("oprf_key_id", oprf_key_id.to_string());
            handle_span.record("event", "abort");
            handle_abort(oprf_key_id, secret_gen).await
        }
        Some(&OprfKeyRegistry::KeyDeletion::SIGNATURE_HASH) => {
            let OprfKeyRegistry::KeyDeletion { oprfKeyId } = log
                .log_decode()
                .context("while decoding key-deletion event")?
                .inner
                .data;
            let oprf_key_id = OprfKeyId::from(oprfKeyId);
            handle_span.record("oprf_key_id", oprf_key_id.to_string());
            handle_span.record("event", "delete");
            handle_delete(oprf_key_id, secret_gen).await
        }
        Some(&OprfKeyRegistry::NotEnoughProducers::SIGNATURE_HASH) => {
            let OprfKeyRegistry::NotEnoughProducers { oprfKeyId } = log
                .log_decode()
                .context("while decoding not-enough-producers event")?
                .inner
                .data;
            let oprf_key_id = OprfKeyId::from(oprfKeyId);
            handle_span.record("oprf_key_id", oprf_key_id.to_string());
            handle_span.record("event", "not enough producers");
            handle_not_enough_producers(oprf_key_id, secret_gen).await
        }
        x => {
            tracing::warn!("unknown event: {x:?}");
            Ok(())
        }
    };
    let new_chain_cursor = ChainCursor::new(block, index);
    match result {
        Ok(()) => Ok(new_chain_cursor),
        Err(KeyRegistryEventError::Revert(RevertError::OprfKeyRegistry(
            OprfKeyRegistryErrors::WrongRound(WrongRound(round)),
        ))) => {
            tracing::warn!(
                "Reverted event with wrong round - most likely this key-gen was aborted: we are in {round}"
            );
            Ok(new_chain_cursor)
        }

        Err(KeyRegistryEventError::Revert(RevertError::OprfKeyRegistry(
            OprfKeyRegistryErrors::AlreadySubmitted(AlreadySubmitted),
        ))) => {
            tracing::warn!(
                "Already submitted for this round - we continue and mark this event as success"
            );
            Ok(new_chain_cursor)
        }
        Err(KeyRegistryEventError::SecretManagerError(
            SecretManagerError::MissingIntermediates(oprf_key_id, epoch),
        )) => {
            // TODO as soon as we release contract version 2 we call the appropriate function to mark this key-gen as stuck
            tracing::error!(
                "Cannot find intermediates for key-id {oprf_key_id} in epoch {epoch} - this key-gen is stuck"
            );
            Ok(new_chain_cursor)
        }

        Err(KeyRegistryEventError::SecretManagerError(
            SecretManagerError::RefusingToRollbackEpoch,
        )) => {
            tracing::warn!(
                "SecretManager refusing to rollback to older share - maybe we got an event out of order?"
            );
            Ok(new_chain_cursor)
        }
        Err(err) => Err(err),
    }
}

async fn handle_keygen_round1(
    oprf_key_id: OprfKeyId,
    threshold: U256,
    secret_gen: &DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> Result<()> {
    tracing::trace!("Received KeyGenRound1 event");
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_1_START,
        METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_KEY_GEN)
    .increment(1);

    // wrap everything in a future to log to log the the potential error inside this span
    let threshold =
        NonZeroU16::try_from(u16::try_from(threshold).context("while parsing threshold")?)
            .context("threshold from contract is zero")?;
    let contribution = secret_gen
        .key_gen_round1(oprf_key_id, ShareEpoch::default(), threshold)
        .await
        .context("while doing key-gen round1")?;
    tracing::trace!("finished round1 - now reporting to chain..");
    transaction_handler
        .add_round1_keygen_contribution(oprf_key_id, contribution)
        .await?;
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_1_FINISH,
        METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_KEY_GEN)
    .increment(1);
    tracing::info!("Finished key-gen 1 for {oprf_key_id:?}");
    Ok(())
}

async fn handle_round2(
    oprf_key_id: OprfKeyId,
    epoch: ShareEpoch,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> Result<()> {
    tracing::trace!("Received SecretGenRound2 event");
    let protocol = if epoch.is_initial_epoch() {
        METRICS_ATTRVAL_PROTOCOL_KEY_GEN
    } else {
        METRICS_ATTRVAL_PROTOCOL_RESHARE
    };
    // We do not know yet whether this node participates as producer or consumer for this round.
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_2_START, METRICS_ATTRID_PROTOCOL=> protocol)
        .increment(1);
    tracing::trace!("fetching ephemeral public keys from chain..");
    let nodes = contract
        .loadPeerPublicKeysForProducers(oprf_key_id.into_inner())
        .call()
        .await;
    // Handle this separately because consumers can legitimately hit `WrongRound` here after
    // producers have already advanced the contract state.
    let nodes = match nodes {
        Ok(nodes) => nodes,
        Err(err) => {
            if let Some(WrongRound(round)) = err.as_decoded_error::<OprfKeyRegistry::WrongRound>() {
                tracing::trace!("reshare is already in round: {round} - we were a consumer");
                // An empty producer list signals the consumer path below.
                Vec::new()
            } else {
                Err(err)?
            }
        }
    };
    let role = if nodes.is_empty() {
        METRICS_ATTRVAL_ROLE_CONSUMER
    } else {
        tracing::trace!("got keys from chain - parsing..");
        let nodes = nodes
            .into_iter()
            .map(EphemeralEncryptionPublicKey::try_from)
            .collect::<eyre::Result<Vec<_>>>()?;
        let contribution = secret_gen
            .producer_round2(oprf_key_id, epoch, nodes)
            .await?;
        tracing::trace!("finished round 2 - now reporting");
        let contribution = Round2Contribution::from(contribution);
        transaction_handler
            .add_round2_contribution(oprf_key_id, contribution)
            .await?;
        METRICS_ATTRVAL_ROLE_PRODUCER
    };
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_2_FINISH,
            METRICS_ATTRID_ROLE => role,
            METRICS_ATTRID_PROTOCOL=> protocol)
    .increment(1);
    tracing::info!("Finished {protocol} 2 for {oprf_key_id:?} and epoch {epoch} as {role}");
    Ok(())
}

async fn handle_keygen_round3(
    oprf_key_id: OprfKeyId,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> Result<()> {
    tracing::trace!("Received SecretGenRound3 event");
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_3_START,
        METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_KEY_GEN)
    .increment(1);
    handle_round3_inner(
        oprf_key_id,
        ShareEpoch::default(),
        contract,
        secret_gen,
        Contributions::Full,
        transaction_handler,
    )
    .await?;
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_3_FINISH,
        METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_KEY_GEN)
    .increment(1);
    tracing::info!("Finished key-gen round 3 for {oprf_key_id:?}");
    Ok(())
}

async fn handle_finalize(
    oprf_key_id: OprfKeyId,
    epoch: ShareEpoch,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &DLogSecretGenService,
) -> Result<()> {
    tracing::trace!("Event for {oprf_key_id} with epoch {epoch}");
    let protocol = if epoch.is_initial_epoch() {
        METRICS_ATTRVAL_PROTOCOL_KEY_GEN
    } else {
        METRICS_ATTRVAL_PROTOCOL_RESHARE
    };
    // we don't know yet whether we are key_gen or reshare, FINISH holds this information
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_4_START,
        METRICS_ATTRID_PROTOCOL => protocol)
    .increment(1);
    let oprf_public_key = match contract
        .getOprfPublicKey(oprf_key_id.into_inner())
        .call()
        .await
    {
        Ok(oprf_public_key) => oprf_public_key,
        Err(err) => {
            if let Some(OprfKeyRegistry::DeletedId { id: _ }) =
                err.as_decoded_error::<OprfKeyRegistry::DeletedId>()
            {
                tracing::info!(
                    "Key got deleted in the meantime - we ignore this key for now. Nodes will run into an error, but they will be fine"
                );
                return Ok(());
            }
            return Err(KeyRegistryEventError::from(err));
        }
    };
    let oprf_public_key = OprfPublicKey::new(oprf_public_key.try_into()?);
    secret_gen
        .finalize(oprf_key_id, epoch, oprf_public_key)
        .await
        .context("while finalizing secret-gen")?;
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_4_FINISH,
            METRICS_ATTRID_PROTOCOL => protocol)
    .increment(1);
    tracing::info!("Finished finalize {protocol} for {oprf_key_id:?} with epoch {epoch}");
    Ok(())
}

async fn handle_reshare_round1(
    oprf_key_id: OprfKeyId,
    threshold: U256,
    epoch: ShareEpoch,
    secret_gen: &DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> Result<()> {
    tracing::trace!("Received ReshareRound1 event");
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_1_START,
        METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_RESHARE)
    .increment(1);
    let threshold = u16::try_from(threshold).context("while parsing threshold")?;

    tracing::trace!("need to load the previous epoch share for reshare");
    let contribution = secret_gen
        .reshare_round1(oprf_key_id, epoch, threshold)
        .await
        .context("while doing round 1 reshare")?;
    transaction_handler
        .add_round1_reshare_contribution(oprf_key_id, contribution)
        .await?;
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_1_FINISH,
            METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_RESHARE)
    .increment(1);
    tracing::info!("Finished reshare round 1 for {oprf_key_id:?} with epoch {epoch}");
    Ok(())
}

async fn handle_reshare_round3(
    oprf_key_id: OprfKeyId,
    epoch: ShareEpoch,
    lagrange: Vec<U256>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> Result<()> {
    tracing::trace!("Received ReshareRound3 event");
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_3_START,
        METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_RESHARE)
    .increment(1);
    tracing::trace!("parsing lagrange coefficients..");
    let lagrange = lagrange
        .into_iter()
        .filter_map(|x| {
            if x.is_zero() {
                // filter the empty coefficients - the smart contract produces lagrange coeffs 0 for the not relevant parties
                None
            } else {
                Some(oprf_types::chain::try_u256_into_bjj_fr(x))
            }
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    handle_round3_inner(
        oprf_key_id,
        epoch,
        contract,
        secret_gen,
        Contributions::Shamir(lagrange),
        transaction_handler,
    )
    .await?;
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_3_FINISH,
        METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_RESHARE)
    .increment(1);
    tracing::info!("Finished reshare round 3 for {oprf_key_id:?}");
    Ok(())
}

async fn handle_delete(oprf_key_id: OprfKeyId, secret_gen: &DLogSecretGenService) -> Result<()> {
    tracing::trace!("Received Delete event for {oprf_key_id}");
    ::metrics::counter!(METRICS_ID_KEY_GEN_DELETION).increment(1);
    // Delete finalized shares and any associated in-progress state for this key.
    secret_gen
        .delete_oprf_key_material(oprf_key_id)
        .await
        .with_context(|| format!("while deleting oprf key-material {oprf_key_id}"))?;
    tracing::info!("successfully deleted {oprf_key_id:?}");
    Ok(())
}

async fn handle_abort(oprf_key_id: OprfKeyId, secret_gen: &DLogSecretGenService) -> Result<()> {
    ::metrics::counter!(METRICS_ID_KEY_GEN_ABORT).increment(1);
    // In contrast to delete, abort only removes in-progress state and keeps finalized shares.
    secret_gen
        .abort_keygen(oprf_key_id)
        .await
        .with_context(|| format!("while aborting key-gen {oprf_key_id}"))?;
    tracing::info!("successfully aborted {oprf_key_id:?}");
    Ok(())
}

async fn handle_not_enough_producers(
    oprf_key_id: OprfKeyId,
    secret_gen: &DLogSecretGenService,
) -> Result<()> {
    ::metrics::counter!(METRICS_ID_KEY_GEN_NOT_ENOUGH_PRODUCERS).increment(1);
    tracing::warn!("Received not-enough-producers for {oprf_key_id:?}");
    // Clear the in-progress state associated with this key, but keep the last confirmed share.
    secret_gen
        .abort_keygen(oprf_key_id)
        .await
        .with_context(|| format!("while handling not-enough-producers {oprf_key_id}"))?;
    tracing::info!("successfully aborted {oprf_key_id:?}");
    Ok(())
}

async fn handle_round3_inner(
    oprf_key_id: OprfKeyId,
    epoch: ShareEpoch,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &DLogSecretGenService,
    contributions: Contributions,
    transaction_handler: &TransactionHandler,
) -> Result<()> {
    tracing::trace!("reading ciphers from chain..");
    let ciphers = contract
        .checkIsParticipantAndReturnRound2Ciphers(oprf_key_id.into_inner())
        .call()
        .await?;

    tracing::trace!("got ciphers from chain {} - parsing..", ciphers.len());
    let ciphers = ciphers
        .into_iter()
        .map(SecretGenCiphertext::try_from)
        .collect::<eyre::Result<Vec<_>>>()?;
    tracing::trace!("getting the public keys from the producers...");
    let pks = contract
        .loadPeerPublicKeysForConsumers(oprf_key_id.into_inner())
        .call()
        .await?;

    let pks = pks
        .into_iter()
        .map(EphemeralEncryptionPublicKey::try_from)
        .collect::<eyre::Result<Vec<_>>>()?;
    secret_gen
        .round3(oprf_key_id, epoch, ciphers, contributions, &pks)
        .await?;
    tracing::trace!("finished round 3 - now reporting");
    transaction_handler
        .add_round3_contribution(oprf_key_id)
        .await?;
    Ok(())
}
