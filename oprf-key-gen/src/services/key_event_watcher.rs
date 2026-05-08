//! Alloy-based Key Generation Event Watcher
//!
//! This module provides [`key_event_watcher_task`], a task that can be spawned to monitor an
//! on-chain `OprfKeyRegistry` contract for key generation events.
//!
//! Responsibilities are split across three submodules:
//!
//! * **This file** — task loop, cursor management, and soft-error policy
//!   ([`handle_soft_errors`]).
//! * **[`events`]** — pure, I/O-free decoding of `Log<LogData>` into the typed
//!   [`events::KeyRegistryEvent`] enum.
//! * **[`handler`]** —  that calls [`DLogSecretGenService`],
//!   reads peer/consumer public keys from the contract, and submits contributions back
//!   via [`TransactionHandler`].
//!
//! The watcher loads the persisted [`ChainCursor`] from [`ChainCursorService`] on startup and
//! passes it to the event stream so backfill resumes from the last processed `(block, log_index)`.
//! The cursor is advanced only after an event is handled successfully — either cleanly or via a
//! soft-error downgrade in [`handle_soft_errors`].  Hard errors propagate immediately and the
//! cursor is **not** advanced, causing the watcher task to abort and restart from the last
//! successfully stored position.

use std::{
    num::NonZeroU16,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::{
    event_cursor_store::ChainCursorService,
    secret_manager::SecretManagerError,
    services::{
        key_event_watcher::{events::KeyRegistryEvent, handler::KeyRegistryEventHandler},
        secret_gen::{DLogSecretGenService, SecretGenError},
        transaction_handler::TransactionHandler,
    },
};
use alloy::{
    network::primitives::TransactionFailedError,
    primitives::{Address, LogData},
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
use oprf_types::chain::{
    OprfKeyRegistry::{self, AlreadySubmitted, DeletedId, OprfKeyRegistryErrors, WrongRound},
    RevertError,
    Verifier::VerifierErrors,
};
use tokio_util::sync::CancellationToken;
use tracing::instrument;

// #[cfg(test)]
// mod tests;

mod events;
mod handler;

type Result<T> = std::result::Result<T, KeyRegistryEventError>;

/// Unified error type for key-registry event handling.
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

/// Configuration bundle for [`key_event_watcher_task`].
pub(crate) struct KeyEventWatcherTaskConfig {
    /// HTTP provider used to verify contract readiness before subscribing.
    pub(crate) http_rpc_provider: web3::HttpRpcProvider,
    /// WebSocket provider used to subscribe to contract events.
    pub(crate) ws_rpc_provider: DynProvider,
    /// Address of the `OprfKeyRegistry` contract to watch.
    pub(crate) contract_address: Address,
    /// Secret-generation service that mutates local key-gen state in response to events.
    pub(crate) dlog_secret_gen_service: DLogSecretGenService,
    /// Persistent store for the `(block, log_index)` cursor; read on startup, written after
    /// each successfully handled log.
    pub(crate) chain_cursor_service: ChainCursorService,
    /// Set to `true` once the watcher has subscribed and is ready to process events.  Used
    /// by startup-ordering / health-check logic in the outer service.
    pub(crate) start_signal: Arc<AtomicBool>,
    /// Transaction handler used to submit round contributions back to the contract.
    pub(crate) transaction_handler: TransactionHandler,
    /// Filtering and backfill settings forwarded to the event-stream builder.
    pub(crate) event_stream_config: EventStreamConfig,
    /// MPC threshold; passed to [`DLogSecretGenService`] for each round-1 call.
    pub(crate) threshold: NonZeroU16,
    /// Signals the task to shut down cleanly.
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
        threshold,
        cancellation_token,
    } = args;

    tracing::info!("loading chain-cursor");
    let chain_cursor = chain_cursor_service
        .load_chain_cursor()
        .await
        .context("while loading chain cursor")?;

    let contract = OprfKeyRegistry::new(contract_address, http_rpc_provider.inner());

    tracing::info!("chain cursor at: {chain_cursor}");
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

    let event_handler = KeyRegistryEventHandler::new(
        contract,
        dlog_secret_gen_service,
        threshold,
        transaction_handler,
    );

    start_signal.store(true, Ordering::Relaxed);
    loop {
        tokio::select! {
            log = event_stream.next() => {
                let log = log.ok_or_else(||eyre::eyre!("logs subscribe stream was closed"))?.context("while fetching event from event_stream")?;

                key_gen_event(log, &event_handler, &chain_cursor_service).await?;
            }
            () = cancellation_token.cancelled() => {
                break;
            }
        };
    }

    tracing::info!("successfully closed key_event_watcher without error");
    Ok(())
}

/// Decode a single chain log, dispatch it to the event handler, apply the soft-error policy,
/// and - on success - advance the chain cursor.
///
/// Span fields populated by [`events::KeyRegistryEvent::record_span_fields`]: `oprf_key_id`, `share_epoch`, `event`.
///
/// `tx_hash` is recorded inside [`handler::KeyRegistryEventHandler::handle`] after a contribution is submitted.
#[instrument(
    level = "info",
    skip_all,
    fields(
        oprf_key_id=tracing::field::Empty,
        share_epoch=tracing::field::Empty,
        tx_hash=tracing::field::Empty,
        event=tracing::field::Empty,
    ))]
async fn key_gen_event(
    log: Log<LogData>,
    event_handler: &KeyRegistryEventHandler,
    chain_cursor_service: &ChainCursorService,
) -> Result<()> {
    tracing::trace!("parsing event...");
    let event = KeyRegistryEvent::try_decode_log(&log).context("while decoding chain event")?;
    event.record_span_fields(&tracing::Span::current());

    tracing::trace!("process event...");
    let result = event_handler.handle(event, &tracing::Span::current()).await;

    tracing::trace!("process result...");
    handle_soft_errors(result)?;

    tracing::trace!("store chain cursor...");
    let block_number = log
        .block_number
        .ok_or_else(|| eyre::eyre!("block number missing on log"))?;
    let index = log
        .log_index
        .ok_or_else(|| eyre::eyre!("log index missing on log"))?;
    let chain_cursor = ChainCursor::new(block_number, index);
    chain_cursor_service
        .store_chain_cursor(chain_cursor)
        .await?;
    Ok(())
}

/// Downgrades known recoverable errors to `Ok(())` so the cursor still advances.
///
/// The following cases are treated as soft errors:
///
/// * `WrongRound` — the contract rejected the contribution because the key-gen was likely
///   aborted; we log a warning and continue.
/// * `DeletedId` — the key was deleted before we could act on an event; logged as an error
///   (race condition) but not fatal.
/// * `AlreadySubmitted` — we already contributed in this round (duplicate event or restart);
///   safe to skip.
/// * `MissingIntermediates` — the intermediate values for this key/epoch are gone; the key-gen
///   is stuck and cannot be recovered without a contract-v2 call (see inline TODO).
/// * `RefusingToRollbackEpoch` — the secret manager detected an out-of-order event; logged
///   as a warning and skipped.
///
/// All other errors are returned as-is and will abort the watcher task.
fn handle_soft_errors(result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(KeyRegistryEventError::Revert(RevertError::OprfKeyRegistry(
            OprfKeyRegistryErrors::WrongRound(WrongRound(round)),
        ))) => {
            tracing::warn!(
                "Reverted event with wrong round - most likely this key-gen was aborted: we are in {round}"
            );
            Ok(())
        }
        Err(KeyRegistryEventError::Revert(RevertError::OprfKeyRegistry(
            OprfKeyRegistryErrors::DeletedId(DeletedId { id }),
        ))) => {
            tracing::error!(
                "This key was deleted before we could process an event - this is a race condition and should not actually happen during ordinary operations: {id}"
            );
            Ok(())
        }
        Err(KeyRegistryEventError::Revert(RevertError::OprfKeyRegistry(
            OprfKeyRegistryErrors::AlreadySubmitted(AlreadySubmitted),
        ))) => {
            tracing::warn!(
                "Already submitted for this round - we continue and mark this event as success"
            );
            Ok(())
        }
        Err(KeyRegistryEventError::SecretManagerError(
            SecretManagerError::MissingIntermediates(oprf_key_id, epoch),
        )) => {
            // TODO as soon as we release contract version 2 we call the appropriate function to mark this key-gen as stuck
            tracing::error!(
                "Cannot find intermediates for key-id {oprf_key_id} in epoch {epoch} - this key-gen is stuck"
            );
            Ok(())
        }

        Err(KeyRegistryEventError::SecretManagerError(
            SecretManagerError::RefusingToRollbackEpoch,
        )) => {
            tracing::warn!(
                "SecretManager refusing to rollback to older share - maybe we got an event out of order?"
            );
            Ok(())
        }
        Err(err) => Err(err),
    }
}
