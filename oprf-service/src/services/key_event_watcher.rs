//! Alloy-based Key Generation Event Watcher
//!
//! This module provides [`key_event_watcher_task`], an task than can be spawned to monitor an on-chain `OprfKeyRegistry` contract for key generation events.
//!
//! The watcher subscribes to various key generation events and reports contributions back to the contract.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, LogData},
    providers::{DynProvider, Provider as _},
    rpc::types::{Filter, Log},
    sol_types::SolEvent as _,
};
use backon::{BackoffBuilder, ExponentialBuilder, Retryable as _};
use eyre::Context;
use futures::StreamExt as _;
use nodes_common::web3;
use oprf_types::{OprfKeyId, ShareEpoch, chain::OprfKeyRegistry};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, instrument};

use crate::services::{
    oprf_key_material_store::OprfKeyMaterialStore, secret_manager::SecretManagerService,
};

/// Represents errors returned when fetching OPRF key material from the [`SecretManagerService`].
///
/// This error type is mainly used to convert `Option` results into an
/// actionable error for retry/backoff logic.
///
/// Variants:
/// - `NotFound` – the requested material for a given OPRF key ID and epoch
///   does not yet exist. Can be used to signal retryable conditions.
/// - `Internal` – wraps any internal database or I/O errors encountered
///   while fetching the material.
#[derive(Debug, thiserror::Error)]
enum FetchOprfKeyMaterialError {
    /// Cannot find the share with requested oprf-key-id and epoch.
    #[error("Cannot find requested material")]
    NotFound,
    /// Internal error from DB.
    #[error("internal error: {0:?}")]
    Internal(#[from] eyre::Report),
}

/// The arguments to start the key-even-watcher.
pub(crate) struct KeyEventWatcherTaskArgs {
    pub(crate) http_rpc_provider: web3::HttpRpcProvider,
    pub(crate) ws_rpc_provider: DynProvider,
    pub(crate) contract_address: Address,
    pub(crate) secret_manager: SecretManagerService,
    pub(crate) oprf_key_material_store: OprfKeyMaterialStore,
    pub(crate) get_oprf_key_material_timeout: Duration,
    pub(crate) start_block: Option<u64>,
    pub(crate) started: Arc<AtomicBool>,
    pub(crate) cancellation_token: CancellationToken,
}

/// Background task that subscribes to key generation events and handles them.
///
/// Connects to the blockchain via WebSocket and verifies that the
/// `OprfKeyRegistry` contract is ready.
pub(crate) async fn key_event_watcher_task(
    key_event_watcher_task_args: KeyEventWatcherTaskArgs,
) -> eyre::Result<()> {
    // shutdown service if event watcher encounters an error and drops this guard
    let cancellation_token = key_event_watcher_task_args.cancellation_token.clone();
    let _drop_guard = cancellation_token.drop_guard_ref();

    tracing::info!("start handling events");
    let result = handle_events(key_event_watcher_task_args).await;
    match result.as_ref() {
        Ok(()) => tracing::info!("stopped key event watcher without error"),
        Err(err) => tracing::error!(?err, "key event watcher encountered an error"),
    }
    result
}

/// Filters for various key generation event signatures and handles them
async fn handle_events(key_event_watcher_task_args: KeyEventWatcherTaskArgs) -> eyre::Result<()> {
    let KeyEventWatcherTaskArgs {
        http_rpc_provider,
        ws_rpc_provider,
        contract_address,
        secret_manager,
        oprf_key_material_store,
        get_oprf_key_material_timeout,
        start_block,
        started,
        cancellation_token,
    } = key_event_watcher_task_args;
    let event_signatures = vec![
        OprfKeyRegistry::SecretGenFinalize::SIGNATURE_HASH,
        OprfKeyRegistry::KeyDeletion::SIGNATURE_HASH,
    ];
    let filter = Filter::new()
        .address(contract_address)
        .from_block(BlockNumberOrTag::Latest)
        .event_signature(event_signatures.clone());
    // subscribe now so we don't miss any events between now and when we start processing past events
    let sub = ws_rpc_provider.subscribe_logs(&filter).await?;
    let mut latest_block = 0;

    // if start_block is set, load past events from there to head
    if let Some(start_block) = start_block {
        tracing::info!("loading past events from block {start_block}..");
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Number(start_block))
            .to_block(BlockNumberOrTag::Latest)
            .event_signature(event_signatures);
        let logs = http_rpc_provider
            .get_logs(&filter)
            .await
            .context("while loading past logs")?;
        for log in logs {
            let block_number = log.block_number.unwrap_or_default();
            latest_block = block_number;
            tracing::info!("handling past event from block {block_number}..");
            key_gen_event(
                log,
                &oprf_key_material_store,
                &secret_manager,
                get_oprf_key_material_timeout,
            )
            .await
            .context("while handling past log")?;
        }
    }

    let mut stream = sub.into_stream();
    // finally set to healthy
    tracing::info!("key event watcher is ready");
    started.store(true, Ordering::Relaxed);
    loop {
        let log = tokio::select! {
            log = stream.next() => {
                log.ok_or_else(||eyre::eyre!("logs subscribe stream was closed"))?
            }
            () = cancellation_token.cancelled() => {
                break;
            }
        };
        // skip logs from blocks we've already handled with get_logs
        if let Some(block_number) = log.block_number
            && block_number <= latest_block
        {
            tracing::info!(
                "skipping event from block {block_number} - already handled up to {latest_block}"
            );
            continue;
        }
        key_gen_event(
            log,
            &oprf_key_material_store,
            &secret_manager,
            get_oprf_key_material_timeout,
        )
        .await
        .context("while handling log")?;
    }
    Ok(())
}

#[instrument(level = "info", skip_all)]
async fn key_gen_event(
    log: Log<LogData>,
    oprf_key_material_store: &OprfKeyMaterialStore,
    secret_manager: &SecretManagerService,
    get_oprf_key_material_timeout: Duration,
) -> eyre::Result<()> {
    match log.topic0() {
        Some(&OprfKeyRegistry::SecretGenFinalize::SIGNATURE_HASH) => handle_finalize(
            log,
            oprf_key_material_store,
            secret_manager,
            get_oprf_key_material_timeout,
        )
        .await
        .context("while handling finalize")?,

        Some(&OprfKeyRegistry::KeyDeletion::SIGNATURE_HASH) => {
            handle_delete(&log, oprf_key_material_store).context("while handling deletion")?;
        }
        x => {
            tracing::warn!("unknown event: {x:?}");
        }
    }
    Ok(())
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty))]
async fn handle_finalize(
    log: Log<LogData>,
    oprf_key_material_store: &OprfKeyMaterialStore,
    secret_manager: &SecretManagerService,
    get_oprf_key_material_timeout: Duration,
) -> eyre::Result<()> {
    let finalize = log.log_decode().context("while decoding finalize event")?;
    let OprfKeyRegistry::SecretGenFinalize { oprfKeyId, epoch } = finalize.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    tracing::info!("trying to fetch {oprf_key_id} for epoch {epoch}");
    let current_span = tracing::Span::current();
    tokio::spawn(
        fetch_oprf_key_material_from_secret_manager(
            oprf_key_id,
            oprf_key_material_store.clone(),
            secret_manager.clone(),
            get_oprf_key_material_timeout,
            epoch.into(),
        )
        .instrument(tracing::info_span!(parent: &current_span,"fetch_oprf_key_material", oprf_key_id=%oprf_key_id, epoch=%epoch)),
    );
    Ok(())
}

async fn fetch_oprf_key_material_from_secret_manager(
    oprf_key_id: OprfKeyId,
    oprf_key_material_store: OprfKeyMaterialStore,
    secret_manager: SecretManagerService,
    get_oprf_key_material_timeout: Duration,
    epoch: ShareEpoch,
) {
    let backoff_strategy = ExponentialBuilder::new()
        .with_total_delay(Some(get_oprf_key_material_timeout))
        .without_max_times()
        .build();
    let result = (|| async {
        secret_manager
            .get_oprf_key_material(oprf_key_id, epoch)
            .await?
            .ok_or_else(|| FetchOprfKeyMaterialError::NotFound)
    })
    .retry(backoff_strategy)
    .sleep(tokio::time::sleep)
    .when(|e| matches!(e, FetchOprfKeyMaterialError::NotFound))
    .notify(|_, duration| {
        tracing::debug!(
            "Share {oprf_key_id} with epoch {epoch} not yet in DB. Retrying after {duration:?}."
        );
    })
    .await;
    match result {
        Ok(key_material) => {
            tracing::trace!("got key from secret manager for {oprf_key_id} and epoch {epoch}");
            oprf_key_material_store.insert(oprf_key_id, key_material);
        }
        Err(FetchOprfKeyMaterialError::NotFound) => {
            tracing::error!(
                "Could not fetch oprf-key-id {oprf_key_id} and epoch {epoch} after {get_oprf_key_material_timeout:?}. Will continue anyways."
            );
        }
        Err(err) => {
            tracing::error!(%err, "could not fetch key-material");
        }
    }
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty))]
fn handle_delete(
    log: &Log<LogData>,
    oprf_key_material_store: &OprfKeyMaterialStore,
) -> eyre::Result<()> {
    let key_delete = log
        .log_decode()
        .context("while decoding key deletion event")?;
    let OprfKeyRegistry::KeyDeletion { oprfKeyId } = key_delete.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    tracing::info!("got key deletion event for {oprf_key_id}");
    oprf_key_material_store.remove(oprf_key_id);
    Ok(())
}
