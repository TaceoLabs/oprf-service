//! Alloy-based Key Generation Event Watcher
//!
//! This module provides [`key_event_watcher_task`], an task than can be spawned to monitor an on-chain `OprfKeyRegistry` contract for key generation events.
//!
//! The watcher subscribes to various key generation events and reports contributions back to the contract.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::{
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
    services::{
        secret_gen::{Contributions, DLogSecretGenService},
        transaction_handler::TransactionHandler,
    },
};
use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, LogData, U256},
    providers::{DynProvider, Provider},
    rpc::types::{Filter, Log},
    sol_types::SolEvent as _,
};
use eyre::Context;
use futures::StreamExt as _;
use nodes_common::web3;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    chain::{
        OprfKeyGen::Round2Contribution,
        OprfKeyRegistry::{self, OprfKeyRegistryErrors, OprfKeyRegistryInstance, WrongRound},
        RevertError,
        Verifier::VerifierErrors,
    },
    crypto::{EphemeralEncryptionPublicKey, OprfPublicKey, SecretGenCiphertext},
};
use tokio_util::sync::CancellationToken;
use tracing::instrument;

#[cfg(test)]
mod tests;

type Result<T> = std::result::Result<T, TransactionError>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum TransactionError {
    #[error("RevertReason: {0}")]
    Revert(RevertError),
    #[error(transparent)]
    Rpc(#[from] eyre::Report),
}

impl From<alloy::contract::Error> for TransactionError {
    fn from(value: alloy::contract::Error) -> Self {
        if let Some(err) = value.as_decoded_interface_error::<OprfKeyRegistryErrors>() {
            TransactionError::Revert(RevertError::OprfKeyRegistry(err))
        } else if let Some(err) = value.as_decoded_interface_error::<VerifierErrors>() {
            TransactionError::Revert(RevertError::Verifier(err))
        } else {
            TransactionError::Rpc(eyre::eyre!(
                "cannot finish transaction and call afterwards failed as well: {value:?}"
            ))
        }
    }
}

pub(crate) struct KeyEventWatcherTaskConfig {
    pub(crate) http_provider: web3::HttpRpcProvider,
    pub(crate) ws_provider: DynProvider,
    pub(crate) contract_address: Address,
    pub(crate) dlog_secret_gen_service: DLogSecretGenService,
    pub(crate) start_block: Option<u64>,
    pub(crate) start_signal: Arc<AtomicBool>,
    pub(crate) transaction_handler: TransactionHandler,
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
    handle_events(args)
        .await
        .inspect(|()| tracing::info!("successfully closed key_event_watcher without error"))
}

/// Filters for various key generation event signatures and handles them
async fn handle_events(args: KeyEventWatcherTaskConfig) -> eyre::Result<()> {
    let KeyEventWatcherTaskConfig {
        http_provider,
        ws_provider,
        contract_address,
        dlog_secret_gen_service,
        start_block,
        start_signal,
        transaction_handler,
        cancellation_token,
    } = args;
    let contract = OprfKeyRegistry::new(contract_address, http_provider.inner());
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
    let filter = Filter::new()
        .address(contract_address)
        .from_block(BlockNumberOrTag::Latest)
        .event_signature(event_signatures.clone());
    // subscribe now so we don't miss any events between now and when we start processing past events
    let sub = ws_provider.subscribe_logs(&filter).await?;
    let mut latest_block = 0;

    // if start_block is set, load past events from there to head
    if let Some(start_block) = start_block {
        tracing::info!("loading past events from block {start_block}..");
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Number(start_block))
            .to_block(BlockNumberOrTag::Latest)
            .event_signature(event_signatures);
        let logs = http_provider
            .get_logs(&filter)
            .await
            .context("while loading past logs")?;
        for log in logs {
            let block_number = log.block_number.unwrap_or_default();
            latest_block = block_number;
            tracing::info!("handling past event from block {block_number}..");
            key_gen_event(
                log,
                &contract,
                &dlog_secret_gen_service,
                &transaction_handler,
            )
            .await
            .context("while handling past log")?;
        }
    }

    let mut stream = sub.into_stream();
    start_signal.store(true, Ordering::Relaxed);
    tracing::info!("key event watcher is ready");
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
            &contract,
            &dlog_secret_gen_service,
            &transaction_handler,
        )
        .await
        .context("while handling log")?;
    }
    Ok(())
}

#[instrument(level = "info", skip_all, fields(oprf_key_id=tracing::field::Empty, epoch=tracing::field::Empty, event=tracing::field::Empty))]
#[allow(
    clippy::too_many_lines,
    reason = "Is easier to have one large match instead of many single methods"
)]
async fn key_gen_event(
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> Result<()> {
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
            let handle_span = tracing::Span::current();
            handle_span.record("oprf_key_id", oprfKeyId.to_string());
            handle_span.record("epoch", "0");
            handle_span.record("event", "key-gen round 1");
            handle_keygen_round1(
                OprfKeyId::from(oprfKeyId),
                threshold,
                contract,
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
            let handle_span = tracing::Span::current();
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
            let handle_span = tracing::Span::current();
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
            let handle_span = tracing::Span::current();
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
            let handle_span = tracing::Span::current();
            handle_span.record("oprf_key_id", oprf_key_id.to_string());
            handle_span.record("epoch", epoch.to_string());
            handle_span.record("event", "reshare round 1");
            handle_reshare_round1(
                oprf_key_id,
                threshold,
                epoch,
                contract,
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
            let handle_span = tracing::Span::current();
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
            let handle_span = tracing::Span::current();
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
            let handle_span = tracing::Span::current();
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
            let handle_span = tracing::Span::current();
            handle_span.record("oprf_key_id", oprf_key_id.to_string());
            handle_span.record("event", "not enough producers");
            handle_not_enough_producers(oprf_key_id, secret_gen).await
        }
        x => {
            tracing::warn!("unknown event: {x:?}");
            return Ok(());
        }
    };
    match result {
        Ok(()) => Ok(()),
        Err(TransactionError::Revert(RevertError::OprfKeyRegistry(
            OprfKeyRegistryErrors::WrongRound(WrongRound(round)),
        ))) => {
            tracing::info!(
                "Reverted event with wrong round - most likely this key-gen was aborted: we are in {round}"
            );
            Ok(())
        }
        Err(err) => {
            tracing::error!("{err}; {err:?}");
            Err(err)
        }
    }
}

async fn handle_keygen_round1(
    oprf_key_id: OprfKeyId,
    threshold: U256,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> Result<()> {
    tracing::trace!("Received KeyGenRound1 event");
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_1_START,
        METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_KEY_GEN)
    .increment(1);

    // wrap everything in a future to log to log the the potential error inside this span
    let threshold = u16::try_from(threshold).context("while parsing threshold")?;
    let contribution = secret_gen
        .key_gen_round1(oprf_key_id, ShareEpoch::default(), threshold)
        .await
        .context("while doing key-gen round1")?;
    tracing::trace!("finished round1 - now reporting to chain..");
    transaction_handler
        .attempt_transaction(|| {
            contract.addRound1KeyGenContribution(oprf_key_id.into_inner(), contribution.clone())
        })
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
        let res = secret_gen
            .producer_round2(oprf_key_id, epoch, nodes)
            .await
            .context("while doing round2")?;
        let contribution = res.ok_or_else(|| {
            // TODO here we will report that the key-gen is stuck, but this will happen in a dedicated PR
            eyre::eyre!("key-gen is stuck in round2")
        })?;
        tracing::trace!("finished round 2 - now reporting");
        let contribution = Round2Contribution::from(contribution);
        transaction_handler
            .attempt_transaction(|| {
                contract.addRound2Contribution(oprf_key_id.into_inner(), contribution.clone())
            })
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
            return Err(TransactionError::from(err));
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
    contract: &OprfKeyRegistryInstance<DynProvider>,
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
        .attempt_transaction(|| {
            contract.addRound1ReshareContribution(oprf_key_id.into_inner(), contribution.clone())
        })
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
        .await
        .context("while doing round3")?
        .ok_or_else(||
            // TODO here we will report that the key-gen is stuck, but this will happen in a dedicated PR
            eyre::eyre!("key-gen is stuck in round3"))?;
    tracing::trace!("finished round 3 - now reporting");
    transaction_handler
        .attempt_transaction(|| contract.addRound3Contribution(oprf_key_id.into_inner()))
        .await?;
    Ok(())
}
