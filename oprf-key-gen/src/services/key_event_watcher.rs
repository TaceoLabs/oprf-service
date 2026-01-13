//! Alloy-based Key Generation Event Watcher
//!
//! This module provides [`key_event_watcher_task`], an task than can be spawned to monitor an on-chain OprfKeyRegistry contract for key generation events.
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
        METRICS_ATTRVAL_ROLE_PRODUCER, METRICS_ID_KEY_GEN_DELETION_FINISH,
        METRICS_ID_KEY_GEN_DELETION_START, METRICS_ID_KEY_GEN_ROUND_1_FINISH,
        METRICS_ID_KEY_GEN_ROUND_1_START, METRICS_ID_KEY_GEN_ROUND_2_FINISH,
        METRICS_ID_KEY_GEN_ROUND_2_START, METRICS_ID_KEY_GEN_ROUND_3_FINISH,
        METRICS_ID_KEY_GEN_ROUND_3_START, METRICS_ID_KEY_GEN_ROUND_4_FINISH,
        METRICS_ID_KEY_GEN_ROUND_4_START,
    },
    services::{
        secret_gen::{Contributions, DLogSecretGenService},
        secret_manager::SecretManagerService,
        transaction_handler::{TransactionHandler, TransactionIdentifier, TransactionType},
    },
};
use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, LogData},
    providers::{DynProvider, Provider},
    rpc::types::{Filter, Log},
    sol_types::SolEvent as _,
};
use eyre::Context;
use futures::StreamExt as _;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    chain::{
        OprfKeyRegistry::{self, OprfKeyRegistryInstance},
        SecretGenRound1Contribution,
        Types::{Round1Contribution, Round2Contribution},
    },
    crypto::{EphemeralEncryptionPublicKey, OprfPublicKey, PartyId, SecretGenCiphertext},
};
use tokio_util::sync::CancellationToken;
use tracing::instrument;

pub(crate) struct KeyEventWatcherTaskConfig {
    pub(crate) party_id: PartyId,
    pub(crate) provider: DynProvider,
    pub(crate) contract_address: Address,
    pub(crate) secret_manager: SecretManagerService,
    pub(crate) dlog_secret_gen_service: DLogSecretGenService,
    pub(crate) start_block: Option<u64>,
    pub(crate) transaction_handler: TransactionHandler,
    pub(crate) start_signal: Arc<AtomicBool>,
    pub(crate) cancellation_token: CancellationToken,
}

/// Background task that subscribes to key generation events and handles them.
///
/// Connects to the blockchain via WebSocket and verifies that the
/// `OprfKeyRegistry` contract is ready.
pub(crate) async fn key_event_watcher_task(args: KeyEventWatcherTaskConfig) -> eyre::Result<()> {
    // shutdown service if event watcher encounters an error and drops this guard
    let cancellation_token = args.cancellation_token.clone();
    let _drop_guard = cancellation_token.drop_guard_ref();
    tracing::info!(
        "checking OprfKeyRegistry ready state at address {}..",
        args.contract_address
    );
    let contract = OprfKeyRegistry::new(args.contract_address, args.provider.clone());
    if !contract.isContractReady().call().await? {
        eyre::bail!("OprfKeyRegistry contract not ready");
    }
    tracing::info!("ready!");

    tracing::info!("start handling events");
    match handle_events(args).await {
        Ok(_) => tracing::info!("stopped key event watcher"),
        Err(err) => tracing::error!("key event watcher encountered an error: {err:?}"),
    }
    Ok(())
}

/// Filters for various key generation event signatures and handles them
async fn handle_events(args: KeyEventWatcherTaskConfig) -> eyre::Result<()> {
    let KeyEventWatcherTaskConfig {
        party_id,
        provider,
        contract_address,
        secret_manager,
        mut dlog_secret_gen_service,
        start_block,
        transaction_handler,
        start_signal,
        cancellation_token,
    } = args;
    let contract = OprfKeyRegistry::new(contract_address, provider.clone());
    let event_signatures = vec![
        OprfKeyRegistry::SecretGenRound1::SIGNATURE_HASH,
        OprfKeyRegistry::SecretGenRound2::SIGNATURE_HASH,
        OprfKeyRegistry::SecretGenRound3::SIGNATURE_HASH,
        OprfKeyRegistry::SecretGenFinalize::SIGNATURE_HASH,
        OprfKeyRegistry::ReshareRound1::SIGNATURE_HASH,
        OprfKeyRegistry::ReshareRound3::SIGNATURE_HASH,
        OprfKeyRegistry::KeyDeletion::SIGNATURE_HASH,
    ];
    let filter = Filter::new()
        .address(contract_address)
        .from_block(BlockNumberOrTag::Latest)
        .event_signature(event_signatures.clone());
    // subscribe now so we don't miss any events between now and when we start processing past events
    let sub = provider.subscribe_logs(&filter).await?;
    let mut latest_block = 0;

    // if start_block is set, load past events from there to head
    if let Some(start_block) = start_block {
        tracing::info!("loading past events from block {start_block}..");
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Number(start_block))
            .to_block(BlockNumberOrTag::Latest)
            .event_signature(event_signatures);
        let logs = provider
            .get_logs(&filter)
            .await
            .context("while loading past logs")?;
        for log in logs {
            let block_number = log.block_number.unwrap_or_default();
            latest_block = block_number;
            tracing::info!("handling past event from block {block_number}..");
            handle_log(
                party_id,
                log,
                &contract,
                &mut dlog_secret_gen_service,
                &secret_manager,
                &transaction_handler,
            )
            .await
            .context("while handling past log")?;
        }
    };

    let mut stream = sub.into_stream();
    start_signal.store(true, Ordering::Relaxed);
    tracing::info!("key event watcher is ready");
    loop {
        let log = tokio::select! {
            log = stream.next() => {
                log.ok_or_else(||eyre::eyre!("logs subscribe stream was closed"))?
            }
            _ = cancellation_token.cancelled() => {
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
        handle_log(
            party_id,
            log,
            &contract,
            &mut dlog_secret_gen_service,
            &secret_manager,
            &transaction_handler,
        )
        .await
        .context("while handling log")?;
    }
    Ok(())
}

#[instrument(level = "info", skip_all)]
async fn handle_log(
    party_id: PartyId,
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    secret_manager: &SecretManagerService,
    transaction_handler: &TransactionHandler,
) -> eyre::Result<()> {
    match log.topic0() {
        Some(&OprfKeyRegistry::SecretGenRound1::SIGNATURE_HASH) => {
            handle_keygen_round1(party_id, log, contract, secret_gen, transaction_handler)
                .await
                .context("while handling round1")?
        }
        Some(&OprfKeyRegistry::SecretGenRound2::SIGNATURE_HASH) => {
            handle_round2(party_id, log, contract, secret_gen, transaction_handler)
                .await
                .context("while handling round2")?
        }
        Some(&OprfKeyRegistry::SecretGenRound3::SIGNATURE_HASH) => {
            handle_keygen_round3(party_id, log, contract, secret_gen, transaction_handler)
                .await
                .context("while handling round3")?
        }
        Some(&OprfKeyRegistry::SecretGenFinalize::SIGNATURE_HASH) => {
            handle_finalize(log, contract, secret_gen, secret_manager)
                .await
                .context("while handling finalize")?
        }
        Some(&OprfKeyRegistry::ReshareRound1::SIGNATURE_HASH) => handle_reshare_round1(
            party_id,
            log,
            contract,
            secret_gen,
            secret_manager,
            transaction_handler,
        )
        .await
        .context("while handling round1")?,
        Some(&OprfKeyRegistry::ReshareRound3::SIGNATURE_HASH) => {
            handle_reshare_round3(party_id, log, contract, secret_gen, transaction_handler)
                .await
                .context("while handling round3")?
        }
        Some(&OprfKeyRegistry::KeyDeletion::SIGNATURE_HASH) => {
            handle_delete(log, secret_gen, secret_manager)
                .await
                .context("while handling deletion")?
        }
        x => {
            tracing::warn!("unknown event: {x:?}");
        }
    }
    Ok(())
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty, epoch=tracing::field::Empty))]
async fn handle_keygen_round1(
    party_id: PartyId,
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> eyre::Result<()> {
    tracing::info!("Received KeyGenRound1 event");
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_1_START,
        METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_KEY_GEN)
    .increment(1);
    let log = log
        .log_decode()
        .context("while decoding key-gen round1 event")?;
    let OprfKeyRegistry::SecretGenRound1 {
        oprfKeyId,
        threshold,
    } = log.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    handle_span.record("epoch", "0");
    tracing::info!("Event for {oprfKeyId} with threshold {threshold}");

    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    let threshold = u16::try_from(threshold)?;
    let SecretGenRound1Contribution {
        oprf_key_id,
        contribution,
    } = secret_gen.key_gen_round1(oprf_key_id, threshold);
    tracing::debug!("finished round1 - now reporting to chain..");
    let transaction_identifier =
        TransactionIdentifier::keygen(oprf_key_id, party_id, TransactionType::Round1);
    transaction_handler
        .attempt_transaction(transaction_identifier, || {
            contract
                .addRound1KeyGenContribution(oprf_key_id.into_inner(), contribution.clone().into())
        })
        .await?;
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_1_FINISH,
        METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_KEY_GEN)
    .increment(1);
    Ok(())
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty, epoch=tracing::field::Empty))]
async fn handle_round2(
    party_id: PartyId,
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> eyre::Result<()> {
    tracing::info!("Received SecretGenRound2 event");
    // we don't know yet whether we are producer or consumer, FINISH holds this information
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_2_START).increment(1);
    let round2 = log
        .log_decode()
        .context("while decoding secret-gen round2 event")?;
    let OprfKeyRegistry::SecretGenRound2 { oprfKeyId, epoch } = round2.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    handle_span.record("epoch", epoch.to_string());
    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    tracing::info!("fetching ephemeral public keys from chain..");
    let nodes = contract
        .loadPeerPublicKeysForProducers(oprfKeyId)
        .call()
        .await
        .context("while loading eph keys")?;
    if nodes.is_empty() {
        tracing::debug!("I am not a producer - nothing do to for me except clean after me");
        secret_gen.consumer_round2(oprf_key_id);
        ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_2_FINISH,
            METRICS_ATTRID_ROLE => METRICS_ATTRVAL_ROLE_CONSUMER)
        .increment(1);
        return Ok(());
    }
    tracing::debug!("got keys from chain - parsing..");
    let nodes = nodes
        .into_iter()
        .map(EphemeralEncryptionPublicKey::try_from)
        .collect::<eyre::Result<Vec<_>>>()?;
    // block_in_place here because we do a lot CPU work
    let res = tokio::task::block_in_place(|| {
        secret_gen
            .producer_round2(oprf_key_id, nodes)
            .context("while doing round2")
    })?;
    tracing::debug!("finished round 2 - now reporting");
    let contribution = Round2Contribution::from(res.contribution);
    let transaction_identifier =
        TransactionIdentifier::keygen(oprf_key_id, party_id, TransactionType::Round2);
    transaction_handler
        .attempt_transaction(transaction_identifier, || {
            contract.addRound2Contribution(res.oprf_key_id.into_inner(), contribution.clone())
        })
        .await?;
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_2_FINISH,
            METRICS_ATTRID_ROLE => METRICS_ATTRVAL_ROLE_PRODUCER)
    .increment(1);
    Ok(())
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty, epoch=tracing::field::Empty))]
async fn handle_keygen_round3(
    party_id: PartyId,
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> eyre::Result<()> {
    tracing::info!("Received SecretGenRound3 event");
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_3_START,
        METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_KEY_GEN)
    .increment(1);
    let round3 = log
        .log_decode()
        .context("while decoding secret-gen round3 event")?;
    let OprfKeyRegistry::SecretGenRound3 { oprfKeyId } = round3.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    handle_span.record("epoch", "0");
    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    let transaction_identifier =
        TransactionIdentifier::keygen(oprf_key_id, party_id, TransactionType::Round3);
    let result = handle_round3_inner(
        oprf_key_id,
        contract,
        secret_gen,
        Contributions::Full,
        transaction_identifier,
        transaction_handler,
    )
    .await;
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_3_FINISH,
        METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_KEY_GEN)
    .increment(1);
    result
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty, epoch=tracing::field::Empty))]
async fn handle_finalize(
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    secret_manager: &SecretManagerService,
) -> eyre::Result<()> {
    tracing::info!("Received SecretGenFinalize event");
    // we don't know yet whether we are key_gen or reshare, FINISH holds this information
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_4_START).increment(1);
    let finalize = log
        .log_decode()
        .context("while decoding secret-gen finalize event")?;
    let OprfKeyRegistry::SecretGenFinalize { oprfKeyId, epoch } = finalize.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    handle_span.record("epoch", epoch.to_string());
    tracing::info!("Event for {oprfKeyId} with epoch {epoch}");
    let oprf_public_key = contract.getOprfPublicKey(oprfKeyId).call().await?;
    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    let oprf_public_key = OprfPublicKey::new(oprf_public_key.try_into()?);
    let epoch = ShareEpoch::from(epoch);
    let dlog_share = secret_gen
        .finalize(oprf_key_id)
        .context("while finalizing secret-gen")?;
    secret_manager
        .store_dlog_share(oprf_key_id, oprf_public_key, epoch, dlog_share)
        .await
        .context("while storing dlog share")?;
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_4_FINISH,
            METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_RESHARE)
    .increment(1);
    Ok(())
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty, epoch=tracing::field::Empty))]
async fn handle_reshare_round1(
    party_id: PartyId,
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    secret_manager: &SecretManagerService,
    transaction_handler: &TransactionHandler,
) -> eyre::Result<()> {
    tracing::info!("Received ReshareRound1 event");
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_1_START,
        METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_RESHARE)
    .increment(1);
    let log = log
        .log_decode()
        .context("while decoding reshare round1 event")?;
    let OprfKeyRegistry::ReshareRound1 {
        oprfKeyId,
        threshold,
        epoch,
    } = log.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    handle_span.record("epoch", epoch.to_string());
    tracing::info!("Event for {oprfKeyId} with threshold {threshold} and generated epoch: {epoch}");

    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    let threshold = u16::try_from(threshold)?;
    let epoch = ShareEpoch::from(epoch);

    tracing::debug!("need to load latest share for reshare");
    // load old share needed for reshare
    let contribution = if let Some(latest_share) = secret_manager
        .get_previous_share(oprf_key_id, epoch)
        .await
        .context("while loading latest share for reshare")?
    {
        tracing::debug!("found share - we want to be producer");
        let SecretGenRound1Contribution {
            oprf_key_id: _,
            contribution,
        } = secret_gen.reshare_round1(oprf_key_id, threshold, latest_share);

        tracing::debug!("finished producer round1 - now reporting to chain..");
        Round1Contribution::from(contribution)
    } else {
        tracing::info!("we don't have the necessary share - we are a consumer");
        let contribution = secret_gen.consumer_round1(oprf_key_id, &mut rand::thread_rng());
        tracing::debug!("finished consumer round1 - now reporting to chain..");
        Round1Contribution::from(contribution)
    };
    let transaction_identifier =
        TransactionIdentifier::reshare(oprf_key_id, party_id, TransactionType::Round1, epoch);
    transaction_handler
        .attempt_transaction(transaction_identifier, || {
            contract.addRound1ReshareContribution(oprf_key_id.into_inner(), contribution.clone())
        })
        .await?;
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_1_FINISH,
            METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_RESHARE)
    .increment(1);

    Ok(())
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty, epoch=tracing::field::Empty))]
async fn handle_reshare_round3(
    party_id: PartyId,
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> eyre::Result<()> {
    tracing::info!("Received ReshareRound3 event");
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_3_START,
        METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_RESHARE)
    .increment(1);
    let log = log
        .log_decode()
        .context("while decoding reshare round3 event")?;
    let OprfKeyRegistry::ReshareRound3 {
        oprfKeyId,
        lagrange,
        epoch,
    } = log.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    handle_span.record("epoch", epoch.to_string());
    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    let epoch = ShareEpoch::from(epoch);
    tracing::debug!("parsing lagrange coefficients..");
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
    let transaction_identifier =
        TransactionIdentifier::reshare(oprf_key_id, party_id, TransactionType::Round3, epoch);
    handle_round3_inner(
        oprf_key_id,
        contract,
        secret_gen,
        Contributions::Shamir(lagrange),
        transaction_identifier,
        transaction_handler,
    )
    .await?;
    ::metrics::counter!(METRICS_ID_KEY_GEN_ROUND_3_FINISH,
        METRICS_ATTRID_PROTOCOL => METRICS_ATTRVAL_PROTOCOL_RESHARE)
    .increment(1);
    Ok(())
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty))]
async fn handle_delete(
    log: Log<LogData>,
    secret_gen: &mut DLogSecretGenService,
    secret_manager: &SecretManagerService,
) -> eyre::Result<()> {
    tracing::info!("Received Delete event");
    ::metrics::counter!(METRICS_ID_KEY_GEN_DELETION_START).increment(1);
    let key_delete = log
        .log_decode()
        .context("while decoding key deletion event")?;
    let OprfKeyRegistry::KeyDeletion { oprfKeyId } = key_delete.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    tracing::info!("got key deletion event for {oprf_key_id}");
    // we need to delete all the toxic waste associated with the rp id
    secret_gen.delete_oprf_key_material(oprf_key_id);
    secret_manager
        .remove_oprf_key_material(oprf_key_id)
        .await
        .context("while storing share to secret manager")?;
    ::metrics::counter!(METRICS_ID_KEY_GEN_DELETION_FINISH).increment(1);
    Ok(())
}

async fn handle_round3_inner(
    oprf_key_id: OprfKeyId,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    contributions: Contributions,
    transaction_identifier: TransactionIdentifier,
    transaction_handler: &TransactionHandler,
) -> eyre::Result<()> {
    tracing::info!("Event for {oprf_key_id}");
    tracing::info!("reading ciphers from chain..");
    let ciphers = contract
        .checkIsParticipantAndReturnRound2Ciphers(oprf_key_id.into_inner())
        .call()
        .await
        .context("while loading ciphers")?;
    tracing::debug!("got ciphers from chain {} - parsing..", ciphers.len());
    let ciphers = ciphers
        .into_iter()
        .map(SecretGenCiphertext::try_from)
        .collect::<eyre::Result<Vec<_>>>()?;
    tracing::debug!("get the public keys from the producers...");
    let pks = contract
        .loadPeerPublicKeysForConsumers(oprf_key_id.into_inner())
        .call()
        .await
        .context("while loading consumer pks")?;
    let pks = pks
        .into_iter()
        .map(EphemeralEncryptionPublicKey::try_from)
        .collect::<eyre::Result<Vec<_>>>()?;
    let res = secret_gen
        .round3(oprf_key_id, ciphers, contributions, pks)
        .context("while doing round3")?;
    tracing::debug!("finished round 3 - now reporting");
    transaction_handler
        .attempt_transaction(transaction_identifier, || {
            contract.addRound3Contribution(res.oprf_key_id.into_inner())
        })
        .await?;
    Ok(())
}
