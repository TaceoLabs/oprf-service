//! Alloy-based Key Generation Event Watcher
//!
//! This module provides [`key_event_watcher_task`], an task than can be spawned to monitor an on-chain OprfKeyRegistry contract for key generation events.
//!
//! The watcher subscribes to various key generation events and reports contributions back to the contract.

use std::collections::BTreeMap;

use crate::services::{
    secret_gen::{Contributions, DLogSecretGenService},
    secret_manager::SecretManagerService,
    transaction_handler::{TransactionHandler, TransactionType},
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
    crypto::{EphemeralEncryptionPublicKey, OprfKeyMaterial, OprfPublicKey, SecretGenCiphertext},
};
use tokio_util::sync::CancellationToken;
use tracing::instrument;

pub(crate) struct KeyEventWatcherTaskConfig {
    pub(crate) provider: DynProvider,
    pub(crate) contract_address: Address,
    pub(crate) secret_manager: SecretManagerService,
    pub(crate) dlog_secret_gen_service: DLogSecretGenService,
    pub(crate) start_block: Option<u64>,
    pub(crate) max_epoch_cache_size: usize,
    pub(crate) transaction_handler: TransactionHandler,
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
        provider,
        contract_address,
        secret_manager,
        mut dlog_secret_gen_service,
        start_block,
        max_epoch_cache_size,
        transaction_handler,
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
                log,
                &contract,
                &mut dlog_secret_gen_service,
                &secret_manager,
                max_epoch_cache_size,
                &transaction_handler,
            )
            .await
            .context("while handling past log")?;
        }
    };

    let mut stream = sub.into_stream();
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
        if let Some(block_number) = log.block_number {
            if block_number <= latest_block {
                tracing::info!(
                    "skipping event from block {block_number} - already handled up to {latest_block}"
                );
                continue;
            }
        }
        handle_log(
            log,
            &contract,
            &mut dlog_secret_gen_service,
            &secret_manager,
            max_epoch_cache_size,
            &transaction_handler,
        )
        .await
        .context("while handling log")?;
    }
    Ok(())
}

#[instrument(level = "info", skip_all)]
async fn handle_log(
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    secret_manager: &SecretManagerService,
    max_epoch_cache_size: usize,
    transaction_handler: &TransactionHandler,
) -> eyre::Result<()> {
    match log.topic0() {
        Some(&OprfKeyRegistry::SecretGenRound1::SIGNATURE_HASH) => {
            handle_keygen_round1(log, contract, secret_gen, transaction_handler)
                .await
                .context("while handling round1")?
        }
        Some(&OprfKeyRegistry::SecretGenRound2::SIGNATURE_HASH) => {
            handle_round2(log, contract, secret_gen, transaction_handler)
                .await
                .context("while handling round2")?
        }
        Some(&OprfKeyRegistry::SecretGenRound3::SIGNATURE_HASH) => {
            handle_keygen_round3(log, contract, secret_gen, transaction_handler)
                .await
                .context("while handling round3")?
        }
        Some(&OprfKeyRegistry::SecretGenFinalize::SIGNATURE_HASH) => handle_finalize(
            log,
            contract,
            secret_gen,
            secret_manager,
            max_epoch_cache_size,
        )
        .await
        .context("while handling finalize")?,
        Some(&OprfKeyRegistry::ReshareRound1::SIGNATURE_HASH) => handle_reshare_round1(
            log,
            contract,
            secret_gen,
            secret_manager,
            transaction_handler,
        )
        .await
        .context("while handling round1")?,
        Some(&OprfKeyRegistry::ReshareRound3::SIGNATURE_HASH) => {
            handle_reshare_round3(log, contract, secret_gen, transaction_handler)
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

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty))]
async fn handle_keygen_round1(
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> eyre::Result<()> {
    tracing::info!("Received KeyGenRound1 event");
    let log = log
        .log_decode()
        .context("while decoding key-gen round1 event")?;
    let OprfKeyRegistry::SecretGenRound1 {
        oprfKeyId,
        threshold,
    } = log.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    tracing::info!("Event for {oprfKeyId} with threshold {threshold}");

    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    let threshold = u16::try_from(threshold)?;
    let SecretGenRound1Contribution {
        oprf_key_id,
        contribution,
    } = secret_gen.key_gen_round1(oprf_key_id, threshold);
    tracing::debug!("finished round1 - now reporting to chain..");
    transaction_handler
        .attempt_transaction(oprf_key_id, TransactionType::Round1, || {
            contract
                .addRound1KeyGenContribution(oprf_key_id.into_inner(), contribution.clone().into())
        })
        .await?;
    Ok(())
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty))]
async fn handle_round2(
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> eyre::Result<()> {
    tracing::info!("Received SecretGenRound2 event");
    let round2 = log
        .log_decode()
        .context("while decoding secret-gen round2 event")?;
    let OprfKeyRegistry::SecretGenRound2 { oprfKeyId } = round2.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
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
        return Ok(());
    }
    tracing::debug!("got keys from chain - parsing..");
    // TODO handle error case better - we want to know which one send wrong key
    let nodes = nodes
        .into_iter()
        .map(EphemeralEncryptionPublicKey::try_from)
        .collect::<eyre::Result<Vec<_>>>()?;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    tracing::info!("Event for {oprfKeyId}");
    // block_in_place here because we do a lot CPU work
    let res = tokio::task::block_in_place(|| {
        secret_gen
            .producer_round2(oprf_key_id, nodes)
            .context("while doing round2")
    })?;
    tracing::debug!("finished round 2 - now reporting");
    let contribution = Round2Contribution::from(res.contribution);
    transaction_handler
        .attempt_transaction(oprf_key_id, TransactionType::Round2, || {
            contract.addRound2Contribution(res.oprf_key_id.into_inner(), contribution.clone())
        })
        .await?;
    Ok(())
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty))]
async fn handle_keygen_round3(
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> eyre::Result<()> {
    tracing::info!("Received SecretGenRound3 event");
    let round3 = log
        .log_decode()
        .context("while decoding secret-gen round3 event")?;
    let OprfKeyRegistry::SecretGenRound3 { oprfKeyId } = round3.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    handle_round3_inner(
        OprfKeyId::from(oprfKeyId),
        contract,
        secret_gen,
        Contributions::Full,
        transaction_handler,
    )
    .await
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty))]
async fn handle_finalize(
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    secret_manager: &SecretManagerService,
    max_epoch_cache_size: usize,
) -> eyre::Result<()> {
    tracing::info!("Received SecretGenFinalize event");
    let finalize = log
        .log_decode()
        .context("while decoding secret-gen finalize event")?;
    let OprfKeyRegistry::SecretGenFinalize { oprfKeyId, epoch } = finalize.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    tracing::info!("Event for {oprfKeyId} with epoch {epoch}");
    let oprf_public_key = contract.getOprfPublicKey(oprfKeyId).call().await?;
    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    let oprf_public_key = OprfPublicKey::new(oprf_public_key.try_into()?);
    let epoch = ShareEpoch::from(epoch);
    let dlog_share = secret_gen
        .finalize(oprf_key_id)
        .context("while finalizing secret-gen")?;
    if epoch.is_initial_epoch() {
        let oprf_key_material = OprfKeyMaterial::new(
            BTreeMap::from([(epoch, dlog_share)]),
            oprf_public_key,
            max_epoch_cache_size,
        );
        secret_manager
            .store_oprf_key_material(oprf_key_id, oprf_key_material)
            .await
            .context("while storing share to secret manager")
    } else {
        secret_manager
            .update_dlog_share(oprf_key_id, epoch, dlog_share)
            .await
            .context("while updating DLog share")
    }
}

async fn handle_reshare_round1(
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    secret_manager: &SecretManagerService,
    transaction_handler: &TransactionHandler,
) -> eyre::Result<()> {
    tracing::info!("Received ReshareRound1 event");
    let log = log
        .log_decode()
        .context("while decoding reshare round1 event")?;
    let OprfKeyRegistry::ReshareRound1 {
        oprfKeyId,
        threshold,
    } = log.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    tracing::info!("Event for {oprfKeyId} with threshold {threshold}");

    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    let threshold = u16::try_from(threshold)?;

    tracing::debug!("need to load latest share for reshare");
    // load old share needed for reshare
    let latest_share = secret_manager
        .get_latest_share(oprf_key_id)
        .await
        .context("while loading latest share for reshare")?;

    let SecretGenRound1Contribution {
        oprf_key_id,
        contribution,
    } = secret_gen.reshare_round1(oprf_key_id, threshold, latest_share);

    tracing::debug!("finished round1 - now reporting to chain..");
    let contribution = Round1Contribution::from(contribution);
    transaction_handler
        .attempt_transaction(oprf_key_id, TransactionType::Round1, || {
            contract.addRound1ReshareContribution(oprf_key_id.into_inner(), contribution.clone())
        })
        .await?;
    Ok(())
}

async fn handle_reshare_round3(
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    transaction_handler: &TransactionHandler,
) -> eyre::Result<()> {
    tracing::info!("Received ReshareRound3 event");
    let log = log
        .log_decode()
        .context("while decoding reshare round3 event")?;
    let OprfKeyRegistry::ReshareRound3 {
        oprfKeyId,
        lagrange,
    } = log.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
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
        OprfKeyId::from(oprfKeyId),
        contract,
        secret_gen,
        Contributions::Shamir(lagrange),
        transaction_handler,
    )
    .await
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty))]
async fn handle_delete(
    log: Log<LogData>,
    secret_gen: &mut DLogSecretGenService,
    secret_manager: &SecretManagerService,
) -> eyre::Result<()> {
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
        .context("while storing share to secret manager")
}

async fn handle_round3_inner(
    oprf_key_id: OprfKeyId,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    contributions: Contributions,
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
        .attempt_transaction(oprf_key_id, TransactionType::Round3, || {
            contract.addRound3Contribution(res.oprf_key_id.into_inner())
        })
        .await?;
    Ok(())
}
