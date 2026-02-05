use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use alloy::{
    consensus::constants::ETH_TO_WEI,
    contract::{CallBuilder, CallDecoder},
    eips::BlockNumberOrTag,
    network::{Network, ReceiptResponse},
    primitives::{
        Address, B256,
        utils::{ParseUnits, Unit},
    },
    providers::{DynProvider, PendingTransactionError, Provider},
};
use eyre::Context as _;
use futures::StreamExt as _;
use oprf_types::{OprfKeyId, ShareEpoch, chain::OprfKeyRegistry, crypto::PartyId};
use tokio::{sync::oneshot, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    metrics::{
        METRICS_ATTRID_WALLET_ADDRESS, METRICS_ID_BLOB_GAS_PRICE, METRICS_ID_GAS_PRICE,
        METRICS_ID_KEY_GEN_ROUND1_GAS, METRICS_ID_KEY_GEN_ROUND3_GAS,
        METRICS_ID_KEY_GEN_RPC_NULL_BUT_OK, METRICS_ID_KEY_GEN_RPC_RETRY,
        METRICS_ID_KEY_GEN_WALLET_BALANCE, METRICS_ID_RESHARE_ROUND1_GAS,
        METRICS_ID_RESHARE_ROUND3_GAS, METRICS_ID_ROUND2_GAS,
    },
    services::key_event_watcher::TransactionError,
};

/// Indicates the transaction type. We need this to distinguish between events.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum TransactionType {
    Round1 = 1,
    Round2 = 2,
    Round3 = 3,
}

impl TryFrom<u8> for TransactionType {
    type Error = eyre::Report;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Round1),
            2 => Ok(Self::Round2),
            3 => Ok(Self::Round3),
            x => eyre::bail!("invalid transaction type: {x}"),
        }
    }
}

impl From<TransactionType> for u8 {
    fn from(t: TransactionType) -> Self {
        t as u8
    }
}

/// The identifier of a transaction.
///
/// The contract will emit an event with this identifier so that we know whether this transaction was registered successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct TransactionIdentifier {
    oprf_key_id: OprfKeyId,
    party_id: PartyId,
    round: TransactionType,
    epoch: ShareEpoch,
}

impl TransactionIdentifier {
    /// Creates a new identifier for key-gen transactions (setting epoch to 0).
    pub(crate) fn keygen(
        oprf_key_id: OprfKeyId,
        party_id: PartyId,
        round: TransactionType,
    ) -> Self {
        Self {
            oprf_key_id,
            party_id,
            round,
            epoch: ShareEpoch::default(),
        }
    }

    /// Creates a new identifier for reshare transactions.
    pub(crate) fn reshare(
        oprf_key_id: OprfKeyId,
        party_id: PartyId,
        round: TransactionType,
        epoch: ShareEpoch,
    ) -> Self {
        Self {
            oprf_key_id,
            party_id,
            round,
            epoch,
        }
    }
}

impl TryFrom<OprfKeyRegistry::KeyGenConfirmation> for TransactionIdentifier {
    type Error = eyre::Report;
    fn try_from(value: OprfKeyRegistry::KeyGenConfirmation) -> eyre::Result<Self> {
        Ok(Self {
            oprf_key_id: value.oprfKeyId.into(),
            party_id: value.partyId.into(),
            round: value.round.try_into()?,
            epoch: value.epoch.into(),
        })
    }
}

/// A signal that fires when we get the confirmation of a dedicated transaction.
struct TransactionSignal(oneshot::Receiver<()>);

impl TransactionSignal {
    /// Wait for the confirmation for this transaction. Returns `true` iff the transaction confirmation was recorded, `false` if we did not record it in time.
    async fn confirmation(self) -> bool {
        self.0.await.is_ok()
    }
}

/// Service that handles transaction submitting, error handling and RPC failure.
///
/// On startup, spawns a task that listens for the `KeyGenConfirmation` logs with a topic-filter set to the party ID of this node. For every transaction, the implementation creates a `oneshot` channel for the a calling party and stores the sender half. If the task records a [`TransactionIdentifier`] that is currently in the store, it signals through that through the channel.
///
/// On every transaction, it will additionally spawn a dedicated `tokio::task`, that waits `max_wait_time` and then removes the transaction from the store, signaling a waiting task that we could not get the confirmation in time.
#[derive(Clone)]
pub(crate) struct TransactionHandler {
    max_wait_time: Duration,
    max_gas_per_transaction: u64,
    confirmations_for_transaction: u64,
    attempts: usize,
    store: Arc<Mutex<HashMap<TransactionIdentifier, oneshot::Sender<()>>>>,
    wallet_address: Address,
    provider: DynProvider,
}

/// The arguments to start the [`TransactionHandler`].
pub(crate) struct TransactionHandlerInitArgs {
    pub(crate) max_wait_time: Duration,
    pub(crate) max_gas_per_transaction: u64,
    pub(crate) confirmations_for_transaction: u64,
    pub(crate) attempts: usize,
    pub(crate) party_id: PartyId,
    pub(crate) contract_address: Address,
    pub(crate) provider: DynProvider,
    pub(crate) wallet_address: Address,
    pub(crate) start_signal: Arc<AtomicBool>,
    pub(crate) cancellation_token: CancellationToken,
}

impl TransactionHandler {
    /// Creates a new [`TransactionHandler`].
    ///
    /// Spawns a task that waits for the `KeyGenConfirmation` events emitted by the provided address. If the task encounters an error, will cancel via the cancellation token.
    pub(crate) async fn new(
        args: TransactionHandlerInitArgs,
    ) -> eyre::Result<(Self, JoinHandle<eyre::Result<()>>)> {
        let TransactionHandlerInitArgs {
            max_wait_time,
            max_gas_per_transaction,
            confirmations_for_transaction,
            attempts,
            party_id,
            contract_address,
            provider,
            wallet_address,
            start_signal,
            cancellation_token,
        } = args;
        let sub = OprfKeyRegistry::new(contract_address, provider.clone())
            .KeyGenConfirmation_filter()
            .topic2(vec![B256::left_padding_from(
                &party_id.into_inner().to_le_bytes(),
            )])
            .from_block(BlockNumberOrTag::Latest)
            .subscribe()
            .await?;

        let mut stream = sub.into_stream();
        let transaction_handler = Self {
            max_wait_time,
            max_gas_per_transaction,
            confirmations_for_transaction,
            attempts,
            store: Arc::new(Mutex::new(HashMap::new())),
            wallet_address,
            provider,
        };
        tracing::info!("transaction handler is ready");
        start_signal.store(true, Ordering::Relaxed);
        let handle = tokio::task::spawn({
            let transaction_handler = transaction_handler.clone();
            async move {
                let _drop_guard = cancellation_token.drop_guard_ref();
                loop {
                    let confirmation = tokio::select! {
                        log = stream.next() => {
                            let (confirmation,_) = log.ok_or_else(||eyre::eyre!("logs subscribe stream was closed"))?.context("while decoding log")?;
                            confirmation
                        }
                        _ = cancellation_token.cancelled() => {
                            break;
                        }
                    };
                    tracing::trace!("got transaction nonce confirmation: {confirmation:?}");
                    match TransactionIdentifier::try_from(confirmation) {
                        Ok(confirmation) => transaction_handler.signal_recorded_nonce(confirmation),
                        Err(err) => {
                            tracing::warn!("Could not parse transaction identifier: {err:?}")
                        }
                    }
                }
                eyre::Ok(())
            }
        });
        Ok((transaction_handler, handle))
    }
    /// Attempts to send a transaction with configured provider.
    ///
    /// We wait for the receipt we get from our RPC. If we successfully get the receipt we check its status. If everything was successful we return with an `Ok`. If we get a receipt signaling a failure we try to do the same call once more, but without doing a transaction to get the potential revert data. This should only act as debug information and not be taken at face value.
    ///
    /// Now, if the RPC responds with a null response (which occurs quite often with e.g., Alchemy) we wait for a dedicated event emitted by the smart-contract that was created by the transaction. Apparently, when getting this null response error, the transaction might still have been successful, therefore we can't rely on the response from the RPC. In most cases, we still get the ordinary receipt with a success, so this is a fail safe. If this runs into a timeout, we try to redo the transaction a configured amount of times.
    ///
    /// If we could not send the transaction at all, we return with an error.
    ///
    /// Takes an `Fn` that produces a `CallBuilder`. This can be done e.g., with
    /// ```rust,ignore
    /// transaction_handler
    ///     .attempt_transaction(oprf_key_id, TransactionType::Round1, || {
    ///         contract.addRound1KeyGenContribution(
    ///             oprf_key_id.into_inner(),
    ///             contribution.clone().into(),
    ///         )
    ///     })
    ///     .await?;
    /// ```
    /// This method will then attempt to send the transaction via the provided RPC.
    pub(crate) async fn attempt_transaction<P, D, N, F>(
        &self,
        transaction_identifier: TransactionIdentifier,
        transaction: F,
    ) -> Result<(), TransactionError>
    where
        P: Provider<N>,
        D: CallDecoder + Unpin,
        N: Network,
        F: Fn() -> CallBuilder<P, D, N>,
    {
        let mut attempt = 0;
        loop {
            tracing::debug!(
                "sending transaction: {transaction_identifier:?}. Attempt {}/{}",
                attempt + 1,
                self.attempts
            );
            // start the timer for this transaction
            let transaction_nonce = self.register_transaction(transaction_identifier);
            let transaction_result = transaction()
                .gas(self.max_gas_per_transaction)
                .send()
                .await
                .context("while broadcasting to network")?
                .with_required_confirmations(self.confirmations_for_transaction)
                .get_receipt()
                .await;
            if let Ok(balance) = self.provider.get_balance(self.wallet_address).await {
                tracing::debug!(
                    "current wallet balance: {} ETH",
                    alloy::primitives::utils::format_ether(balance)
                );
                ::metrics::gauge!(METRICS_ID_KEY_GEN_WALLET_BALANCE, METRICS_ATTRID_WALLET_ADDRESS => self.wallet_address.to_string())
                    .set(f64::from(balance) / ETH_TO_WEI as f64);
            } else {
                tracing::warn!("could not fetch current wallet balance");
            }
            match transaction_result {
                Ok(receipt) => {
                    return check_receipt(transaction_identifier, transaction, receipt).await;
                }
                Err(PendingTransactionError::TransportError(
                    alloy::transports::RpcError::NullResp,
                )) => {
                    tracing::debug!("got null response - trying to wait for confirmation event...");
                    if transaction_nonce.confirmation().await {
                        tracing::debug!(
                            "received confirmation! we can continue as our contribution is registered"
                        );
                        ::metrics::counter!(METRICS_ID_KEY_GEN_RPC_NULL_BUT_OK).increment(1);
                        return Ok(());
                    } else {
                        tracing::debug!("ran into timeout while waiting for nonce event...");
                        ::metrics::counter!(METRICS_ID_KEY_GEN_RPC_RETRY).increment(1);
                    }
                }
                Err(err) => {
                    return Err(TransactionError::Rpc(eyre::eyre!(err)));
                }
            }
            if attempt >= self.attempts {
                return Err(TransactionError::Rpc(eyre::eyre!(
                    "could not finish transaction within {} attempts",
                    self.attempts
                )));
            };
            attempt += 1;
        }
    }

    /// Tries to signal to a waiting task that we recorded the specified transaction confirmation. Does nothing if the transaction is not in store.
    fn signal_recorded_nonce(&self, confirmation: TransactionIdentifier) {
        // If not in store either nonce belongs to someone else or we ran into timeout
        if let Some(tx) = self
            .store
            .lock()
            .expect("Not poisoned")
            .remove(&confirmation)
        {
            tracing::trace!(
                "maybe someone waiting for confirmation from {}",
                confirmation.oprf_key_id
            );
            let _ = tx.send(());
        }
    }

    /// Creates a new [`TransactionSignal`].
    ///
    /// Additionally, spawns a task that drops signal from the store, signaling that we did not get the transaction confirmation in time.
    fn register_transaction(&self, identifier: TransactionIdentifier) -> TransactionSignal {
        let (tx, rx) = oneshot::channel();
        self.store
            .lock()
            .expect("Not poisoned")
            .insert(identifier, tx);
        tokio::task::spawn({
            let max_wait_time = self.max_wait_time;
            let store = self.clone();
            async move {
                tokio::time::sleep(max_wait_time).await;
                // we simply drop the sender without sending anything - if someone is still waiting then they will know that it didn't work. Otherwise this won't do anything.
                store
                    .store
                    .lock()
                    .expect("Not poisoned")
                    .remove(&identifier);
            }
        });
        TransactionSignal(rx)
    }
}

/// Helper function to get the revert data in case the transaction failed.
async fn check_receipt<P, D, N, F>(
    transaction_identifier: TransactionIdentifier,
    transaction: F,
    receipt: N::ReceiptResponse,
) -> Result<(), TransactionError>
where
    P: Provider<N>,
    D: CallDecoder + Unpin,
    N: Network,
    F: Fn() -> CallBuilder<P, D, N>,
{
    if receipt.status() {
        handle_success_receipt(transaction_identifier, receipt);
        Ok(())
    } else {
        tracing::debug!("could not send transaction - do a call to get revert data");
        transaction().call().await?;
        // if we are here the call afterwards succeeded - we don't really know why the receipt failed so just return the wrapped receipt
        Err(TransactionError::Rpc(eyre::eyre!(
            "cannot finish transaction for unknown reason: {receipt:?}"
        )))
    }
}

fn handle_success_receipt<R: ReceiptResponse>(
    transaction_identifier: TransactionIdentifier,
    receipt: R,
) {
    let epoch = transaction_identifier.epoch;
    let gas_used_gwei = ParseUnits::from(receipt.gas_used())
        .format_units(Unit::GWEI)
        .parse::<f64>()
        .expect("Is a float");
    let cost_eth = alloy::primitives::utils::format_ether(receipt.cost());
    let gas_price_eth = alloy::primitives::utils::format_ether(receipt.effective_gas_price());
    // we did it!
    tracing::debug!("gas used: {gas_used_gwei} GWEI");
    tracing::debug!("transaction cost: {cost_eth} ETH");
    tracing::debug!("transaction gas price: {gas_price_eth} ETH");
    if let Some(blob_price) = receipt.blob_gas_price() {
        let blob_price_eth = alloy::primitives::utils::format_ether(blob_price);
        tracing::debug!("transaction blob gas price: {blob_price_eth} ETH");
        metrics::histogram!(METRICS_ID_BLOB_GAS_PRICE)
            .record(blob_price_eth.parse::<f64>().expect("Is a float"))
    }
    tracing::debug!("successfully sent transaction");
    metrics::histogram!(METRICS_ID_GAS_PRICE)
        .record(gas_price_eth.parse::<f64>().expect("Is a float"));
    match transaction_identifier.round {
        TransactionType::Round1 if epoch.is_initial_epoch() => {
            metrics::histogram!(METRICS_ID_KEY_GEN_ROUND1_GAS).record(gas_used_gwei)
        }
        TransactionType::Round1 => {
            metrics::histogram!(METRICS_ID_RESHARE_ROUND1_GAS).record(gas_used_gwei)
        }
        TransactionType::Round2 => metrics::histogram!(METRICS_ID_ROUND2_GAS).record(gas_used_gwei),
        TransactionType::Round3 if epoch.is_initial_epoch() => {
            metrics::histogram!(METRICS_ID_KEY_GEN_ROUND3_GAS).record(gas_used_gwei)
        }
        TransactionType::Round3 => {
            metrics::histogram!(METRICS_ID_RESHARE_ROUND3_GAS).record(gas_used_gwei)
        }
    }
}
