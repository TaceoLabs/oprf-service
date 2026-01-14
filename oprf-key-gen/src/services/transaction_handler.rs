use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy::{
    contract::{CallBuilder, CallDecoder},
    eips::BlockNumberOrTag,
    network::{Network, ReceiptResponse as _},
    primitives::Address,
    providers::{DynProvider, PendingTransactionError, Provider},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use eyre::Context as _;
use futures::StreamExt as _;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    chain::OprfKeyRegistry::{self, OprfKeyRegistryErrors},
    crypto::PartyId,
};
use tokio::{sync::oneshot, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::metrics::{METRICS_ID_KEY_GEN_RPC_NULL_BUT_OK, METRICS_ID_KEY_GEN_RPC_RETRY};

/// Indicates the transaction type. We need this to distinguish between events.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum TransactionType {
    Round1 = 1,
    Round2 = 2,
    Round3 = 3,
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
    round: u8,
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
            round: round.into(),
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
            round: round.into(),
            epoch,
        }
    }
}

impl From<OprfKeyRegistry::KeyGenConfirmation> for TransactionIdentifier {
    fn from(value: OprfKeyRegistry::KeyGenConfirmation) -> Self {
        Self {
            oprf_key_id: value.oprfKeyId.into(),
            party_id: value.partyId.into(),
            round: value.round,
            epoch: value.epoch.into(),
        }
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
/// On startup, spawns a task that listens for the `KeyGenConfirmation` logs. The implementation will receive all confirmation events, also from the other nodes and from clones of the same instance (redundant nodes from same party). The events from other parties are simply ignored, whereas the events from the cloned instances will be recorded. These events are distinguished by a nonce that every instance sends with their transaction. The calling node will know whether a clone's contribution was registered or their own.
///
/// If the task records a [`TransactionIdentifier`] that is currently in the store and has the same nonce embedded it sends an `TransactionResult::Success` value to the waiting channel. If the nonce doesn't match, it sends `TransactionResult::NotByUs`.
///
/// On every transaction, it will additionally spawn a dedicated `tokio::task`, that waits `max_wait_time` and then removes the transaction from the store, signaling a waiting task that we could not get the confirmation in time.
#[derive(Clone)]
pub(crate) struct TransactionHandler {
    max_wait_time: Duration,
    attempts: usize,
    party_id: PartyId,
    store: Arc<Mutex<HashMap<TransactionIdentifier, oneshot::Sender<()>>>>,
}

impl TransactionHandler {
    /// Creates a new [`TransactionHandler`].
    ///
    /// Spawns a task that waits for the `KeyGenConfirmation` events emitted by the provided address. If the task encounters an error, will cancel via the cancellation token.
    /// * `max_wait_time` max wait time for a confirmation event
    /// * `attempts` max attempts we try to redo the transaction if we get a null response
    /// * `party_id` the party id of this node
    /// * `contract_address` the contract address that emits the events
    /// * `provider` the provider for subscribing
    /// * `cancellation_token` token to stop the subscribe task and signaling if the subscribe task encountered an error
    pub(crate) async fn new(
        max_wait_time: Duration,
        attempts: usize,
        party_id: PartyId,
        contract_address: Address,
        provider: DynProvider,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<(Self, JoinHandle<eyre::Result<()>>)> {
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Latest)
            .event_signature(OprfKeyRegistry::KeyGenConfirmation::SIGNATURE_HASH);

        let sub = provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();
        let transaction_handler = Self {
            max_wait_time,
            attempts,
            party_id,
            store: Arc::new(Mutex::new(HashMap::new())),
        };
        let handle = tokio::task::spawn({
            let transaction_handler = transaction_handler.clone();
            async move {
                let _drop_guard = cancellation_token.drop_guard_ref();
                loop {
                    let log = tokio::select! {
                        log = stream.next() => {
                            log.ok_or_else(||eyre::eyre!("logs subscribe stream was closed"))?
                        }
                        _ = cancellation_token.cancelled() => {
                            break;
                        }
                    };
                    let log = log
                        .log_decode()
                        .context("while decoding transaction-nonce event")?;
                    let confirmation: OprfKeyRegistry::KeyGenConfirmation = log.inner.data;
                    tracing::trace!("got transaction nonce confirmation: {confirmation:?}");
                    transaction_handler.signal_recorded_nonce(confirmation.into());
                }
                eyre::Ok(())
            }
        });
        Ok((transaction_handler, handle))
    }
    /// Attempts to send a transaction using the configured provider.
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
    ///
    /// ## Normal flow
    /// 1. Send the transaction and wait for the transaction receipt from the RPC.
    /// 2. If a receipt is returned:
    ///    - If the receipt signals success, return `Ok`.
    ///    - If the receipt signals failure, continue with failure handling.
    ///
    /// ## Failure handling
    /// If the receipt indicates a failure, we wait for the `KeyGenConfirmation` event:
    /// - Using the embedded nonce, we determine whether this node’s confirmation
    ///   was still recorded, or whether the event originated from a redundant clone.
    /// - If the confirmation shows that the transaction was effectively recorded,
    ///   we treat the operation as successful.
    ///
    /// If this check fails, we retry the same call once more *without* sending a
    /// transaction, in order to retrieve potential revert data. This result is
    /// intended for debugging purposes only and must not be taken at face value.
    ///
    /// ## RPC null-response handling
    /// In some cases (e.g., with Alchemy), the RPC may return a null response instead
    /// of a receipt. Even in this case, the transaction may still have been executed
    /// successfully.
    /// - When this happens, we wait for the `KeyGenConfirmation` event emitted by the smart
    ///   contract to confirm whether the transaction was processed.
    /// - In most cases, a normal receipt with a success status is still received,
    ///   so this serves purely as a fail-safe mechanism.
    ///
    /// ## Retries
    /// If waiting for the confirmation event times out, we retry sending the
    /// transaction up to a configured number of attempts.
    pub(crate) async fn attempt_transaction<P, D, N, F>(
        &self,
        transaction_identifier: TransactionIdentifier,
        transaction: F,
    ) -> eyre::Result<()>
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
                .gas(10000000) // FIXME this is only for dummy smart contract
                .send()
                .await
                .context("while broadcasting to network")?
                .get_receipt()
                .await;
            match transaction_result {
                Ok(receipt) => return check_receipt(transaction, receipt).await,
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
                Err(err) => eyre::bail!(err),
            }
            if attempt >= self.attempts {
                eyre::bail!("could not finish transaction with configured attempts");
            }
            attempt += 1;
        }
    }

    /// Tries to signal to a waiting task that we recorded the specified transaction confirmation. Does nothing if the transaction is not in store.
    fn signal_recorded_nonce(&self, confirmation: TransactionIdentifier) {
        // If not in store either nonce belongs to someone else or we ran into timeout
        if confirmation.party_id == self.party_id
            && let Some(tx) = self
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
async fn check_receipt<P, D, N, F>(transaction: F, receipt: N::ReceiptResponse) -> eyre::Result<()>
where
    P: Provider<N>,
    D: CallDecoder + Unpin,
    N: Network,
    F: Fn() -> CallBuilder<P, D, N>,
{
    if receipt.status() {
        // we did it!
        tracing::debug!("successfully sent transaction");
        Ok(())
    } else {
        tracing::debug!("could not send transaction - do a call to get revert data");
        match transaction().call().await {
            Ok(_) => {
                eyre::bail!("cannot finish transaction for unknown reason: {receipt:?}");
            }
            Err(err) => {
                if let Some(error) = err.as_decoded_interface_error::<OprfKeyRegistryErrors>() {
                    tracing::debug!("call reverted: {error:?}");
                    eyre::bail!(
                        "transaction failed - call afterwards reverted with error {error:?}, but take with a grain of salt"
                    );
                } else {
                    eyre::bail!(
                        "cannot finish transaction and call afterwards failed as well: {err:?}"
                    );
                }
            }
        }
    }
}
