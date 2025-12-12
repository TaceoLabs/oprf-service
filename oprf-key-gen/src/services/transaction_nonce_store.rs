use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy::{
    contract::{CallBuilder, CallDecoder},
    eips::BlockNumberOrTag,
    network::{Network, ReceiptResponse as _},
    primitives::{Address, U256},
    providers::{DynProvider, PendingTransactionError, Provider},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use ark_ff::UniformRand;
use eyre::Context as _;
use futures::StreamExt as _;
use oprf_types::chain::OprfKeyRegistry::{self, OprfKeyRegistryErrors};
use rand::{CryptoRng, Rng};
use tokio::{sync::oneshot, task::JoinHandle};
use tokio_util::sync::CancellationToken;

/// A nonce that
struct TransactionNonce {
    nonce: U256,
    chan: oneshot::Receiver<()>,
}

impl TransactionNonce {
    /// Wait for the confirmation for this nonce. Returns `true` iff the nonce was recorded, `false` if we did not record it in time.
    async fn confirmation(self) -> bool {
        self.chan.await.is_ok()
    }
}

/// The store of the currently registered nonces.
///
/// On startup, spawns a task that listens for the `TransactionNonce` logs. The implementation will receive all nonce events, also from the other nodes, but will just ignore them. If the task records a nonce that is currently in the store it send an `Ok` value to the waiting channel.
///
/// On every transaction, it will additionally spawn a dedicated `tokio::task`, that waits `max_wait_time` and then removes the nonce from the store, signaling a waiting task that we could not get the confirmation in time.
#[derive(Clone)]
pub(crate) struct TransactionNonceStore {
    max_wait_time: Duration,
    store: Arc<Mutex<HashMap<U256, oneshot::Sender<()>>>>,
}

impl TransactionNonceStore {
    /// Creates a new [`TransactionNonceStore`].
    ///
    /// Spawns a task that waits for the `TransactionNonce` events emitted by the provided address. If the task encounters an error, will cancel via the cancellation token.
    /// * `max_wait_time` max wait time for a confirmation event
    /// * `contract_address` the contract address that emits the events
    /// * `provider` the provider for subscribing
    /// * `cancellation_token` token to stop the subscribe task and signaling if the subscribe task encountered an error
    pub(crate) async fn new(
        max_wait_time: Duration,
        contract_address: Address,
        provider: DynProvider,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<(Self, JoinHandle<eyre::Result<()>>)> {
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Latest)
            .event_signature(OprfKeyRegistry::TransactionNonce::SIGNATURE_HASH);

        let sub = provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();
        let nonce_store = Self {
            max_wait_time,
            store: Arc::new(Mutex::new(HashMap::new())),
        };
        let handle = tokio::task::spawn({
            let nonce_store = nonce_store.clone();
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
                    let OprfKeyRegistry::TransactionNonce { nonce } = log.inner.data;
                    tracing::trace!("got transaction nonce confirmation: {nonce:?}");
                    nonce_store.signal_recorded_nonce(nonce);
                }

                eyre::Ok(())
            }
        });
        Ok((nonce_store, handle))
    }

    /// Attempts to send a transaction with configured provider.
    ///
    /// We wait for the receipt we get from our RPC. If we successfully get the receipt we check its status. If everything was successful we return with an `Ok`. If we get a receipt signaling a failure we try to do the same call once more, but without doing a transaction to get the potential revert data. This should only act as debug information and not be taken at face value.
    ///
    /// Now, if the RPC responds with a null response (which occurs quite often with e.g., Alchemy) we wait for a dedicated event emitted by the smart-contract along a nonce that was sent by the transaction. Apparently, when getting this null response error, the transaction might still have been successful, therefore we can't rely on the response from the RPC. In most cases, we still get the ordinary receipt with a success, so this is a fail safe.
    ///
    /// If we could not send the transaction at all, we return with an error.
    ///
    /// Takes an `Fn` that produces a `CallBuilder`. This can be done e.g., with
    /// ```rust,ignore
    /// transaction_nonce_store
    ///     .attempt_transaction(|nonce| {
    ///         contract.addRound1KeyGenContribution(
    ///             nonce,
    ///             oprf_key_id.into_inner(),
    ///             contribution.clone().into(),
    ///         )
    ///     })
    ///     .await?;
    /// ```
    /// This method will then attempt to send the transaction via the provided RPC. This method will create a nonce and inject it at callsite to call the contributions. Callsite MUST use this nonce otherwise we can't guarantee that anything at all works.
    pub(crate) async fn attempt_transaction<P, D, N, F>(&self, transaction: F) -> eyre::Result<()>
    where
        P: Provider<N>,
        D: CallDecoder + Unpin,
        N: Network,
        F: Fn(U256) -> CallBuilder<P, D, N>,
    {
        // create a new nonce
        let transaction_nonce = self.register_nonce(&mut rand::thread_rng());
        let transaction_result = transaction(transaction_nonce.nonce)
            .gas(10000000) // FIXME this is only for dummy smart contract
            .send()
            .await
            .context("while broadcasting to network")?
            .get_receipt()
            .await;
        match transaction_result {
            Ok(receipt) => check_receipt(transaction_nonce, transaction, receipt).await,
            Err(PendingTransactionError::TransportError(alloy::transports::RpcError::NullResp)) => {
                tracing::debug!("got null response - trying to wait for nonce event...");
                if transaction_nonce.confirmation().await {
                    tracing::debug!(
                        "received nonce event! we can continue as our contribution is registered"
                    );
                    Ok(())
                } else {
                    tracing::debug!("ran into timeout while waiting for nonce event...");
                    eyre::bail!(
                        "ran into timeout while waiting for nonce event after null response"
                    );
                }
            }
            Err(err) => eyre::bail!(err),
        }
    }

    /// Tries to signal to a waiting task that we recorded the specified nonce. Does nothing if the nonce is not in store.
    fn signal_recorded_nonce(&self, nonce: U256) {
        // If not in store either nonce belongs to someone else or we ran into timeout
        if let Some(tx) = self.store.lock().expect("Not poisoned").remove(&nonce) {
            tracing::trace!("maybe someone waiting for {nonce}");
            let _ = tx.send(());
        }
    }

    /// Creates a new [`TransactionNonce`].
    ///
    /// Additionally, spawns a task that drops the nonce from the store, signaling that we did not get the transaction in time.
    fn register_nonce<R: Rng + CryptoRng>(&self, r: &mut R) -> TransactionNonce {
        let nonce = U256::rand(r);
        let (tx, rx) = oneshot::channel();
        // we don't check if already there because with a good rng this chance is negligible
        self.store.lock().expect("Not poisoned").insert(nonce, tx);
        tokio::task::spawn({
            let max_wait_time = self.max_wait_time;
            let store = self.clone();
            async move {
                tokio::time::sleep(max_wait_time).await;
                // we simply drop the sender without sending anything - if someone is still waiting then they will know that it didn't work. Otherwise this won't do anything.
                store.store.lock().expect("Not poisoned").remove(&nonce);
            }
        });
        TransactionNonce { nonce, chan: rx }
    }
}

/// Helper function to get the revert data in case the transaction failed.
async fn check_receipt<P, D, N, F>(
    transaction_nonce: TransactionNonce,
    transaction: F,
    receipt: N::ReceiptResponse,
) -> eyre::Result<()>
where
    P: Provider<N>,
    D: CallDecoder + Unpin,
    N: Network,
    F: Fn(U256) -> CallBuilder<P, D, N>,
{
    if receipt.status() {
        // we did it!
        tracing::debug!("successfully sent transaction");
        Ok(())
    } else {
        tracing::debug!("could not send transaction - do a call to get revert data");
        match transaction(transaction_nonce.nonce).call().await {
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
