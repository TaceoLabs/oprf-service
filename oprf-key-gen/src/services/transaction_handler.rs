use std::{f64, time::Duration};

use alloy::{
    contract::{CallBuilder, CallDecoder, Error as ContractError},
    eips::BlockId,
    network::ReceiptResponse,
    primitives::{Address, TxHash},
    providers::{DynProvider, PendingTransactionError, Provider, WatchTxError},
    rpc::types::TransactionReceipt,
    transports::{RpcError, TransportError},
};
use backon::{BackoffBuilder as _, ConstantBackoff, ConstantBuilder, Retryable as _};
use nodes_common::web3;
use oprf_types::{
    OprfKeyId,
    chain::{
        OprfKeyGen::Round1Contribution, OprfKeyGen::Round2Contribution,
        OprfKeyRegistry::OprfKeyRegistryInstance,
    },
};
use tracing::instrument;

use crate::{metrics, services::key_event_watcher::KeyRegistryEventError};

/// Service that handles transaction submission and receipt confirmation.
///
/// Simulates each call first (`eth_call` pre-flight via [`submit`](TransactionHandler::submit),
/// pinned to the block of the event being reacted to), then broadcasts the transaction and polls
/// for receipts, retrying on `NullResp` responses up to `max_tries_fetching_receipt` times.  On
/// receipt, [`ReceiptResponse::ensure_success`] is called to surface reverts.  Gas price and
/// wallet balance are recorded as metrics after every confirmed transaction.
#[derive(Clone)]
pub(crate) struct TransactionHandler {
    max_wait_time_watch_transaction: Duration,
    confirmations_for_transaction: u64,
    sleep_between_get_receipt: Duration,
    max_tries_fetching_receipt: usize,
    sleep_between_simulation: Duration,
    max_tries_simulation: usize,
    max_gas_per_transaction: u64,
    rpc_provider: web3::HttpRpcProvider,
    wallet_address: Address,
    contract: OprfKeyRegistryInstance<DynProvider>,
}

/// Construction arguments for [`TransactionHandler`].
pub(crate) struct TransactionHandlerArgs {
    /// Maximum time to wait for enough block confirmations before treating the transaction as
    /// timed out.
    pub(crate) max_wait_time_watch_transaction: Duration,
    /// Number of block confirmations required before a receipt is considered final.
    pub(crate) confirmations_for_transaction: u64,
    /// Delay between each manual `eth_getTransactionReceipt` retry after an initial
    /// `NullResp`.
    pub(crate) sleep_between_get_receipt: Duration,
    /// Maximum number of `eth_getTransactionReceipt` retries when receiving `NullResp`.
    pub(crate) max_tries_fetching_receipt: usize,
    /// Gas limit applied to every call and send, in gas units.
    pub(crate) max_gas_per_transaction: u64,
    /// HTTP provider used for transaction submission, balance queries, and receipt polling.
    pub(crate) rpc_provider: web3::HttpRpcProvider,
    /// Wallet address used to query the on-chain balance after each confirmed transaction.
    pub(crate) wallet_address: Address,
    /// Address of the `OprfKeyRegistry` contract.
    pub(crate) contract_address: Address,
    /// Delay between retries of a pre-flight simulation the RPC could not serve yet.
    pub(crate) sleep_between_simulation: Duration,
    /// Maximum number of pre-flight simulation retries while the RPC lags behind the event.
    pub(crate) max_tries_simulation: usize,
}

impl From<TransactionHandlerArgs> for TransactionHandler {
    fn from(value: TransactionHandlerArgs) -> Self {
        let TransactionHandlerArgs {
            max_wait_time_watch_transaction,
            confirmations_for_transaction,
            sleep_between_get_receipt,
            max_tries_fetching_receipt,
            max_gas_per_transaction,
            rpc_provider,
            wallet_address,
            contract_address,
            sleep_between_simulation,
            max_tries_simulation,
        } = value;
        Self {
            max_wait_time_watch_transaction,
            confirmations_for_transaction,
            sleep_between_get_receipt,
            max_tries_fetching_receipt,
            sleep_between_simulation,
            max_tries_simulation,
            max_gas_per_transaction,
            wallet_address,
            contract: OprfKeyRegistryInstance::new(contract_address, rpc_provider.inner()),
            rpc_provider,
        }
    }
}

impl TransactionHandler {
    /// Construct a [`TransactionHandler`] from its arguments.
    pub(crate) fn new(args: TransactionHandlerArgs) -> Self {
        Self::from(args)
    }

    fn backoff_strategy(&self) -> ConstantBackoff {
        ConstantBuilder::new()
            .with_delay(self.sleep_between_get_receipt)
            .with_max_times(self.max_tries_fetching_receipt)
            .build()
    }

    fn simulation_backoff(&self) -> ConstantBackoff {
        ConstantBuilder::new()
            .with_delay(self.sleep_between_simulation)
            .with_max_times(self.max_tries_simulation)
            .build()
    }

    /// Runs `call` against the state at `block`, retrying while the RPC cannot serve that block.
    ///
    /// Events arrive over the WebSocket provider while calls go out over the load-balanced HTTP
    /// pool, so a call reacting to an event can be served by an endpoint that has not seen the
    /// event's block and answer from the state before it - reporting e.g. `WrongRound` for a
    /// round we have already moved past. Pinning to `block` makes that impossible: such an
    /// endpoint cannot answer at all, it can only fail. So a failure carrying revert data is
    /// authoritative, and any other failure means the RPC lags behind and we retry. Checking for
    /// revert data instead of the error message keeps this independent of how each node phrases
    /// "unknown block".
    ///
    /// Retries are bounded. Once exhausted the error propagates and aborts the watcher without
    /// advancing the chain cursor, so the event is replayed after the restart.
    pub(crate) async fn call_pinned<P, D>(
        &self,
        call: CallBuilder<P, D>,
        block: BlockId,
    ) -> Result<D::CallOutput, ContractError>
    where
        P: Provider,
        D: CallDecoder,
    {
        let call = call.block(block);
        (|| async { call.call().await })
            .retry(self.simulation_backoff())
            .sleep(tokio::time::sleep)
            // We retry on any error that does not carry revert data, because that means the RPC is behind and cannot serve the block yet. 
            // If it does carry revert data, we do not retry because that is an authoritative answer from the chain.
            .when(|err: &ContractError| err.as_revert_data().is_none())
            .notify(|err, duration| {
                tracing::warn!(
                    "eth_call at {block:?} failed without revert data ({err}) - RPC likely behind, retrying in {duration:?}"
                );
            })
            .await
    }

    /// Pre-flight `eth_call`, pinned to the block of the event this transaction responds to.
    ///
    /// See [`call_pinned`](Self::call_pinned) for why the pin makes a revert here trustworthy.
    async fn simulate_transaction<D>(
        &self,
        transaction: CallBuilder<&DynProvider, D>,
        block: BlockId,
    ) -> Result<(), KeyRegistryEventError>
    where
        D: CallDecoder + Unpin,
    {
        tracing::trace!("simulating transaction at {block:?} before submitting");
        self.call_pinned(transaction.gas(self.max_gas_per_transaction), block)
            .await?;
        Ok(())
    }

    async fn send_transaction<D>(
        &self,
        transaction: CallBuilder<&DynProvider, D>,
    ) -> Result<TransactionReceipt, KeyRegistryEventError>
    where
        D: CallDecoder + Unpin,
    {
        tracing::trace!("sending transaction");
        let pending_transaction = transaction
            .gas(self.max_gas_per_transaction)
            .send()
            .await?
            .with_required_confirmations(self.confirmations_for_transaction)
            .with_timeout(Some(self.max_wait_time_watch_transaction));
        let tx_hash = pending_transaction.tx_hash().to_owned();
        let get_receipt_result = pending_transaction.get_receipt().await;
        match get_receipt_result {
            Ok(receipt) => Ok(receipt),
            Err(
                err @ (PendingTransactionError::TransportError(RpcError::NullResp)
                | PendingTransactionError::TxWatcher(WatchTxError::Timeout)),
            ) => {
                tracing::warn!(%err, "initial get_receipt failed - starting backoff");
                let receipt = (|| async {
                    self.rpc_provider
                        .get_transaction_receipt(tx_hash)
                        .await?
                        .ok_or(TransportError::NullResp)
                })
                .retry(self.backoff_strategy())
                .sleep(tokio::time::sleep)
                .when(|e| matches!(e, TransportError::NullResp))
                .notify(|_e, duration| {
                    tracing::warn!(
                        "Retrying eth_getTransactionReceipt in {duration:?} due to NullResp"
                    );
                })
                .await?;
                tracing::info!("successfully fetched receipt after initial fail");
                Ok(receipt)
            }
            Err(err) => Err(KeyRegistryEventError::from(err)),
        }
    }

    async fn record_metrics(&self, receipt: &TransactionReceipt) {
        tracing::trace!(
            "transaction with hash: {} confirmed",
            receipt.transaction_hash()
        );

        if let Ok(balance) = self.rpc_provider.get_balance(self.wallet_address).await {
            let balance_eth = alloy::primitives::utils::format_ether(balance);
            tracing::trace!("current wallet balance: {balance_eth} ETH",);
            metrics::wallet::set_wallet_balance(&balance_eth);
        } else {
            tracing::warn!("could not fetch current wallet balance");
        }
        let gas_used = receipt
            .gas_used()
            .to_string()
            .parse::<f64>()
            .unwrap_or(f64::NAN);
        let cost_eth = alloy::primitives::utils::format_ether(receipt.cost());
        // we do this to_string -> parse hop to have easy way to call to NAN if too large
        let gas_price_eth = alloy::primitives::utils::format_ether(receipt.effective_gas_price());
        tracing::trace!(
            "gas used: {gas_used}; transaction cost: {cost_eth} ETH; transaction gas price: {gas_price_eth} ETH"
        );
        metrics::wallet::set_gas_price_from_wei(receipt.effective_gas_price());
    }

    /// Full transaction lifecycle: simulate → send → confirm → ensure success → record metrics.
    ///
    /// Runs a pre-flight `eth_call` via [`simulate_transaction`](Self::simulate_transaction),
    /// pinned to `block` — the block of the event we are responding to — to surface reverts
    /// before spending gas, then broadcasts via
    /// [`send_transaction`](Self::send_transaction), calls
    /// [`ReceiptResponse::ensure_success`] to assert the receipt status, and
    /// emits gas/balance metrics via [`record_metrics`](Self::record_metrics).
    ///
    /// Returns the `TxHash` of the confirmed transaction.
    #[instrument(level = "info", skip_all)]
    async fn submit<D>(
        &self,
        transaction: CallBuilder<&DynProvider, D>,
        block: BlockId,
    ) -> Result<TxHash, KeyRegistryEventError>
    where
        D: CallDecoder + Unpin + Clone,
    {
        // first we simulate the transaction
        self.simulate_transaction(transaction.clone(), block)
            .await?;
        let receipt = self.send_transaction(transaction).await?;
        self.record_metrics(&receipt).await;
        receipt.ensure_success()?;
        Ok(receipt.transaction_hash)
    }

    /// Submits a round-1 key-gen contribution to `OprfKeyRegistry::addRound1KeyGenContribution`.
    ///
    /// Returns the `TxHash` of the confirmed transaction.
    ///
    /// # Errors
    ///
    /// Returns [`KeyRegistryEventError`] on revert, RPC failure, or receipt timeout.
    pub(crate) async fn add_round1_keygen_contribution(
        &self,
        oprf_key_id: OprfKeyId,
        contribution: Round1Contribution,
        block: BlockId,
    ) -> Result<TxHash, KeyRegistryEventError> {
        let transaction = self
            .contract
            .addRound1KeyGenContribution(oprf_key_id.into_inner(), contribution);
        self.submit(transaction, block).await
    }

    /// Submits a round-1 reshare contribution to `OprfKeyRegistry::addRound1ReshareContribution`.
    ///
    /// Returns the `TxHash` of the confirmed transaction.
    ///
    /// # Errors
    ///
    /// Returns [`KeyRegistryEventError`] on revert, RPC failure, or receipt timeout.
    pub(crate) async fn add_round1_reshare_contribution(
        &self,
        oprf_key_id: OprfKeyId,
        contribution: Round1Contribution,
        block: BlockId,
    ) -> Result<TxHash, KeyRegistryEventError> {
        let transaction = self
            .contract
            .addRound1ReshareContribution(oprf_key_id.into_inner(), contribution);
        self.submit(transaction, block).await
    }

    /// Submits a round-2 contribution to `OprfKeyRegistry::addRound2Contribution`.
    ///
    /// Returns the `TxHash` of the confirmed transaction.
    ///
    /// # Errors
    ///
    /// Returns [`KeyRegistryEventError`] on revert, RPC failure, or receipt timeout.
    pub(crate) async fn add_round2_contribution(
        &self,
        oprf_key_id: OprfKeyId,
        contribution: Round2Contribution,
        block: BlockId,
    ) -> Result<TxHash, KeyRegistryEventError> {
        let transaction = self
            .contract
            .addRound2Contribution(oprf_key_id.into_inner(), contribution);
        self.submit(transaction, block).await
    }

    /// Submits a round-3 contribution to `OprfKeyRegistry::addRound3Contribution`.
    ///
    /// Returns the `TxHash` of the confirmed transaction.
    ///
    /// # Errors
    ///
    /// Returns [`KeyRegistryEventError`] on revert, RPC failure, or receipt timeout.
    pub(crate) async fn add_round3_contribution(
        &self,
        oprf_key_id: OprfKeyId,
        block: BlockId,
    ) -> Result<TxHash, KeyRegistryEventError> {
        let transaction = self
            .contract
            .addRound3Contribution(oprf_key_id.into_inner());
        self.submit(transaction, block).await
    }
}
