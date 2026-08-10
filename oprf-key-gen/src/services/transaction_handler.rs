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
/// Broadcasts each transaction and polls for its receipt, retrying on `NullResp` responses up to
/// `max_tries_fetching_receipt` times. If the receipt reports failure, an `eth_call` pinned to the
/// receipt's block hash probes the post-block state for a decodable revert. Gas price and wallet
/// balance are recorded as metrics after every confirmed transaction.
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
    /// Delay between retries of a pinned call the RPC could not serve.
    pub(crate) sleep_between_simulation: Duration,
    /// Maximum number of retries for a pinned call that fails without revert data.
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

    fn pinned_call_backoff(&self) -> ConstantBackoff {
        ConstantBuilder::new()
            .with_delay(self.sleep_between_simulation)
            .with_max_times(self.max_tries_simulation)
            .build()
    }

    /// Runs `call` against the state at `block`, retrying while the RPC cannot serve that block.
    ///
    /// Events arrive over the WebSocket provider while calls go out over the load-balanced HTTP
    /// pool, so an HTTP endpoint may not yet know the relevant block. Pinning prevents it from
    /// silently answering from different state. A failure carrying revert data is authoritative;
    /// failures without revert data are retried because they may indicate a lagging endpoint.
    /// Other transient or permanent errors without revert data are retried as well and may still
    /// exhaust the configured retry limit.
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
            .retry(self.pinned_call_backoff())
            .sleep(tokio::time::sleep)
            // Revert data is an authoritative chain response. Errors without it may be caused by
            // a lagging RPC (or another failure), so retry them within the configured bound.
            .when(|err: &ContractError| err.as_revert_data().is_none())
            .notify(|err, duration| {
                tracing::warn!(
                    "eth_call at {block:?} failed without revert data ({err}) - RPC may be behind, retrying in {duration:?}"
                );
            })
            .await
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

    /// Full transaction lifecycle: send → confirm → record metrics → optional recovery probe.
    ///
    /// Broadcasts via [`send_transaction`](Self::send_transaction), then checks the confirmed
    /// receipt and emits gas/balance metrics. A successful receipt returns immediately. For a
    /// failed receipt, an `eth_call` pinned by the receipt's block hash probes the post-block
    /// state. A decoded revert is propagated through the normal soft/hard error policy; if the
    /// probe succeeds, the original receipt failure is returned. The probe is recovery guidance,
    /// not an exact reconstruction of the transaction's historical revert.
    ///
    /// Returns the `TxHash` of the confirmed transaction.
    #[instrument(level = "info", skip_all)]
    async fn submit<D>(
        &self,
        transaction: CallBuilder<&DynProvider, D>,
    ) -> Result<TxHash, KeyRegistryEventError>
    where
        D: CallDecoder + Unpin + Clone,
    {
        let receipt = self.send_transaction(transaction.clone()).await?;
        self.record_metrics(&receipt).await;
        match receipt.ensure_success() {
            Ok(()) => Ok(receipt.transaction_hash),
            Err(e) => {
                let receipt_block_hash = receipt
                    .block_hash
                    .ok_or_else(|| eyre::eyre!("block hash not found on failed receipt"))?;
                tracing::debug!(
                    "transaction {e} failed - probing post-block state at {receipt_block_hash}"
                );
                self.call_pinned(
                    transaction.gas(self.max_gas_per_transaction),
                    BlockId::hash(receipt_block_hash),
                )
                .await?;
                tracing::warn!("transaction failed but recovery probe succeeded");
                Err(KeyRegistryEventError::TransactionFailedError(e))
            }
        }
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
    ) -> Result<TxHash, KeyRegistryEventError> {
        let transaction = self
            .contract
            .addRound1KeyGenContribution(oprf_key_id.into_inner(), contribution);
        self.submit(transaction).await
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
    ) -> Result<TxHash, KeyRegistryEventError> {
        let transaction = self
            .contract
            .addRound1ReshareContribution(oprf_key_id.into_inner(), contribution);
        self.submit(transaction).await
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
    ) -> Result<TxHash, KeyRegistryEventError> {
        let transaction = self
            .contract
            .addRound2Contribution(oprf_key_id.into_inner(), contribution);
        self.submit(transaction).await
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
    ) -> Result<TxHash, KeyRegistryEventError> {
        let transaction = self
            .contract
            .addRound3Contribution(oprf_key_id.into_inner());
        self.submit(transaction).await
    }
}
