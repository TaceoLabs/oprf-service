use std::{f64, time::Duration};

use alloy::{
    contract::{CallBuilder, CallDecoder},
    network::{Network, ReceiptResponse},
    primitives::Address,
    providers::{PendingTransactionError, Provider},
    transports::TransportError,
};
use backon::{BackoffBuilder as _, ConstantBackoff, ConstantBuilder, Retryable as _};
use eyre::Context as _;
use nodes_common::web3;
use tracing::instrument;

use crate::{
    metrics::{
        METRICS_ATTRID_WALLET_ADDRESS, METRICS_ID_GAS_PRICE, METRICS_ID_KEY_GEN_WALLET_BALANCE,
    },
    services::key_event_watcher::TransactionError,
};

/// Service that handles transaction submission and receipt confirmation.
///
/// Submits transactions to the blockchain via the configured RPC provider, waits for the
/// required number of confirmations up to `max_wait_time`, and handles failure cases by
/// performing a static call to extract revert data for diagnostics.
#[derive(Clone)]
pub(crate) struct TransactionHandler {
    max_wait_time_watch_transaction: Duration,
    confirmations_for_transaction: u64,
    sleep_between_get_receipt: Duration,
    max_tries_fetching_receipt: usize,
    max_gas_per_transaction: u64,
    rpc_provider: web3::RpcProvider,
    wallet_address: Address,
}

pub(crate) struct TransactionHandlerArgs {
    pub(crate) max_wait_time_watch_transaction: Duration,
    pub(crate) confirmations_for_transaction: u64,
    pub(crate) sleep_between_get_receipt: Duration,
    pub(crate) max_tries_fetching_receipt: usize,
    pub(crate) max_gas_per_transaction: u64,
    pub(crate) rpc_provider: web3::RpcProvider,
    pub(crate) wallet_address: Address,
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
        } = value;
        Self {
            max_wait_time_watch_transaction,
            confirmations_for_transaction,
            sleep_between_get_receipt,
            max_tries_fetching_receipt,
            max_gas_per_transaction,
            rpc_provider,
            wallet_address,
        }
    }
}

impl TransactionHandler {
    pub(crate) fn new(args: TransactionHandlerArgs) -> Self {
        Self::from(args)
    }

    fn backoff_strategy(&self) -> ConstantBackoff {
        ConstantBuilder::new()
            .with_delay(self.sleep_between_get_receipt)
            .with_max_times(self.max_tries_fetching_receipt)
            .build()
    }

    /// Attempts to send a transaction and waits for the receipt.
    ///
    /// Broadcasts the transaction to the network and waits for the configured number of
    /// confirmations, up to `max_wait_time`. If the receipt indicates success, returns `Ok`.
    /// If the receipt indicates failure, performs a static call to extract revert data for
    /// diagnostics (this is best-effort and should not be taken at face value).
    ///
    /// If the transaction could not be sent or the confirmation times out, returns an error.
    ///
    /// Takes an `Fn` that produces a `CallBuilder`. This can be done e.g., with
    /// ```rust,ignore
    /// transaction_handler
    ///     .attempt_transaction(|| {
    ///         contract.addRound1KeyGenContribution(
    ///             oprf_key_id.into_inner(),
    ///             contribution.clone().into(),
    ///         )
    ///     })
    ///     .await?;
    /// ```
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn attempt_transaction<P, D, N, F>(
        &self,
        transaction: F,
    ) -> Result<(), TransactionError>
    where
        P: Provider<N>,
        D: CallDecoder + Unpin,
        N: Network,
        F: Fn() -> CallBuilder<P, D, N>,
    {
        let pending_transaction = transaction()
            .gas(self.max_gas_per_transaction)
            .send()
            .await
            .context("while broadcasting to network")?
            .with_required_confirmations(self.confirmations_for_transaction)
            .with_timeout(Some(self.max_wait_time_watch_transaction));
        let tx_hash = pending_transaction.tx_hash().to_owned();
        let receipt_result = pending_transaction.get_receipt().await;

        tracing::trace!("transaction with hash: {tx_hash} confirmed");

        if let Ok(balance) = self
            .rpc_provider
            .http()
            .get_balance(self.wallet_address)
            .await
        {
            let balance_eth = alloy::primitives::utils::format_ether(balance);
            tracing::trace!("current wallet balance: {balance_eth} ETH",);
            ::metrics::gauge!(METRICS_ID_KEY_GEN_WALLET_BALANCE, METRICS_ATTRID_WALLET_ADDRESS => self.wallet_address.to_string())
                    .set(balance_eth.parse::<f64>().unwrap_or(f64::NAN));
        } else {
            tracing::warn!("could not fetch current wallet balance");
        }
        match receipt_result {
            Ok(receipt) => check_receipt(transaction, &receipt).await,
            Err(PendingTransactionError::TransportError(TransportError::NullResp)) => {
                let receipt = (|| async {
                    self.rpc_provider
                        .http()
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
                .await
                .context("while fetching getReceipt")?;
                check_receipt(transaction, &receipt).await
            }
            Err(err) => Err(TransactionError::Rpc(eyre::Report::from(err))),
        }
    }
}

async fn check_receipt<P, D, N, F, R>(transaction: F, receipt: &R) -> Result<(), TransactionError>
where
    P: Provider<N>,
    D: CallDecoder + Unpin,
    N: Network,
    F: Fn() -> CallBuilder<P, D, N>,
    R: ReceiptResponse + std::fmt::Debug,
{
    if receipt.status() {
        handle_success_receipt(receipt);
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

fn handle_success_receipt<R: ReceiptResponse>(receipt: &R) {
    let gas_used = receipt
        .gas_used()
        .to_string()
        .parse::<f64>()
        .unwrap_or(f64::NAN);
    let cost_eth = alloy::primitives::utils::format_ether(receipt.cost());
    // we do this to_string -> parse hop to have easy way to call to NAN if too large
    let gas_price_wei = receipt
        .effective_gas_price()
        .to_string()
        .parse::<f64>()
        .unwrap_or(f64::NAN);
    let gas_price_eth = alloy::primitives::utils::format_ether(receipt.effective_gas_price());
    tracing::debug!(
        "gas used: {gas_used}; transaction cost: {cost_eth} ETH; transaction gas price: {gas_price_eth} ETH"
    );
    metrics::gauge!(METRICS_ID_GAS_PRICE).set(gas_price_wei);
}
