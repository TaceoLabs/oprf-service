use std::{f64, time::Duration};

use alloy::{
    contract::{CallBuilder, CallDecoder},
    network::{Network, ReceiptResponse},
    primitives::Address,
    providers::{PendingTransactionError, Provider},
    transports::RpcError,
};
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
    max_wait_time: Duration,
    max_gas_per_transaction: u64,
    confirmations_for_transaction: u64,
    rpc_provider: web3::RpcProvider,
    wallet_address: Address,
}

impl TransactionHandler {
    pub(crate) fn new(
        max_wait_time: Duration,
        max_gas_per_transaction: u64,
        confirmations_for_transaction: u64,
        rpc_provider: web3::RpcProvider,
        wallet_address: Address,
    ) -> Self {
        Self {
            max_wait_time,
            max_gas_per_transaction,
            confirmations_for_transaction,
            rpc_provider,
            wallet_address,
        }
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
        let pending_tx = transaction()
            .gas(self.max_gas_per_transaction)
            .send()
            .await
            .context("while broadcasting to network")?;

        let pending_tx_hash = pending_tx.tx_hash().to_owned();

        let transaction_result = pending_tx
            .with_required_confirmations(self.confirmations_for_transaction)
            .with_timeout(Some(self.max_wait_time))
            .get_receipt()
            .await;
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
        match transaction_result {
            Ok(receipt) => {
                return check_receipt(transaction, &receipt).await;
            }
            Err(err) => {
                if matches!(
                    err,
                    PendingTransactionError::TransportError(RpcError::NullResp)
                ) {
                    // we got a null response. This can mean the transaction was accepted but the provider failed to return a proper responser.
                    let mut tries = 0;
                    loop {
                        tries += 1;
                        if tries > 5 {
                            return Err(TransactionError::Rpc(eyre::eyre!(
                                "transaction might have been accepted but could not get receipt after multiple tries: {pending_tx_hash}, last error: {err:?}"
                            )));
                        }

                        let maybe_receipt = self
                            .rpc_provider
                            .http()
                            .get_transaction_receipt(pending_tx_hash)
                            .await;

                        match maybe_receipt {
                            Ok(Some(receipt)) => {
                                tracing::debug!(
                                    "got receipt for transaction after null response error, additional tries: {tries}"
                                );
                                return check_receipt(transaction, &receipt).await;
                            }
                            Ok(None) => {
                                tracing::debug!(
                                    "transaction receipt not available yet after null response error, additional tries: {tries}"
                                );
                                tokio::time::sleep(Duration::from_secs(2)).await;
                            }
                            Err(err) => {
                                tracing::debug!(
                                    "error while fetching receipt for transaction after null response error, additional tries: {tries}, error: {err:?}"
                                );
                                tokio::time::sleep(Duration::from_secs(2)).await;
                            }
                        }
                    }
                }
                return Err(TransactionError::Rpc(eyre::Report::from(err)));
            }
        }
    }
}

/// Helper function to get the revert data in case the transaction failed.
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
