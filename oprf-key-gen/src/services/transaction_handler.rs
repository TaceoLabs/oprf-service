use std::{f64, time::Duration};

use alloy::{
    contract::{CallBuilder, CallDecoder},
    network::{Network, ReceiptResponse},
    primitives::Address,
    providers::Provider,
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
        // start the timer for this transaction
        let transaction_result = transaction()
            .gas(self.max_gas_per_transaction)
            .send()
            .await
            .context("while broadcasting to network")?
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
            tracing::debug!("current wallet balance: {balance_eth} ETH",);
            ::metrics::gauge!(METRICS_ID_KEY_GEN_WALLET_BALANCE, METRICS_ATTRID_WALLET_ADDRESS => self.wallet_address.to_string())
                    .set(balance_eth.parse::<f64>().unwrap_or(f64::NAN));
        } else {
            tracing::warn!("could not fetch current wallet balance");
        }
        match transaction_result {
            Ok(receipt) => {
                return check_receipt(transaction, receipt).await;
            }
            Err(err) => {
                return Err(TransactionError::Rpc(eyre::eyre!(err)));
            }
        }
    }
}

/// Helper function to get the revert data in case the transaction failed.
async fn check_receipt<P, D, N, F>(
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

fn handle_success_receipt<R: ReceiptResponse>(receipt: R) {
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
    tracing::debug!("successfully sent transaction");
    tracing::debug!("gas used: {gas_used}");
    tracing::debug!("transaction cost: {cost_eth} ETH");
    tracing::debug!("transaction gas price: {gas_price_eth} ETH");
    metrics::gauge!(METRICS_ID_GAS_PRICE).set(gas_price_wei);
}
