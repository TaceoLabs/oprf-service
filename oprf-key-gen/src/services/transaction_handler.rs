use std::{f64, time::Duration};

use alloy::{
    contract::{CallBuilder, CallDecoder},
    network::ReceiptResponse,
    primitives::Address,
    providers::{DynProvider, Provider},
    rpc::types::TransactionReceipt,
    transports::TransportError,
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

use crate::{
    metrics::{
        METRICS_ATTRID_WALLET_ADDRESS, METRICS_ID_GAS_PRICE, METRICS_ID_KEY_GEN_WALLET_BALANCE,
    },
    services::key_event_watcher::KeyRegistryEventError,
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
    rpc_provider: web3::HttpRpcProvider,
    wallet_address: Address,
    contract: OprfKeyRegistryInstance<DynProvider>,
}

pub(crate) struct TransactionHandlerArgs {
    pub(crate) max_wait_time_watch_transaction: Duration,
    pub(crate) confirmations_for_transaction: u64,
    pub(crate) sleep_between_get_receipt: Duration,
    pub(crate) max_tries_fetching_receipt: usize,
    pub(crate) max_gas_per_transaction: u64,
    pub(crate) rpc_provider: web3::HttpRpcProvider,
    pub(crate) wallet_address: Address,
    pub(crate) contract_address: Address,
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
        } = value;
        Self {
            max_wait_time_watch_transaction,
            confirmations_for_transaction,
            sleep_between_get_receipt,
            max_tries_fetching_receipt,
            max_gas_per_transaction,
            wallet_address,
            contract: OprfKeyRegistryInstance::new(contract_address, rpc_provider.inner()),
            rpc_provider,
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

    async fn simulate_transaction<D>(
        &self,
        transaction: CallBuilder<&DynProvider, D>,
    ) -> Result<(), KeyRegistryEventError>
    where
        D: CallDecoder + Unpin,
    {
        tracing::trace!("simulating transaction before submitting");
        transaction.gas(self.max_gas_per_transaction).call().await?;
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
        let current_span = tracing::Span::current();
        current_span.record("tx_hash", tx_hash.to_string());
        let get_receipt_result = pending_transaction.get_receipt().await;
        match get_receipt_result {
            Ok(receipt) => Ok(receipt),
            Err(err) => {
                tracing::warn!(%err, "initial get_receipt failed - starting backon");
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
        }
    }

    async fn record_metrics(
        &self,
        receipt: TransactionReceipt,
    ) -> Result<(), KeyRegistryEventError> {
        tracing::trace!(
            "transaction with hash: {} confirmed",
            receipt.transaction_hash()
        );

        if let Ok(balance) = self.rpc_provider.get_balance(self.wallet_address).await {
            let balance_eth = alloy::primitives::utils::format_ether(balance);
            tracing::trace!("current wallet balance: {balance_eth} ETH",);
            ::metrics::gauge!(METRICS_ID_KEY_GEN_WALLET_BALANCE, METRICS_ATTRID_WALLET_ADDRESS => self.wallet_address.to_string())
                    .set(balance_eth.parse::<f64>().unwrap_or(f64::NAN));
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
        let gas_price_wei = receipt
            .effective_gas_price()
            .to_string()
            .parse::<f64>()
            .unwrap_or(f64::NAN);
        let gas_price_eth = alloy::primitives::utils::format_ether(receipt.effective_gas_price());
        tracing::trace!(
            "gas used: {gas_used}; transaction cost: {cost_eth} ETH; transaction gas price: {gas_price_eth} ETH"
        );
        metrics::gauge!(METRICS_ID_GAS_PRICE).set(gas_price_wei);
        Ok(())
    }

    #[instrument(level = "info", skip_all, fields(tx_hash = tracing::field::Empty))]
    async fn submit<D>(
        &self,
        transaction: CallBuilder<&DynProvider, D>,
    ) -> Result<(), KeyRegistryEventError>
    where
        D: CallDecoder + Unpin + Clone,
    {
        // first we simulate the transaction
        self.simulate_transaction(transaction.clone()).await?;
        let receipt = self.send_transaction(transaction).await?;
        receipt.ensure_success()?;
        self.record_metrics(receipt).await
    }

    pub(crate) async fn add_round1_keygen_contribution(
        &self,
        oprf_key_id: OprfKeyId,
        contribution: Round1Contribution,
    ) -> Result<(), KeyRegistryEventError> {
        let transaction = self
            .contract
            .addRound1KeyGenContribution(oprf_key_id.into_inner(), contribution);
        self.submit(transaction).await
    }

    pub(crate) async fn add_round1_reshare_contribution(
        &self,
        oprf_key_id: OprfKeyId,
        contribution: Round1Contribution,
    ) -> Result<(), KeyRegistryEventError> {
        let transaction = self
            .contract
            .addRound1ReshareContribution(oprf_key_id.into_inner(), contribution);
        self.submit(transaction).await
    }

    pub(crate) async fn add_round2_contribution(
        &self,
        oprf_key_id: OprfKeyId,
        contribution: Round2Contribution,
    ) -> Result<(), KeyRegistryEventError> {
        let transaction = self
            .contract
            .addRound2Contribution(oprf_key_id.into_inner(), contribution);
        self.submit(transaction).await
    }

    pub(crate) async fn add_round3_contribution(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> Result<(), KeyRegistryEventError> {
        let transaction = self
            .contract
            .addRound3Contribution(oprf_key_id.into_inner());
        self.submit(transaction).await
    }
}
