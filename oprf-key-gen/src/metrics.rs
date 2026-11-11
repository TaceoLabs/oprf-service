//! Metrics definitions for the OPRF key-gen service.
//!
//! This module defines all metrics keys used by the key-gen node and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.
//!
//! # Metrics key schema
//!
//! Every metric emitted by this crate follows the schema
//!
//! ```text
//! taceo.oprf.key_gen.lib.METRICS_KEY
//! ```
//!
//! where `lib` is the sub-project slot reserved for keys emitted by this crate. Keys are
//! built with the `oprf_metrics_key!` macro instead of being hand-written, so the schema
//! stays enforced.

macro_rules! oprf_metrics_key {
    ($key:expr) => {
        concat!("taceo.oprf.key_gen.lib.", $key)
    };
}

/// Describe all metrics used by the service.
///
/// This calls the `describe_*` functions from the `metrics` crate to set metadata on the different metrics.
pub fn describe_metrics() {
    wallet::describe_metrics();
    chain_events::describe_metrics();
    storage::describe_metrics();
}

pub(crate) mod storage {
    const METRIC_ROWS_DIRECT: &str = oprf_metrics_key!("storage.rows.direct");
    const METRIC_ROWS_ENVELOPE_V1: &str = oprf_metrics_key!("storage.rows.envelope_v1");
    const METRIC_ROWS_DISALLOWED: &str = oprf_metrics_key!("storage.rows.disallowed");
    const METRIC_ROWS_UPGRADED: &str = oprf_metrics_key!("storage.rows.upgraded");

    pub(super) fn describe_metrics() {
        metrics::describe_gauge!(
            METRIC_ROWS_DIRECT,
            metrics::Unit::Count,
            "Number of rows with secrets stored as plaintext (direct), counted at startup"
        );

        metrics::describe_gauge!(
            METRIC_ROWS_ENVELOPE_V1,
            metrics::Unit::Count,
            "Number of rows with secrets stored encrypted (envelopeV1), counted at startup"
        );

        metrics::describe_gauge!(
            METRIC_ROWS_DISALLOWED,
            metrics::Unit::Count,
            "Number of rows stored in a format that is not allowed, counted at startup"
        );

        metrics::describe_counter!(
            METRIC_ROWS_UPGRADED,
            metrics::Unit::Count,
            "Number of rows upgraded from direct to envelopeV1"
        );
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "row counts stay far below 2^52, where f64 is exact"
    )]
    pub(crate) fn set_row_counts(direct: u64, envelope_v1: u64, disallowed: u64) {
        metrics::gauge!(METRIC_ROWS_DIRECT).set(direct as f64);
        metrics::gauge!(METRIC_ROWS_ENVELOPE_V1).set(envelope_v1 as f64);
        metrics::gauge!(METRIC_ROWS_DISALLOWED).set(disallowed as f64);
    }

    pub(crate) fn inc_upgraded(upgraded: u64) {
        metrics::counter!(METRIC_ROWS_UPGRADED).increment(upgraded);
    }
}

pub(crate) mod wallet {

    const METRICS_ID_KEY_GEN_WALLET_BALANCE: &str = oprf_metrics_key!("wallet.balance");
    const METRICS_ID_GAS_PRICE: &str = oprf_metrics_key!("wallet.transaction.gas_price");

    pub(super) fn describe_metrics() {
        metrics::describe_gauge!(
            METRICS_ID_KEY_GEN_WALLET_BALANCE,
            metrics::Unit::Count,
            "Balance of the wallet used for key generation in ETH"
        );

        metrics::describe_gauge!(
            METRICS_ID_GAS_PRICE,
            metrics::Unit::Count,
            "Gas price of the transactions in WEI"
        );
    }

    pub(crate) fn set_wallet_balance(balance_eth: &str) {
        metrics::gauge!(METRICS_ID_KEY_GEN_WALLET_BALANCE)
            .set(balance_eth.parse::<f64>().unwrap_or(f64::NAN));
    }

    pub(crate) fn set_gas_price_from_wei(gas_price_wei: u128) {
        let gas_price_wei = gas_price_wei.to_string().parse::<f64>().unwrap_or(f64::NAN);
        metrics::gauge!(METRICS_ID_GAS_PRICE).set(gas_price_wei);
    }
}

pub(crate) mod chain_events {
    use nodes_common::web3::event_stream::ChainCursor;

    const METRIC_EVENT_COUNTER: &str = oprf_metrics_key!("chain.events");

    const ATTR_TYPE_EVENT: &str = "type";
    const ATTR_EVENT_KEYGEN_ROUND1: &str = "round1.keygen";
    const ATTR_EVENT_RESHARE_ROUND1: &str = "round1.reshare";
    const ATTR_EVENT_ROUND2: &str = "round2";
    const ATTR_EVENT_ROUND3: &str = "round3";
    const ATTR_EVENT_FINALIZE: &str = "finalize";
    const ATTR_EVENT_DELETE: &str = "delete";
    const ATTR_EVENT_ABORT: &str = "abort";
    const ATTR_EVENT_NOT_ENOUGH_PRODUCERS: &str = "not-enough-producers";

    const METRIC_PRODUCER_ROLE: &str = oprf_metrics_key!("role.producer");
    const METRIC_CONSUMER_ROLE: &str = oprf_metrics_key!("role.consumer");
    const METRIC_CURRENT_BLOCK: &str = oprf_metrics_key!("block.number");

    pub(super) fn describe_metrics() {
        metrics::describe_counter!(
            METRIC_EVENT_COUNTER,
            metrics::Unit::Count,
            "Number of observed chain events successfully handled by this node"
        );

        metrics::describe_counter!(
            METRIC_PRODUCER_ROLE,
            metrics::Unit::Count,
            "Number of time the node participated as PRODUCER in the key-gen protocol"
        );

        metrics::describe_counter!(
            METRIC_CONSUMER_ROLE,
            metrics::Unit::Count,
            "Number of time the node participated as CONSUMER in the key-gen protocol"
        );

        metrics::describe_gauge!(
            METRIC_CURRENT_BLOCK,
            metrics::Unit::Count,
            "Last block where we observed a key-gen event"
        );
    }

    pub(crate) fn inc_keygen_round1() {
        metrics::counter!(METRIC_EVENT_COUNTER, ATTR_TYPE_EVENT => ATTR_EVENT_KEYGEN_ROUND1)
            .increment(1);
    }

    pub(crate) fn inc_reshare_round1() {
        metrics::counter!(METRIC_EVENT_COUNTER, ATTR_TYPE_EVENT => ATTR_EVENT_RESHARE_ROUND1)
            .increment(1);
    }

    pub(crate) fn inc_round2() {
        metrics::counter!(METRIC_EVENT_COUNTER, ATTR_TYPE_EVENT => ATTR_EVENT_ROUND2).increment(1);
    }

    pub(crate) fn inc_round3() {
        metrics::counter!(METRIC_EVENT_COUNTER, ATTR_TYPE_EVENT => ATTR_EVENT_ROUND3).increment(1);
    }

    pub(crate) fn inc_finalize() {
        metrics::counter!(METRIC_EVENT_COUNTER, ATTR_TYPE_EVENT => ATTR_EVENT_FINALIZE)
            .increment(1);
    }

    pub(crate) fn inc_delete() {
        metrics::counter!(METRIC_EVENT_COUNTER, ATTR_TYPE_EVENT => ATTR_EVENT_DELETE).increment(1);
    }

    pub(crate) fn inc_abort() {
        metrics::counter!(METRIC_EVENT_COUNTER, ATTR_TYPE_EVENT => ATTR_EVENT_ABORT).increment(1);
    }

    pub(crate) fn inc_not_enough_producers() {
        metrics::counter!(METRIC_EVENT_COUNTER, ATTR_TYPE_EVENT => ATTR_EVENT_NOT_ENOUGH_PRODUCERS)
            .increment(1);
    }

    pub(crate) fn inc_producer() {
        metrics::counter!(METRIC_PRODUCER_ROLE).increment(1);
    }

    pub(crate) fn inc_consumer() {
        metrics::counter!(METRIC_CONSUMER_ROLE).increment(1);
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "We accept precision loss as we don't expect to have a block number > f64::MAX"
    )]
    pub(crate) fn record_current_block(chain_cursor: ChainCursor) {
        metrics::gauge!(METRIC_CURRENT_BLOCK).set(chain_cursor.block() as f64);
    }
}
