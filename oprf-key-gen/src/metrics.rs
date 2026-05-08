//! Metrics definitions for the OPRF key-gen service.
//!
//! This module defines all metrics keys used by the key-gen node and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.

/// Describe all metrics used by the service.
///
/// This calls the `describe_*` functions from the `metrics` crate to set metadata on the different metrics.
pub fn describe_metrics() {
    health::describe_metrics();
    wallet::describe_metrics();
    chain_events::describe_metrics();
}

pub(crate) mod health {

    const METRICS_ID_I_AM_ALIVE: &str = "taceo.oprf.key_gen.i.am.alive";

    pub(super) fn describe_metrics() {
        metrics::describe_counter!(
            METRICS_ID_I_AM_ALIVE,
            metrics::Unit::Count,
            "I am alive metric. Used to measure liveness in datadog"
        );
    }

    pub(crate) fn inc_i_am_alive() {
        metrics::counter!(METRICS_ID_I_AM_ALIVE).increment(1);
    }
}

pub(crate) mod wallet {

    const METRICS_ID_KEY_GEN_WALLET_BALANCE: &str = "taceo.oprf.key_gen.wallet.balance";
    const METRICS_ID_GAS_PRICE: &str = "taceo.oprf.key_gen.wallet.transaction.gas_price";

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

    const METRIC_EVENT_COUNTER: &str = "taceo.oprf.key_gen.chain.events";

    const ATTR_TYPE_EVENT: &str = "type";
    const ATTR_EVENT_KEYGEN_ROUND1: &str = "round1.keygen";
    const ATTR_EVENT_RESHARE_ROUND1: &str = "round1.reshare";
    const ATTR_EVENT_ROUND2: &str = "round2";
    const ATTR_EVENT_ROUND3: &str = "round3";
    const ATTR_EVENT_FINALIZE: &str = "finalize";
    const ATTR_EVENT_DELETE: &str = "delete";
    const ATTR_EVENT_ABORT: &str = "abort";
    const ATTR_EVENT_NOT_ENOUGH_PRODUCERS: &str = "not-enough-producers";

    const METRIC_PRODUCER_ROLE: &str = "taceo.oprf.key_gen.role.producer";
    const METRIC_CONSUMER_ROLE: &str = "taceo.oprf.key_gen.role.consumer";
    const METRIC_CURRENT_BLOCK: &str = "taceo.oprf.key_gen.block.number";

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

        metrics::describe_counter!(
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

    pub(crate) fn record_current_block(chain_cursor: ChainCursor) {
        metrics::counter!(METRIC_CURRENT_BLOCK).absolute(chain_cursor.block());
    }
}
