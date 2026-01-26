//! Metrics definitions for the OPRF service.
//!
//! This module defines all metrics keys used by the service and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.

/// Attribute ID attached to KEY_GEN_ROUND* metrics distinguishing key_gen vs reshare
pub const METRICS_ATTRID_PROTOCOL: &str = "protocol";
/// Attribute ID attached to KEY_GEN_ROUND* metrics distinguishing producer vs consumer
pub const METRICS_ATTRID_ROLE: &str = "role";
/// Attribute ID attached to METRICS_ID_KEY_GEN_WALLET_BALANCE metric to easily see wallet address
pub const METRICS_ATTRID_WALLET_ADDRESS: &str = "wallet_address";

/// Attribute value for ROLE describing a producer
pub const METRICS_ATTRVAL_ROLE_PRODUCER: &str = "producer";
/// Attribute value for ROLE describing a consumer
pub const METRICS_ATTRVAL_ROLE_CONSUMER: &str = "consumer";

/// Attribute value for PROTOCOL describing key_gen
pub const METRICS_ATTRVAL_PROTOCOL_KEY_GEN: &str = "key_gen";
/// Attribute value for PROTOCOL describing reshare
pub const METRICS_ATTRVAL_PROTOCOL_RESHARE: &str = "reshare";

/// Observed event for start of round 1
pub const METRICS_ID_KEY_GEN_ROUND_1_START: &str = "taceo.oprf.key_gen.round_1.start";
/// Finished processing round 1 on our side
pub const METRICS_ID_KEY_GEN_ROUND_1_FINISH: &str = "taceo.oprf.key_gen.round_1.finish";
/// Observed event for start of round 2
pub const METRICS_ID_KEY_GEN_ROUND_2_START: &str = "taceo.oprf.key_gen.round_2.start";
/// Finished processing round 2 on our side
pub const METRICS_ID_KEY_GEN_ROUND_2_FINISH: &str = "taceo.oprf.key_gen.round_2.finish";
/// Observed event for start of round 3
pub const METRICS_ID_KEY_GEN_ROUND_3_START: &str = "taceo.oprf.key_gen.round_3.start";
/// Finished processing round 3 on our side
pub const METRICS_ID_KEY_GEN_ROUND_3_FINISH: &str = "taceo.oprf.key_gen.round_3.finish";
/// Observed event for start of round 4
pub const METRICS_ID_KEY_GEN_ROUND_4_START: &str = "taceo.oprf.key_gen.round_4.start";
/// Finished processing round 4 on our side
pub const METRICS_ID_KEY_GEN_ROUND_4_FINISH: &str = "taceo.oprf.key_gen.round_4.finish";
/// Observed event for start of a deletion
pub const METRICS_ID_KEY_GEN_DELETION: &str = "taceo.oprf.key_gen.deletion";

/// Observed event for keygen abort
pub const METRICS_ID_KEY_GEN_ABORT: &str = "taceo.oprf.key_gen.abort";

/// Number of null-response errors from Alchemy and transaction not recorded on-chain.
pub const METRICS_ID_KEY_GEN_RPC_RETRY: &str = "taceo.oprf.key_gen.rpc_retry";
/// Number of null-response errors from Alchemy but transaction recorded on-chain.
pub const METRICS_ID_KEY_GEN_RPC_NULL_BUT_OK: &str = "taceo.oprf.key_gen.rpc_null_but_ok";

/// Balance of the wallet used for key generation
pub const METRICS_ID_KEY_GEN_WALLET_BALANCE: &str = "taceo.oprf.key_gen.wallet_balance";

/// Gas used by a single transaction in key-gen round 1
pub const METRICS_ID_KEY_GEN_ROUND1_GAS_COST: &str =
    "taceo.oprf.key_gen.transaction.cost.round1.key_gen";

/// Gas used by a single transaction in reshare round 1
pub const METRICS_ID_RESHARE_ROUND1_GAS_COST: &str =
    "taceo.oprf.key_gen.transaction.cost.round1.reshare";

/// Gas used by a single transaction in key-gen/reshare round 2
pub const METRICS_ID_ROUND2_GAS_COST: &str = "taceo.oprf.key_gen.transaction.cost.round2";

/// Gas used by a single transaction in key-gen round 3
pub const METRICS_ID_KEY_GEN_ROUND3_GAS_COST: &str =
    "taceo.oprf.key_gen.transaction.cost.round3.key_gen";

/// Gas used by a single transaction in reshare round 3
pub const METRICS_ID_RESHARE_ROUND3_GAS_COST: &str =
    "taceo.oprf.key_gen.transaction.cost.round3.reshare";

/// Describe all metrics used by the service.
///
/// This calls the `describe_*` functions from the `metrics` crate to set metadata on the different metrics.
pub fn describe_metrics() {
    metrics::describe_counter!(
        METRICS_ID_KEY_GEN_ROUND_1_START,
        metrics::Unit::Count,
        "Number of observed round 1 events for key_gen/reshare"
    );
    metrics::describe_counter!(
        METRICS_ID_KEY_GEN_ROUND_1_FINISH,
        metrics::Unit::Count,
        "Number of finished round 1 steps of key_gen/reshare"
    );
    metrics::describe_counter!(
        METRICS_ID_KEY_GEN_ROUND_2_START,
        metrics::Unit::Count,
        "Number of observed round 2 events for key_gen/reshare"
    );
    metrics::describe_counter!(
        METRICS_ID_KEY_GEN_ROUND_2_FINISH,
        metrics::Unit::Count,
        "Number of finished round 2 steps of key_gen/reshare"
    );
    metrics::describe_counter!(
        METRICS_ID_KEY_GEN_ROUND_3_START,
        metrics::Unit::Count,
        "Number of observed round 3 events for key_gen/reshare"
    );
    metrics::describe_counter!(
        METRICS_ID_KEY_GEN_ROUND_3_FINISH,
        metrics::Unit::Count,
        "Number of finished round 3 steps of key_gen/reshare"
    );
    metrics::describe_counter!(
        METRICS_ID_KEY_GEN_ROUND_4_START,
        metrics::Unit::Count,
        "Number of observed round 4 events for key_gen/reshare"
    );
    metrics::describe_counter!(
        METRICS_ID_KEY_GEN_ROUND_4_FINISH,
        metrics::Unit::Count,
        "Number of finished round 4 steps of key_gen/reshare"
    );
    metrics::describe_counter!(
        METRICS_ID_KEY_GEN_DELETION,
        metrics::Unit::Count,
        "Number of observed deletion events"
    );
    metrics::describe_counter!(
        METRICS_ID_KEY_GEN_ABORT,
        metrics::Unit::Count,
        "Number of observed abort events"
    );
    metrics::describe_counter!(
        METRICS_ID_KEY_GEN_RPC_RETRY,
        metrics::Unit::Count,
        "Number of null-response errors from Alchemy and transaction not recorded on-chain, leading to a retry."
    );
    metrics::describe_counter!(
        METRICS_ID_KEY_GEN_RPC_NULL_BUT_OK,
        metrics::Unit::Count,
        "Number of null-response errors from Alchemy but transaction recorded on-chain."
    );
    metrics::describe_gauge!(
        METRICS_ID_KEY_GEN_WALLET_BALANCE,
        metrics::Unit::Count,
        "Balance of the wallet used for key generation in GWEI"
    );
    metrics::describe_histogram!(
        METRICS_ID_KEY_GEN_ROUND1_GAS_COST,
        metrics::Unit::Count,
        "Gas used by a single transaction in key-gen round 1 in GWEI"
    );
    metrics::describe_histogram!(
        METRICS_ID_RESHARE_ROUND1_GAS_COST,
        metrics::Unit::Count,
        "Gas used by a single transaction in reshare round 1 in GWEI"
    );
    metrics::describe_histogram!(
        METRICS_ID_ROUND2_GAS_COST,
        metrics::Unit::Count,
        "Gas used by a single transaction in key-gen/reshare round 2 in GWEI"
    );
    metrics::describe_histogram!(
        METRICS_ID_KEY_GEN_ROUND3_GAS_COST,
        metrics::Unit::Count,
        "Gas used by a single transaction in key-gen round 3 in GWEI"
    );
    metrics::describe_histogram!(
        METRICS_ID_RESHARE_ROUND3_GAS_COST,
        metrics::Unit::Count,
        "Gas used by a single transaction in reshare round 3 in GWEI"
    );
}
