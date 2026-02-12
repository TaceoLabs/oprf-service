//! Metrics definitions for the OPRF service.
//!
//! This module defines all metrics keys used by the service and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.

/// Metrics key for counting successful OPRF evaluations
pub const METRICS_ID_NODE_OPRF_SUCCESS: &str = "taceo.oprf.node.success";
/// Metrics key for counting currently running sessions.
pub const METRICS_ID_NODE_SESSIONS_OPEN: &str = "taceo.oprf.node.sessions.open";
/// Metrics key for deleted sessions.
pub const METRICS_ID_NODE_SESSIONS_TIMEOUT: &str = "taceo.oprf.node.sessions.timeout";
/// Metrics key for registered DLogSecrets.
pub const METRICS_ID_NODE_OPRF_SECRETS: &str = "taceo.oprf.node.secrets";
/// Metrics key for the duration of successful OprfRequestAuth verification
pub const METRICS_ID_NODE_REQUEST_VERIFY_DURATION: &str = "taceo.oprf.node.request_verify.duration";
/// Metrics key for the duration of part one of the OPRF computation
pub const METRICS_ID_NODE_PART_1_DURATION: &str = "taceo.oprf.node.part_1.duration";
/// Metrics key for the duration of part two of the OPRF computation
pub const METRICS_ID_NODE_PART_2_DURATION: &str = "taceo.oprf.node.part_2.duration";
/// Metrics key for number of requests for part one of the OPRF computation
pub const METRICS_ID_NODE_PART_1_START: &str = "taceo.oprf.node.part_1.start";
/// Metrics key for number of finishing handling a request for part one of the OPRF computation
pub const METRICS_ID_NODE_PART_1_FINISH: &str = "taceo.oprf.node.part_1.finish";
/// Metrics key for number of requests for part two of the OPRF computation
pub const METRICS_ID_NODE_PART_2_START: &str = "taceo.oprf.node.part_2.start";
/// Metrics key for number of finishing handling a request for part two of the OPRF computation
pub const METRICS_ID_NODE_PART_2_FINISH: &str = "taceo.oprf.node.part_2.finish";

/// Metrics key for times the node could not fetch key-material after finalize event.
pub const METRICS_ID_NODE_CANNOT_FETCH_KEY_MATERIAL: &str = "taceo.oprf.node.fetch.error";

/// Describe all metrics used by the service.
///
/// This calls the `describe_*` functions from the `metrics` crate to set metadata on the different metrics.
pub fn describe_metrics() {
    metrics::describe_counter!(
        METRICS_ID_NODE_OPRF_SUCCESS,
        metrics::Unit::Count,
        "Number of successful OPRF evaluations"
    );

    metrics::describe_gauge!(
        METRICS_ID_NODE_SESSIONS_OPEN,
        metrics::Unit::Count,
        "Number of open sessions the node has stored"
    );

    metrics::describe_counter!(
        METRICS_ID_NODE_SESSIONS_TIMEOUT,
        metrics::Unit::Count,
        "Number of sessions that were removed because they exceeded the deadline"
    );

    metrics::describe_gauge!(
        METRICS_ID_NODE_OPRF_SECRETS,
        metrics::Unit::Count,
        "Number of secrets stored"
    );

    metrics::describe_histogram!(
        METRICS_ID_NODE_REQUEST_VERIFY_DURATION,
        metrics::Unit::Milliseconds,
        "Duration of successful OprfRequestAuth verification"
    );

    metrics::describe_histogram!(
        METRICS_ID_NODE_PART_1_DURATION,
        metrics::Unit::Milliseconds,
        "Duration of the OPRF computation part one"
    );

    metrics::describe_histogram!(
        METRICS_ID_NODE_PART_2_DURATION,
        metrics::Unit::Milliseconds,
        "Duration of the OPRF computation part two"
    );

    metrics::describe_counter!(
        METRICS_ID_NODE_PART_1_START,
        metrics::Unit::Count,
        "Number of requests to compute part one of OPRF"
    );

    metrics::describe_counter!(
        METRICS_ID_NODE_PART_1_FINISH,
        metrics::Unit::Count,
        "Number of finished computations for part one of OPRF"
    );

    metrics::describe_counter!(
        METRICS_ID_NODE_PART_2_START,
        metrics::Unit::Count,
        "Number of requests to compute part two of OPRF"
    );

    metrics::describe_counter!(
        METRICS_ID_NODE_PART_2_FINISH,
        metrics::Unit::Count,
        "Number of finished computations for part two of OPRF"
    );

    metrics::describe_counter!(
        METRICS_ID_NODE_CANNOT_FETCH_KEY_MATERIAL,
        metrics::Unit::Count,
        "Number of times we could not fetch key-material from secret-manager"
    )
}
