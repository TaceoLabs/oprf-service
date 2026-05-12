//! Metrics definitions for the OPRF service.
//!
//! This module defines all metrics keys used by the service and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.

/// Describe all metrics used by the service.
///
/// This calls the `describe_*` functions from the `metrics` crate to set metadata on the different metrics.
pub fn describe_metrics() {
    request::describe_metrics();
    health::describe_metrics();
    sessions::describe_metrics();
    secrets::describe_metrics();
}

pub(crate) mod request {
    use std::time::Duration;

    /// Metrics key for counting successful OPRF evaluations
    const METRICS_ID_NODE_OPRF_SUCCESS: &str = "taceo.oprf.node.request.success";

    /// Metrics key for the duration of successful `OprfRequestAuth` verification
    const METRICS_ID_NODE_REQUEST_VERIFY_DURATION: &str = "taceo.oprf.node.request.verify.duration";
    /// Metrics key for the duration of part one of the OPRF computation
    const METRICS_ID_NODE_PART_1_DURATION: &str = "taceo.oprf.node.request.part1.duration";
    /// Metrics key for the duration of part two of the OPRF computation
    const METRICS_ID_NODE_PART_2_DURATION: &str = "taceo.oprf.node.request.part2.duration";

    /// Metrics key for how often we reject clients due to version mismatch.
    const METRICS_CLIENT_VERSION_MISMATCH: &str = "taceo.oprf.node.client.invalid_version";

    pub(super) fn describe_metrics() {
        metrics::describe_counter!(
            METRICS_ID_NODE_OPRF_SUCCESS,
            metrics::Unit::Count,
            "Number of successful OPRF evaluations"
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
            METRICS_CLIENT_VERSION_MISMATCH,
            metrics::Unit::Count,
            "How often we rejected clients due to version mismatch"
        );
    }

    pub(crate) fn inc_client_version_mismatch() {
        metrics::counter!(METRICS_CLIENT_VERSION_MISMATCH).increment(1);
    }

    pub(crate) fn inc_success() {
        metrics::counter!(METRICS_ID_NODE_OPRF_SUCCESS).increment(1);
    }

    pub(crate) fn record_verify_duration(duration: Duration) {
        metrics::histogram!(METRICS_ID_NODE_REQUEST_VERIFY_DURATION)
            .record(duration.as_millis() as f64);
    }

    pub(crate) fn record_part1_duration(duration: Duration) {
        metrics::histogram!(METRICS_ID_NODE_PART_1_DURATION).record(duration.as_millis() as f64);
    }

    pub(crate) fn record_part2_duration(duration: Duration) {
        metrics::histogram!(METRICS_ID_NODE_PART_2_DURATION).record(duration.as_millis() as f64);
    }
}

pub(crate) mod health {

    const METRICS_ID_I_AM_ALIVE: &str = "taceo.oprf.node.i.am.alive";

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

pub(crate) mod sessions {
    /// Metrics key for counting currently running sessions.
    const METRICS_ID_NODE_SESSIONS_OPEN: &str = "taceo.oprf.node.sessions.open";

    pub(super) fn describe_metrics() {
        metrics::describe_gauge!(
            METRICS_ID_NODE_SESSIONS_OPEN,
            metrics::Unit::Count,
            "Number of open sessions the node has stored"
        );
    }

    pub(crate) fn reset() {
        ::metrics::gauge!(METRICS_ID_NODE_SESSIONS_OPEN).set(0);
    }

    pub(crate) fn inc() {
        ::metrics::gauge!(METRICS_ID_NODE_SESSIONS_OPEN).increment(1);
    }

    pub(crate) fn dec() {
        ::metrics::gauge!(METRICS_ID_NODE_SESSIONS_OPEN).decrement(1);
    }
}

pub(crate) mod secrets {

    /// Metrics key for registered `DLogSecrets`.
    const METRICS_ID_NODE_OPRF_SECRETS: &str = "taceo.oprf.node.secrets";

    pub(super) fn describe_metrics() {
        metrics::describe_gauge!(
            METRICS_ID_NODE_OPRF_SECRETS,
            metrics::Unit::Count,
            "Number of secrets stored"
        );
    }

    pub(crate) fn set(x: usize) {
        ::metrics::gauge!(METRICS_ID_NODE_OPRF_SECRETS).set(x as f64);
    }

    pub(crate) fn inc() {
        ::metrics::gauge!(METRICS_ID_NODE_OPRF_SECRETS).increment(1);
    }

    pub(crate) fn dec() {
        ::metrics::gauge!(METRICS_ID_NODE_OPRF_SECRETS).decrement(1);
    }
}
