//! Metrics definitions for the OPRF service.
//!
//! This module defines all metrics keys used by the service and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.
//!
//! # Metrics key schema
//!
//! Every metric emitted under the TACEO:OPRF umbrella follows the schema
//!
//! ```text
//! taceo.oprf.node.SUB_PROJECT.METRICS_KEY
//! ```
//!
//! where `SUB_PROJECT` identifies the emitting project and `METRICS_KEY` is the
//! metric-specific suffix. `lib` is reserved for keys emitted by this crate.
//!
//! Consumers building their own node metrics MUST go through [`crate::oprf_metrics_key`]
//! instead of hand-writing the key, so the schema stays enforced:
//!
//! ```
//! use taceo_oprf_service::oprf_metrics_key;
//!
//! const MY_KEY: &str = oprf_metrics_key!("my-service", "request.success");
//! assert_eq!(MY_KEY, "taceo.oprf.node.my-service.request.success");
//! ```

/// Builds a metrics key following the `taceo.oprf.node.SUB_PROJECT.METRICS_KEY` schema.
///
/// `$sub_project` identifies the emitting project (`"lib"` for this crate); `$key` is the
/// metric-specific suffix.
///
/// ```
/// use taceo_oprf_service::oprf_metrics_key;
///
/// assert_eq!(
///     oprf_metrics_key!("lib", "request.success"),
///     "taceo.oprf.node.lib.request.success"
/// );
/// ```
#[macro_export]
macro_rules! oprf_metrics_key {
    ($sub_project:expr, $key:expr) => {
        concat!("taceo.oprf.node.", $sub_project, ".", $key)
    };
}

/// Internal helper for the library.
macro_rules! oprf_metrics_key_lib {
    ($key:expr) => {
        oprf_metrics_key!("lib", $key)
    };
}

/// Describe all metrics used by the service.
///
/// This calls the `describe_*` functions from the `metrics` crate to set metadata on the different metrics.
pub fn describe_metrics() {
    request::describe_metrics();
    sessions::describe_metrics();
    secrets::describe_metrics();
}

pub(crate) mod request {
    use std::time::Duration;

    /// Metrics key for counting successful OPRF evaluations
    const METRICS_ID_NODE_OPRF_SUCCESS: &str = oprf_metrics_key_lib!("request.success");

    /// Metrics key for counting all OPRF requests
    const METRICS_ID_NODE_OPRF_REQUESTS: &str = oprf_metrics_key_lib!("request");

    /// Metrics key for the duration of successful `OprfRequestAuth` verification
    const METRICS_ID_NODE_REQUEST_VERIFY_DURATION: &str =
        oprf_metrics_key_lib!("request.verify.duration");
    /// Metrics key for the duration of part one of the OPRF computation
    const METRICS_ID_NODE_PART_1_DURATION: &str = oprf_metrics_key_lib!("request.part1.duration");
    /// Metrics key for the duration of part two of the OPRF computation
    const METRICS_ID_NODE_PART_2_DURATION: &str = oprf_metrics_key_lib!("request.part2.duration");

    /// Metrics key for how often we reject clients due to version mismatch.
    const METRICS_CLIENT_VERSION_MISMATCH: &str = oprf_metrics_key_lib!("client.invalid_version");

    /// Metrics key for how often we terminated user connection due to timeout.
    const METRICS_CLIENT_TIMEOUT: &str = oprf_metrics_key_lib!("request.timeout");

    /// Metrics key for counting all OPRF delegate requests
    const METRICS_ID_NODE_DELEGATE_REQUESTS: &str = oprf_metrics_key_lib!("delegate");

    /// Metrics key for counting successful OPRF delegate evaluations
    const METRICS_ID_NODE_DELEGATE_SUCCESS: &str = oprf_metrics_key_lib!("delegate.success");

    pub(super) fn describe_metrics() {
        params::describe_metrics();
        metrics::describe_counter!(
            METRICS_ID_NODE_OPRF_SUCCESS,
            metrics::Unit::Count,
            "Number of successful OPRF evaluations"
        );

        metrics::describe_counter!(
            METRICS_ID_NODE_OPRF_REQUESTS,
            metrics::Unit::Count,
            "Number of OPRF requests observed. Includes successes, failures and close connections due to threshold reached by client."
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

        metrics::describe_counter!(
            METRICS_CLIENT_TIMEOUT,
            metrics::Unit::Count,
            "How often we terminated user connection due to timeout"
        );

        metrics::describe_counter!(
            METRICS_ID_NODE_DELEGATE_REQUESTS,
            metrics::Unit::Count,
            "Number of OPRF delegate requests observed. Includes successes and failures."
        );

        metrics::describe_counter!(
            METRICS_ID_NODE_DELEGATE_SUCCESS,
            metrics::Unit::Count,
            "Number of successful OPRF delegate evaluations"
        );
    }

    pub(crate) fn inc_client_version_mismatch() {
        metrics::counter!(METRICS_CLIENT_VERSION_MISMATCH).increment(1);
    }

    pub(crate) fn inc_oprf_request() {
        metrics::counter!(METRICS_ID_NODE_OPRF_REQUESTS).increment(1);
    }

    pub(crate) fn inc_success() {
        metrics::counter!(METRICS_ID_NODE_OPRF_SUCCESS).increment(1);
    }

    pub(crate) fn inc_client_timeout() {
        metrics::counter!(METRICS_CLIENT_TIMEOUT).increment(1);
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

    pub(crate) fn inc_delegate_request() {
        metrics::counter!(METRICS_ID_NODE_DELEGATE_REQUESTS).increment(1);
    }

    pub(crate) fn inc_delegate_success() {
        metrics::counter!(METRICS_ID_NODE_DELEGATE_SUCCESS).increment(1);
    }

    pub(crate) mod params {

        const METRICS_ID_NODE_CLIENT_VERSION_HEADER: &str =
            oprf_metrics_key_lib!("request.params.version.header");
        const METRICS_ID_NODE_CLIENT_VERSION_QUERY: &str =
            oprf_metrics_key_lib!("request.params.version.query");

        pub(super) fn describe_metrics() {
            metrics::describe_counter!(
                METRICS_ID_NODE_CLIENT_VERSION_HEADER,
                metrics::Unit::Count,
                "How often clients reported their client version by HTTP header"
            );
            metrics::describe_counter!(
                METRICS_ID_NODE_CLIENT_VERSION_QUERY,
                metrics::Unit::Count,
                "How often clients reported their client version by query parameter"
            );
        }

        pub(crate) fn inc_client_version_in_header() {
            metrics::counter!(METRICS_ID_NODE_CLIENT_VERSION_HEADER).increment(1);
        }

        pub(crate) fn inc_client_version_in_query() {
            metrics::counter!(METRICS_ID_NODE_CLIENT_VERSION_QUERY).increment(1);
        }
    }
}

pub(crate) mod sessions {
    /// Metrics key for counting currently running sessions.
    const METRICS_ID_NODE_SESSIONS_OPEN: &str = oprf_metrics_key_lib!("sessions.open");

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

    /// Metrics key for stored `DLogSecrets` in cache.
    const METRICS_ID_NODE_OPRF_SECRETS: &str = oprf_metrics_key_lib!("secrets");
    /// Number of misses in the `DLogSecrets` cache.
    const METRICS_ID_NODE_OPRF_SECRETS_MISSES: &str = oprf_metrics_key_lib!("secrets.misses");
    /// Number of hits in the `DLogSecrets` cache.
    const METRICS_ID_NODE_OPRF_SECRETS_HITS: &str = oprf_metrics_key_lib!("secrets.hits");

    pub(super) fn describe_metrics() {
        metrics::describe_gauge!(
            METRICS_ID_NODE_OPRF_SECRETS,
            metrics::Unit::Count,
            "Number of secrets stored"
        );

        metrics::describe_counter!(
            METRICS_ID_NODE_OPRF_SECRETS_MISSES,
            metrics::Unit::Count,
            "Number of misses in the oprf-secrets cache."
        );

        metrics::describe_counter!(
            METRICS_ID_NODE_OPRF_SECRETS_HITS,
            metrics::Unit::Count,
            "Number of hits in the oprf-secrets cache."
        );
    }

    pub(crate) fn set(x: u64) {
        ::metrics::gauge!(METRICS_ID_NODE_OPRF_SECRETS).set(x as f64);
    }

    pub(crate) fn hit() {
        metrics::counter!(METRICS_ID_NODE_OPRF_SECRETS_HITS).increment(1);
    }

    pub(crate) fn miss() {
        metrics::counter!(METRICS_ID_NODE_OPRF_SECRETS_MISSES).increment(1);
    }
}
