//! Retry helpers for transient database errors.

use std::{num::NonZeroUsize, time::Duration};

use backon::{BackoffBuilder as _, ConstantBackoff, ConstantBuilder, Retryable as _};

/// Returns `true` if `e` is a structural or driver-level error that is worth retrying.
#[inline]
#[must_use]
pub fn is_transient(e: &sqlx::Error) -> bool {
    matches!(
        e,
        sqlx::Error::PoolTimedOut
            | sqlx::Error::Io(_)
            | sqlx::Error::Tls(_)
            | sqlx::Error::Protocol(_)
            | sqlx::Error::AnyDriverError(_)
            | sqlx::Error::WorkerCrashed
            | sqlx::Error::BeginFailed
    )
}

/// Returns `true` if `e` is [transient](is_transient) or a transaction conflict.
///
/// Conflicts are `serialization_failure` (`40001`) and `deadlock_detected` (`40P01`).
#[inline]
#[must_use]
pub fn is_transient_or_conflict(e: &sqlx::Error) -> bool {
    is_transient(e)
        || matches!(
            e,
            sqlx::Error::Database(db_err)
                if matches!(db_err.code().as_deref(), Some("40001" | "40P01"))
        )
}

/// Builds the constant backoff strategy used for retrying database operations.
#[inline]
#[must_use]
pub fn backoff(max_retries: NonZeroUsize, delay: Duration) -> ConstantBackoff {
    ConstantBuilder::new()
        .with_delay(delay)
        .with_max_times(max_retries.get())
        .build()
}

/// Runs `op` and retries it with `backoff` while `retryable` returns `true` for its error.
///
/// Sleeps with [`tokio::time::sleep`] between attempts and logs a warning with the error,
/// `op_name` and the delay before each retry. Once the backoff is exhausted, or on an error
/// `retryable` rejects, the last error is returned.
///
/// # Errors
/// Returns the error of the last attempt if no attempt succeeded.
pub async fn with_retry<T, E, Fut, F, P>(
    op_name: &str,
    backoff: ConstantBackoff,
    retryable: P,
    op: F,
) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    P: Fn(&E) -> bool,
    E: std::fmt::Display,
{
    op.retry(backoff)
        .sleep(tokio::time::sleep)
        .when(retryable)
        .notify(|err, duration| {
            tracing::warn!(%err, "Retrying {op_name} in db after {duration:?}");
        })
        .await
}
