//! Retry helpers for transient database errors.

use std::{num::NonZeroUsize, time::Duration};

use backon::{BackoffBuilder as _, ConstantBackoff, ConstantBuilder};

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
