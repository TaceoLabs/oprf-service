//! Shared database storage layer for TACEO:OPRF.
//!
//! This crate holds the pieces that the OPRF key-gen service and the OPRF node
//! have in common when talking to the database:
//!
//! - [`codec`]: the canonical byte encoding of key material in the database.
//! - `retry` (feature `postgres`): classification of transient database errors and the
//!   shared backoff strategy.
//! - `MIGRATOR` (feature `postgres`): the embedded database migrations.
#![deny(missing_docs)]

pub mod codec;
#[cfg(feature = "postgres")]
pub mod retry;

#[cfg(test)]
mod tests;

/// The embedded database migrations of the OPRF database schema.
#[cfg(feature = "postgres")]
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Errors returned by the storage layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The underlying database returned an error.
    #[cfg(feature = "postgres")]
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    /// Data read from the database is corrupt and could not be decoded.
    #[error("corrupt data in database: {0}")]
    Corrupt(String),
}
