//! Shared database storage layer for TACEO:OPRF.
//!
//! This crate holds the pieces that the OPRF key-gen service and the OPRF node
//! have in common when talking to the database:
//!
//! - [`mod@format`] and [`aad`]: the per-row storage format and the AAD binding ciphertexts to rows.
//! - [`codec`]: the canonical byte encoding of key material in the database.
//! - [`kms`]: wrapping of data encryption keys with a KMS key.
//! - `retry` (feature `postgres`): classification of transient database errors and the
//!   shared backoff strategy.
//! - `shares` (feature `postgres`): reading rows of the `shares` table.
//! - `test_utils` (feature `test-utils`): helpers to seed the database in tests.
//! - `MIGRATOR` (feature `postgres`): the embedded database migrations.
#![deny(missing_docs)]

pub mod aad;
mod cipher;
pub mod codec;
pub mod format;
pub mod kms;
#[cfg(feature = "postgres")]
pub mod retry;
#[cfg(feature = "postgres")]
pub mod shares;
#[cfg(feature = "test-utils")]
pub mod test_utils;

pub use cipher::Dek;
#[cfg(feature = "aws-kms")]
pub use kms::AwsKmsWrapper;
#[cfg(feature = "test-utils")]
pub use kms::InMemoryWrapper;
pub use kms::{DekWrapper, KmsError};

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
    /// The row is stored in a storage format this code path cannot read.
    #[error("unsupported storage format: {0}")]
    UnsupportedStorageFormat(String),
    /// An envelope-encryption error.
    #[error(transparent)]
    Envelope(#[from] EnvelopeError),
}

/// Errors of the envelope-encryption layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// The storage format string is not known.
    #[error("unknown storage format: {0}")]
    UnknownFormat(String),
    /// A public key was supplied for a row kind that has none, or is missing for one that has.
    #[error("public key does not match the row kind")]
    PublicKeyMismatch,
    /// Authenticated decryption failed.
    ///
    /// Deliberately carries no detail: a short input, a wrong key, a wrong AAD and modified
    /// bytes are indistinguishable.
    #[error("decryption failed")]
    Decrypt,
}
