//! Persistence of wrapped data encryption keys in the `data_keys` table.
//!
//! A data encryption key (DEK) is only ever stored wrapped by a [`DekWrapper`]. Key-gen creates a DEK
//! with [`create`]; key-gen and the node load and unwrap DEKs with [`load_all`] and [`load_one`].
//! None of these functions retry; callers decide.

use sqlx::PgExecutor;
use uuid::Uuid;

use crate::{Dek, DekWrapper, KmsError};

/// Errors of the `data_keys` persistence.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DataKeyError {
    /// The underlying database returned an error.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    /// Generating or unwrapping a data key failed.
    #[error(transparent)]
    Kms(#[from] KmsError),
    /// The data key was wrapped with another key than the configured one.
    #[error("data key {id} is wrapped with key {stored}, but key {configured} is configured")]
    KeyIdMismatch {
        /// The id of the data key.
        id: Uuid,
        /// The wrapping key identifier stored with the data key.
        stored: String,
        /// The key identifier of the configured wrapper.
        configured: String,
    },
    /// The data key was wrapped in another way than the configured wrapper wraps, e.g. by AWS
    /// KMS while a local master key is configured.
    #[error("data key {id} has wrapping {stored}, but wrapping {configured} is configured")]
    WrappingMismatch {
        /// The id of the data key.
        id: Uuid,
        /// The wrapping stored with the data key.
        stored: String,
        /// The wrapping of the configured wrapper.
        configured: &'static str,
    },
}

#[derive(sqlx::FromRow)]
struct DataKeyRow {
    id: Uuid,
    wrapped_key: Vec<u8>,
    wrapping: String,
    wrapping_key_id: String,
}

impl DataKeyRow {
    /// Checks wrapping and wrapping key, then unwraps the key.
    async fn unwrap_dek(self, wrapper: &dyn DekWrapper) -> Result<Dek, DataKeyError> {
        if self.wrapping != wrapper.wrapping() {
            return Err(DataKeyError::WrappingMismatch {
                id: self.id,
                stored: self.wrapping,
                configured: wrapper.wrapping(),
            });
        }
        if self.wrapping_key_id != wrapper.key_id() {
            return Err(DataKeyError::KeyIdMismatch {
                id: self.id,
                stored: self.wrapping_key_id,
                configured: wrapper.key_id().to_owned(),
            });
        }
        let key = wrapper.unwrap_dek(self.id, &self.wrapped_key).await?;
        Ok(Dek::new(self.id, &key))
    }
}

/// Loads and unwraps every data key.
///
/// # Errors
///
/// Returns an error if the query fails, a row was wrapped in another way or with another key
/// than `wrapper`'s, or unwrapping a key fails. No row is skipped.
pub async fn load_all(
    exec: impl PgExecutor<'_>,
    wrapper: &dyn DekWrapper,
) -> Result<Vec<Dek>, DataKeyError> {
    let rows: Vec<DataKeyRow> =
        sqlx::query_as("SELECT id, wrapped_key, wrapping, wrapping_key_id FROM data_keys")
            .fetch_all(exec)
            .await?;
    futures::future::try_join_all(rows.into_iter().map(|row| row.unwrap_dek(wrapper))).await
}

/// Loads and unwraps the data key `id`, or returns `None` if there is no such key.
///
/// # Errors
///
/// Same as [`load_all`].
pub async fn load_one(
    exec: impl PgExecutor<'_>,
    wrapper: &dyn DekWrapper,
    id: Uuid,
) -> Result<Option<Dek>, DataKeyError> {
    let row: Option<DataKeyRow> = sqlx::query_as(
        "SELECT id, wrapped_key, wrapping, wrapping_key_id FROM data_keys WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(exec)
    .await?;
    match row {
        Some(row) => Ok(Some(row.unwrap_dek(wrapper).await?)),
        None => Ok(None),
    }
}

/// Returns the id of the newest data key (by `created_at`), if any.
///
/// # Errors
///
/// Returns an error if the query fails.
pub async fn current_id(exec: impl PgExecutor<'_>) -> Result<Option<Uuid>, DataKeyError> {
    let id =
        sqlx::query_scalar("SELECT id FROM data_keys ORDER BY created_at DESC, id DESC LIMIT 1")
            .fetch_optional(exec)
            .await?;
    Ok(id)
}

/// Generates a new data key, stores it wrapped and returns it.
///
/// The key is only returned after the row was inserted.
///
/// # Errors
///
/// Returns an error if generating the key or the insert fails.
pub async fn create(
    exec: impl PgExecutor<'_>,
    wrapper: &dyn DekWrapper,
) -> Result<Dek, DataKeyError> {
    let id = Uuid::new_v4();
    let (key, wrapped_key) = wrapper.generate(id).await?;
    sqlx::query(
        "INSERT INTO data_keys (id, wrapped_key, wrapping, wrapping_key_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(&wrapped_key)
    .bind(wrapper.wrapping())
    .bind(wrapper.key_id())
    .execute(exec)
    .await?;
    Ok(Dek::new(id, &key))
}
