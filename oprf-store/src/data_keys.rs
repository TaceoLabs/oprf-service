//! Persistence of wrapped data encryption keys in the `data_keys` table.
//!
//! A data encryption key (DEK) is only ever stored wrapped by a KMS key. Key-gen creates a DEK
//! with [`create`]; key-gen and the node load and unwrap DEKs with [`load_all`] and [`load_one`].
//! None of these functions retry; callers decide.

use sqlx::PgExecutor;
use uuid::Uuid;

use crate::{Dek, DekWrapper, KmsError};

/// The `pg_advisory_xact_lock` key that serializes data key creation.
///
/// Key-gen takes this transaction-level advisory lock before it checks for a current data key
/// and creates one, so instances starting together create exactly one. The value is arbitrary
/// but fixed; it only has to differ from every other advisory lock key used on the database.
pub const CREATE_LOCK_KEY: i64 = 0x4f50_5246_4445_4b31; // "OPRFDEK1"

/// The only supported value of the `wrapping` column.
const WRAPPING_AWS_KMS: &str = "awsKms";

/// Errors of the `data_keys` persistence.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DataKeyError {
    /// The underlying database returned an error.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    /// Generating or unwrapping a data key with the KMS failed.
    #[error(transparent)]
    Kms(#[from] KmsError),
    /// The data key was wrapped with another KMS key than the configured one.
    #[error(
        "data key {id} is wrapped with KMS key {stored}, but KMS key {configured} is configured"
    )]
    KeyArnMismatch {
        /// The id of the data key.
        id: Uuid,
        /// The ARN stored with the data key.
        stored: String,
        /// The ARN of the configured wrapper.
        configured: String,
    },
    /// The `wrapping` of a stored data key is not known.
    #[error("unknown data key wrapping: {0}")]
    UnknownWrapping(String),
}

#[derive(sqlx::FromRow)]
struct DataKeyRow {
    id: Uuid,
    wrapped_key: Vec<u8>,
    wrapping: String,
    kms_key_arn: String,
}

impl DataKeyRow {
    /// Checks wrapping and ARN, then unwraps the key.
    async fn unwrap(self, wrapper: &dyn DekWrapper) -> Result<Dek, DataKeyError> {
        if self.wrapping != WRAPPING_AWS_KMS {
            return Err(DataKeyError::UnknownWrapping(self.wrapping));
        }
        if self.kms_key_arn != wrapper.key_arn() {
            return Err(DataKeyError::KeyArnMismatch {
                id: self.id,
                stored: self.kms_key_arn,
                configured: wrapper.key_arn().to_owned(),
            });
        }
        let key = wrapper.unwrap(self.id, &self.wrapped_key).await?;
        Ok(Dek::new(self.id, key))
    }
}

/// Loads and unwraps every data key.
///
/// # Errors
///
/// Returns an error if the query fails, a row has an unknown wrapping or was wrapped with
/// another KMS key than `wrapper`'s, or unwrapping a key fails. No row is skipped.
pub async fn load_all(
    exec: impl PgExecutor<'_>,
    wrapper: &dyn DekWrapper,
) -> Result<Vec<Dek>, DataKeyError> {
    let rows: Vec<DataKeyRow> =
        sqlx::query_as("SELECT id, wrapped_key, wrapping, kms_key_arn FROM data_keys")
            .fetch_all(exec)
            .await?;
    let mut deks = Vec::with_capacity(rows.len());
    for row in rows {
        deks.push(row.unwrap(wrapper).await?);
    }
    Ok(deks)
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
        "SELECT id, wrapped_key, wrapping, kms_key_arn FROM data_keys WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(exec)
    .await?;
    match row {
        Some(row) => Ok(Some(row.unwrap(wrapper).await?)),
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
/// Returns an error if the KMS call or the insert fails.
pub async fn create(
    exec: impl PgExecutor<'_>,
    wrapper: &dyn DekWrapper,
) -> Result<Dek, DataKeyError> {
    let id = Uuid::new_v4();
    let (key, wrapped_key) = wrapper.generate(id).await?;
    sqlx::query(
        "INSERT INTO data_keys (id, wrapped_key, wrapping, kms_key_arn) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(&wrapped_key)
    .bind(WRAPPING_AWS_KMS)
    .bind(wrapper.key_arn())
    .execute(exec)
    .await?;
    Ok(Dek::new(id, key))
}
