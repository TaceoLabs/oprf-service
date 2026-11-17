//! Helpers to seed the database in tests.

use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use sqlx::PgExecutor;

use crate::{
    LocalKeyWrapper, StorageCrypto, StoreError,
    aad::{Kind, RowId},
    codec,
};

/// The 32-byte test master key number `seed`; different seeds give different keys.
#[must_use]
pub fn master_key(seed: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut next = seed;
    for byte in &mut key {
        *byte = next;
        next = next.wrapping_add(1);
    }
    key
}

/// [`master_key`]`(seed)` as the 64 hex characters accepted in configuration.
#[must_use]
pub fn master_key_hex(seed: u8) -> String {
    crate::kms::to_hex(&master_key(seed))
}

/// A [`LocalKeyWrapper`] under [`master_key`]`(seed)`.
///
/// # Panics
///
/// Never; every test master key is accepted.
#[must_use]
pub fn local_wrapper(seed: u8) -> LocalKeyWrapper {
    LocalKeyWrapper::new(&master_key(seed)).expect("test master keys are valid")
}

/// Inserts a live share row for `oprf_key_id`.
///
/// # Errors
/// Returns an error if the insert fails, e.g., because a row for the key already exists.
pub async fn insert_share(
    exec: impl PgExecutor<'_>,
    oprf_key_id: OprfKeyId,
    epoch: ShareEpoch,
    share: &DLogShareShamir,
    public_key: &OprfPublicKey,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "
            INSERT INTO shares (id, share, epoch, public_key)
            VALUES ($1, $2, $3, $4)
        ",
    )
    .bind(oprf_key_id.to_le_bytes())
    .bind(codec::to_bytes(share).as_slice())
    // Postgres lacks u32; widen to i64
    .bind(i64::from(epoch.into_inner()))
    .bind(codec::to_bytes(public_key).as_slice())
    .execute(exec)
    .await?;
    Ok(())
}

/// Inserts a live share row for `oprf_key_id`, sealed by `crypto` in its write format.
///
/// # Errors
/// Returns an error if sealing fails (e.g., `crypto` is read-only) or the insert fails.
pub async fn insert_share_sealed(
    exec: impl PgExecutor<'_>,
    crypto: &StorageCrypto,
    oprf_key_id: OprfKeyId,
    epoch: ShareEpoch,
    share: &DLogShareShamir,
    public_key: &OprfPublicKey,
) -> Result<(), StoreError> {
    let row = RowId {
        kind: Kind::Share(*public_key),
        oprf_key_id,
        epoch,
    };
    let sealed = crypto.seal(&row, &codec::to_bytes(share))?;
    sqlx::query(
        "
            INSERT INTO shares (id, share, epoch, public_key, storage_format, data_key_id)
            VALUES ($1, $2, $3, $4, $5, $6)
        ",
    )
    .bind(oprf_key_id.to_le_bytes())
    .bind(sealed.bytes.as_slice())
    // Postgres lacks u32; widen to i64
    .bind(i64::from(epoch.into_inner()))
    .bind(codec::to_bytes(public_key).as_slice())
    .bind(sealed.format.as_str())
    .bind(sealed.data_key_id)
    .execute(exec)
    .await?;
    Ok(())
}
