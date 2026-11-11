//! Startup upgrade of `direct` rows to `envelopeV1`, and the count of rows per storage format.
//!
//! Rows are read in batches in primary key order and each row is rewritten by its own
//! compare-and-swap `UPDATE` that only matches while the row is still `direct` and unchanged.
//! An interrupted upgrade therefore leaves every row either fully upgraded or untouched, and a
//! later run picks up the remaining rows. The upgrade works on the raw column bytes: secrets are
//! sealed as they are stored, never deserialized. Only the public key of a live share is parsed,
//! because it is part of the associated data.

use eyre::eyre;
use oprf_store::{
    StorageCrypto,
    aad::{Kind, RowId},
    codec,
    format::StorageFormat,
    shares,
};
use oprf_types::crypto::OprfPublicKey;
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

use super::Result;

/// Number of rows read per batch at startup.
pub(super) const BATCH_SIZE: i64 = 256;

/// A `direct` row of the `shares` table. Holds plaintext key material; zeroized on drop.
#[derive(sqlx::FromRow, ZeroizeOnDrop)]
struct DirectShareRow {
    id: Vec<u8>,
    epoch: i64,
    share: Option<Vec<u8>>,
    public_key: Vec<u8>,
}

/// A `direct` row of the `in_progress_keygens` table. Holds plaintext key material; zeroized
/// on drop.
#[derive(sqlx::FromRow, ZeroizeOnDrop)]
struct DirectInProgressRow {
    id: Vec<u8>,
    pending_epoch: i64,
    intermediates: Vec<u8>,
    pending_share: Option<Vec<u8>>,
}

/// Number of rows per storage format in `shares` and `in_progress_keygens` together.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct FormatCounts {
    pub(super) direct: u64,
    pub(super) envelope_v1: u64,
    /// Rows whose format `crypto` does not allow, including unknown format strings.
    pub(super) disallowed: u64,
}

/// Upgrades every `direct` row of both tables to the write format of `crypto`, which must be
/// `envelopeV1`, reading `batch_size` rows at a time. Returns the number of rows this call
/// upgraded.
///
/// Rows are sealed without consulting the policy, so callers must only run it if `crypto`
/// allows `direct`: otherwise a planted `direct` row would become readable.
pub(super) async fn upgrade_all(
    pool: &PgPool,
    crypto: &StorageCrypto,
    batch_size: i64,
) -> Result<u64> {
    let mut upgraded = 0;

    let mut after: Option<Vec<u8>> = None;
    loop {
        let (count, last) =
            upgrade_shares_batch(pool, crypto, after.as_deref(), batch_size).await?;
        upgraded += count;
        match last {
            Some(last) => after = Some(last),
            None => break,
        }
    }

    let mut after: Option<(Vec<u8>, i64)> = None;
    loop {
        let (count, last) = upgrade_in_progress_batch(pool, crypto, after, batch_size).await?;
        upgraded += count;
        match last {
            Some(last) => after = Some(last),
            None => break,
        }
    }

    Ok(upgraded)
}

/// Upgrades up to `limit` `direct` share rows whose id is greater than `after`.
///
/// Returns the number of upgraded rows and the id of the last row read (`None` if none was
/// read), to continue with.
pub(super) async fn upgrade_shares_batch(
    pool: &PgPool,
    crypto: &StorageCrypto,
    after: Option<&[u8]>,
    limit: i64,
) -> Result<(u64, Option<Vec<u8>>)> {
    let data_key_id = envelope_data_key_id(crypto)?;
    let rows: Vec<DirectShareRow> = sqlx::query_as(
        "
            SELECT id, epoch, share, public_key
            FROM shares
            WHERE storage_format = 'direct'
              AND ($1::BYTEA IS NULL OR id > $1)
            ORDER BY id
            LIMIT $2
        ",
    )
    .bind(after)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut upgraded = 0;
    for row in &rows {
        if upgrade_share(pool, crypto, data_key_id, row).await? {
            upgraded += 1;
        }
    }
    Ok((upgraded, rows.last().map(|row| row.id.clone())))
}

/// Upgrades one share row; returns whether this call changed it.
async fn upgrade_share(
    pool: &PgPool,
    crypto: &StorageCrypto,
    data_key_id: Uuid,
    row: &DirectShareRow,
) -> Result<bool> {
    let oprf_key_id = shares::key_id(&row.id)?;
    let epoch = shares::epoch(row.epoch)?;
    let result = match row.share.as_deref() {
        // Soft-deleted: no secret to seal, only the format is relabeled.
        None => {
            sqlx::query(
                "
                    UPDATE shares
                    SET storage_format = $3, data_key_id = $4
                    WHERE id = $1
                      AND epoch = $2
                      AND storage_format = 'direct'
                      AND share IS NULL
                ",
            )
            .bind(&row.id)
            .bind(row.epoch)
            .bind(StorageFormat::EnvelopeV1.as_str())
            .bind(data_key_id)
            .execute(pool)
            .await?
        }
        Some(share) => {
            let public_key: OprfPublicKey = codec::from_bytes(&row.public_key).map_err(|e| {
                eyre!("the public key of share row {oprf_key_id} does not parse: {e}")
            })?;
            let row_id = RowId {
                kind: Kind::Share(public_key),
                oprf_key_id,
                epoch,
            };
            let sealed = crypto.seal(&row_id, share)?;
            sqlx::query(
                "
                    UPDATE shares
                    SET share = $3, storage_format = $4, data_key_id = $5
                    WHERE id = $1
                      AND epoch = $2
                      AND storage_format = 'direct'
                      AND share = $6
                ",
            )
            .bind(&row.id)
            .bind(row.epoch)
            .bind(sealed.bytes.as_slice())
            .bind(sealed.format.as_str())
            .bind(sealed.data_key_id)
            // A share replaced since the read must not be overwritten.
            .bind(share)
            .execute(pool)
            .await?
        }
    };
    Ok(result.rows_affected() == 1)
}

/// Upgrades up to `limit` `direct` in-progress rows whose `(id, pending_epoch)` is greater than
/// `after`.
///
/// Returns the number of upgraded rows and the key of the last row read (`None` if none was
/// read), to continue with.
async fn upgrade_in_progress_batch(
    pool: &PgPool,
    crypto: &StorageCrypto,
    after: Option<(Vec<u8>, i64)>,
    limit: i64,
) -> Result<(u64, Option<(Vec<u8>, i64)>)> {
    let (after_id, after_epoch) = after.unzip();
    let rows: Vec<DirectInProgressRow> = sqlx::query_as(
        "
            SELECT id, pending_epoch, intermediates, pending_share
            FROM in_progress_keygens
            WHERE storage_format = 'direct'
              AND ($1::BYTEA IS NULL OR (id, pending_epoch) > ($1, $2))
            ORDER BY id, pending_epoch
            LIMIT $3
        ",
    )
    .bind(after_id)
    .bind(after_epoch.unwrap_or_default())
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut upgraded = 0;
    for row in &rows {
        if upgrade_in_progress(pool, crypto, row).await? {
            upgraded += 1;
        }
    }
    Ok((
        upgraded,
        rows.last().map(|row| (row.id.clone(), row.pending_epoch)),
    ))
}

/// Upgrades one in-progress row; returns whether this call changed it.
async fn upgrade_in_progress(
    pool: &PgPool,
    crypto: &StorageCrypto,
    row: &DirectInProgressRow,
) -> Result<bool> {
    let oprf_key_id = shares::key_id(&row.id)?;
    let epoch = shares::epoch(row.pending_epoch)?;
    let row_id = |kind| RowId {
        kind,
        oprf_key_id,
        epoch,
    };
    let intermediates = crypto.seal(&row_id(Kind::Intermediates), &row.intermediates)?;
    let pending_share = row
        .pending_share
        .as_deref()
        .map(|share| crypto.seal(&row_id(Kind::PendingShare), share))
        .transpose()?;
    let result = sqlx::query(
        "
            UPDATE in_progress_keygens
            SET intermediates = $3, pending_share = $4, storage_format = $5, data_key_id = $6
            WHERE id = $1
              AND pending_epoch = $2
              AND storage_format = 'direct'
              AND intermediates = $7
              AND pending_share IS NOT DISTINCT FROM $8
        ",
    )
    .bind(&row.id)
    .bind(row.pending_epoch)
    .bind(intermediates.bytes.as_slice())
    .bind(pending_share.as_ref().map(|sealed| sealed.bytes.as_slice()))
    .bind(intermediates.format.as_str())
    .bind(intermediates.data_key_id)
    // Intermediates replaced (abort and retry of the same epoch) or a pending share stored
    // since the read must not be overwritten.
    .bind(&row.intermediates)
    .bind(row.pending_share.as_deref())
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Counts the rows of both tables per storage format, judged against what `crypto` allows.
pub(super) async fn count_formats(pool: &PgPool, crypto: &StorageCrypto) -> Result<FormatCounts> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "
            SELECT storage_format, COUNT(*)
            FROM (
                SELECT storage_format FROM shares
                UNION ALL
                SELECT storage_format FROM in_progress_keygens
            ) AS formats
            GROUP BY storage_format
        ",
    )
    .fetch_all(pool)
    .await?;
    let mut counts = FormatCounts::default();
    for (format, count) in rows {
        let count = count.unsigned_abs();
        let parsed = format.parse::<StorageFormat>().ok();
        match parsed {
            Some(StorageFormat::Direct) => counts.direct += count,
            Some(StorageFormat::EnvelopeV1) => counts.envelope_v1 += count,
            _ => {}
        }
        if !parsed.is_some_and(|format| crypto.allows(format)) {
            counts.disallowed += count;
        }
    }
    Ok(counts)
}

/// The data key the upgrade seals under; the write format must be `envelopeV1`.
fn envelope_data_key_id(crypto: &StorageCrypto) -> Result<Uuid> {
    match crypto.write_target() {
        Some(oprf_store::WriteTarget::EnvelopeV1(id)) => Ok(id),
        target => Err(eyre!("the upgrade needs envelopeV1 as write format, not {target:?}").into()),
    }
}
