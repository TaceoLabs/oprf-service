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
    Sealed, StorageCrypto,
    aad::{Kind, RowId},
    codec,
    format::StorageFormat,
};
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

use super::Result;

/// Number of rows read per batch.
#[cfg(not(test))]
const BATCH_SIZE: i64 = 256;

/// Number of rows read per batch; small in tests so that few rows span several batches.
#[cfg(test)]
pub(super) const BATCH_SIZE: i64 = 2;

/// Byte length of an encoded [`OprfKeyId`].
const OPRF_KEY_ID_LEN: usize = 20;

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
/// `envelopeV1`. Returns the number of rows this call upgraded.
///
/// Rows are sealed without consulting the policy, so callers must only run it if `crypto`
/// allows `direct`: otherwise a planted `direct` row would become readable.
pub(super) async fn upgrade_all(pool: &PgPool, crypto: &StorageCrypto) -> Result<u64> {
    let mut upgraded = 0;

    let mut after: Option<Vec<u8>> = None;
    loop {
        let (count, last) =
            upgrade_shares_batch(pool, crypto, after.as_deref(), BATCH_SIZE).await?;
        upgraded += count;
        match last {
            Some(last) => after = Some(last),
            None => break,
        }
    }

    let mut after: Option<(Vec<u8>, i64)> = None;
    loop {
        let (count, last) = upgrade_in_progress_batch(pool, crypto, after, BATCH_SIZE).await?;
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
    let oprf_key_id = key_id(&row.id, "shares")?;
    let epoch = epoch(row.epoch, "shares", oprf_key_id)?;
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
                kind: Kind::Share,
                oprf_key_id,
                epoch,
                public_key: Some(&public_key),
            };
            let sealed = seal_verified(crypto, &row_id, share)?;
            sqlx::query(
                "
                    UPDATE shares
                    SET share = $3, storage_format = $4, data_key_id = $5
                    WHERE id = $1
                      AND epoch = $2
                      AND storage_format = 'direct'
                      AND share IS NOT NULL
                ",
            )
            .bind(&row.id)
            .bind(row.epoch)
            .bind(sealed.bytes.as_slice())
            .bind(sealed.format.as_str())
            .bind(sealed.data_key_id)
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
    let oprf_key_id = key_id(&row.id, "in_progress_keygens")?;
    let epoch = epoch(row.pending_epoch, "in_progress_keygens", oprf_key_id)?;
    let row_id = |kind| RowId {
        kind,
        oprf_key_id,
        epoch,
        public_key: None,
    };
    let intermediates = seal_verified(crypto, &row_id(Kind::Intermediates), &row.intermediates)?;
    let pending_share = row
        .pending_share
        .as_deref()
        .map(|share| seal_verified(crypto, &row_id(Kind::PendingShare), share))
        .transpose()?;
    let result = sqlx::query(
        "
            UPDATE in_progress_keygens
            SET intermediates = $3, pending_share = $4, storage_format = $5, data_key_id = $6
            WHERE id = $1
              AND pending_epoch = $2
              AND storage_format = 'direct'
              AND pending_share IS NOT DISTINCT FROM $7
        ",
    )
    .bind(&row.id)
    .bind(row.pending_epoch)
    .bind(intermediates.bytes.as_slice())
    .bind(pending_share.as_ref().map(|sealed| sealed.bytes.as_slice()))
    .bind(intermediates.format.as_str())
    .bind(intermediates.data_key_id)
    // A pending share stored concurrently since the read must not be overwritten.
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

/// Seals `plaintext` in the write format and checks that it opens to the same bytes.
fn seal_verified(crypto: &StorageCrypto, row: &RowId<'_>, plaintext: &[u8]) -> Result<Sealed> {
    let sealed = crypto.seal(row, plaintext)?;
    let opened = crypto.open(
        sealed.format.as_str(),
        sealed.data_key_id,
        row,
        &sealed.bytes,
    )?;
    if opened.as_slice() != plaintext {
        return Err(eyre!(
            "verifying the upgraded {:?} of {} at epoch {} failed",
            row.kind,
            row.oprf_key_id,
            row.epoch
        )
        .into());
    }
    Ok(sealed)
}

/// The data key the upgrade seals under; the write format must be `envelopeV1`.
fn envelope_data_key_id(crypto: &StorageCrypto) -> Result<Uuid> {
    match crypto.write_target() {
        Some((StorageFormat::EnvelopeV1, Some(id))) => Ok(id),
        target => Err(eyre!("the upgrade needs envelopeV1 as write format, not {target:?}").into()),
    }
}

fn key_id(raw: &[u8], table: &str) -> Result<OprfKeyId> {
    if raw.len() > OPRF_KEY_ID_LEN {
        return Err(eyre!("a row of {table} has an oprf key id of {} bytes", raw.len()).into());
    }
    Ok(OprfKeyId::from_le_slice(raw))
}

fn epoch(raw: i64, table: &str, oprf_key_id: OprfKeyId) -> Result<ShareEpoch> {
    u32::try_from(raw)
        .map(ShareEpoch::new)
        .map_err(|_| eyre!("the {table} row of {oprf_key_id} has epoch {raw} out of range").into())
}
