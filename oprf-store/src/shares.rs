//! Reading rows of the `shares` table.

use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use sqlx::PgExecutor;
use zeroize::ZeroizeOnDrop;

use crate::{StoreError, codec};

/// A raw row of the `shares` table.
///
/// The row may hold secret key material and is zeroized on drop.
#[derive(sqlx::FromRow, ZeroizeOnDrop)]
pub struct ShareRow {
    id: Vec<u8>,
    share: Option<Vec<u8>>,
    epoch: i64,
    public_key: Vec<u8>,
    deleted: bool,
}

impl std::fmt::Debug for ShareRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareRow")
            .field("deleted", &self.deleted)
            .field("epoch", &self.epoch)
            .field("has_share", &self.share.is_some())
            .finish_non_exhaustive()
    }
}

/// A decoded, live share together with its metadata.
#[non_exhaustive]
pub struct StoredShare {
    /// The id of the OPRF key.
    pub oprf_key_id: OprfKeyId,
    /// The epoch of the share.
    pub epoch: ShareEpoch,
    /// The public key of the OPRF key.
    pub public_key: OprfPublicKey,
    /// The secret share.
    pub share: DLogShareShamir,
}

impl std::fmt::Debug for StoredShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredShare")
            .field("oprf_key_id", &self.oprf_key_id)
            .field("epoch", &self.epoch)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// Fetches the row of the OPRF key `oprf_key_id`, whether live or deleted.
///
/// # Errors
/// Returns an error if the query fails.
pub async fn fetch(
    exec: impl PgExecutor<'_>,
    oprf_key_id: OprfKeyId,
) -> Result<Option<ShareRow>, sqlx::Error> {
    sqlx::query_as(
        "
            SELECT
                id,
                share,
                epoch,
                deleted,
                public_key
            FROM shares
            WHERE id = $1
        ",
    )
    .bind(oprf_key_id.to_le_bytes())
    .fetch_optional(exec)
    .await
}

impl ShareRow {
    /// Returns whether the row was soft-deleted.
    #[must_use]
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// Returns the epoch of the share.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] if the stored epoch does not fit into a `u32`.
    pub fn epoch(&self) -> Result<ShareEpoch, StoreError> {
        u32::try_from(self.epoch)
            .map(ShareEpoch::new)
            .map_err(|_| StoreError::Corrupt(format!("epoch {} out of range", self.epoch)))
    }

    /// Decodes the row into a [`StoredShare`].
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] if the row is deleted, the share is NULL, or any
    /// stored bytes are invalid.
    pub fn decode(&self) -> Result<StoredShare, StoreError> {
        if self.deleted {
            return Err(StoreError::Corrupt("row is deleted".to_owned()));
        }
        let share_bytes = self
            .share
            .as_deref()
            .ok_or_else(|| StoreError::Corrupt("share column is NULL for live row".to_owned()))?;
        Ok(StoredShare {
            oprf_key_id: OprfKeyId::from_le_slice(&self.id),
            epoch: self.epoch()?,
            public_key: codec::from_bytes(&self.public_key)?,
            share: codec::from_bytes(share_bytes)?,
        })
    }
}
