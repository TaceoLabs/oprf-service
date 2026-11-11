//! The storage policy: the single place that decides how a stored value is read or written.
//!
//! The `storage_format` column of a row can be changed by anyone with database write access, so
//! it never decides on its own how a row is read. The column *describes* the row; the configured
//! allowed set *authorizes* it. A row whose format is not allowed is a hard error, never a
//! fallback to another format.

use std::{
    collections::HashMap,
    sync::{PoisonError, RwLock},
};

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    Dek, EnvelopeError,
    aad::{AadContext, RowId},
    format::StorageFormat,
};

/// A value prepared for storage, together with the columns that describe it.
///
/// `bytes` holds ciphertext, or the plaintext itself for [`StorageFormat::Direct`]; it is
/// zeroized on drop either way.
#[allow(
    clippy::exhaustive_structs,
    reason = "plain data carrier, constructed and destructured by consumers"
)]
pub struct Sealed {
    /// The storage format to write into the `storage_format` column.
    pub format: StorageFormat,
    /// The data key id to write into the `data_key_id` column; `None` for `direct`.
    pub data_key_id: Option<Uuid>,
    /// The bytes to store.
    pub bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealed")
            .field("format", &self.format)
            .field("data_key_id", &self.data_key_id)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// The format new values are written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteTarget {
    /// Write plain bytes.
    Direct,
    /// Seal under the data key with this id.
    EnvelopeV1(Uuid),
}

impl WriteTarget {
    /// The storage format written by this target.
    #[must_use]
    pub const fn format(self) -> StorageFormat {
        match self {
            Self::Direct => StorageFormat::Direct,
            Self::EnvelopeV1(_) => StorageFormat::EnvelopeV1,
        }
    }
}

/// Policy for reading and writing secret columns.
///
/// Holds the set of formats this process is allowed to read, the [`AadContext`] of the
/// deployment, the known data keys and, optionally, the format new values are written in.
/// Instances built with [`StorageCrypto::new`] are read-only until [`StorageCrypto::with_write`]
/// is applied. Shareable between threads; data keys can be added through a shared reference.
pub struct StorageCrypto {
    allowed: Vec<StorageFormat>,
    ctx: AadContext,
    deks: RwLock<HashMap<Uuid, Dek>>,
    write: Option<WriteTarget>,
}

impl std::fmt::Debug for StorageCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageCrypto")
            .field("allowed", &self.allowed)
            .field("write", &self.write)
            .field("deks", &self.dek_count())
            .finish_non_exhaustive()
    }
}

impl StorageCrypto {
    /// Creates a read-only policy that allows reading the `allowed` formats and knows the given
    /// data keys.
    ///
    /// An empty `allowed` set is accepted here: every read then fails with
    /// [`EnvelopeError::FormatNotAllowed`].
    #[must_use]
    pub fn new(allowed: &[StorageFormat], ctx: AadContext, deks: Vec<Dek>) -> Self {
        Self {
            allowed: allowed.to_vec(),
            ctx,
            deks: RwLock::new(deks.into_iter().map(|d| (d.id(), d)).collect()),
            write: None,
        }
    }

    /// Makes this policy write new values to `target`.
    ///
    /// # Errors
    /// - [`EnvelopeError::WriteFormatNotAllowed`] if the format of `target` is not in the
    ///   allowed set.
    /// - [`EnvelopeError::UnknownDataKey`] if the data key of `target` is not known.
    pub fn with_write(mut self, target: WriteTarget) -> Result<Self, EnvelopeError> {
        if !self.allows(target.format()) {
            return Err(EnvelopeError::WriteFormatNotAllowed(target.format()));
        }
        if let WriteTarget::EnvelopeV1(id) = target
            && !self.has_dek(id)
        {
            return Err(EnvelopeError::UnknownDataKey(id));
        }
        self.write = Some(target);
        Ok(self)
    }

    /// Whether rows stored in `format` may be read.
    #[must_use]
    pub fn allows(&self, format: StorageFormat) -> bool {
        self.allowed.contains(&format)
    }

    /// Where new values are written to, or `None` if read-only.
    #[must_use]
    pub fn write_target(&self) -> Option<WriteTarget> {
        self.write
    }

    /// Whether the data key `id` is known.
    #[must_use]
    pub fn has_dek(&self, id: Uuid) -> bool {
        // The map is only ever mutated by a single `insert`, so it is consistent even if a
        // holder of the lock panicked; recover the guard instead of skipping the lookup.
        self.deks
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(&id)
    }

    /// Makes the data key `dek` known, replacing a key with the same id.
    pub fn insert_dek(&self, dek: Dek) {
        self.deks
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(dek.id(), dek);
    }

    fn dek_count(&self) -> usize {
        self.deks
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Reads a stored value.
    ///
    /// `format` and `data_key_id` are the raw column values of the row. Checks run in this
    /// order: the format is known, the format is allowed, then for `envelopeV1` a data key id
    /// is present, that key is known, and finally authenticated decryption under the AAD of
    /// `row`. For `direct`, `data_key_id` must be `None` and `stored` is returned unchanged;
    /// `row` is ignored.
    ///
    /// # Errors
    /// - [`EnvelopeError::UnknownFormat`] if `format` is not a known format string.
    /// - [`EnvelopeError::FormatNotAllowed`] if the format is not in the allowed set.
    /// - [`EnvelopeError::UnexpectedDataKeyId`] if a `direct` row has a data key id.
    /// - [`EnvelopeError::MissingDataKeyId`] if an `envelopeV1` row has no data key id.
    /// - [`EnvelopeError::UnknownDataKey`] if the data key is not known.
    /// - [`EnvelopeError::Decrypt`] if authentication fails.
    pub fn open(
        &self,
        format: &str,
        data_key_id: Option<Uuid>,
        row: &RowId,
        stored: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        let format: StorageFormat = format.parse()?;
        if !self.allows(format) {
            return Err(EnvelopeError::FormatNotAllowed(format));
        }
        match format {
            StorageFormat::Direct => {
                if data_key_id.is_some() {
                    return Err(EnvelopeError::UnexpectedDataKeyId);
                }
                Ok(Zeroizing::new(stored.to_vec()))
            }
            StorageFormat::EnvelopeV1 => {
                let id = data_key_id.ok_or(EnvelopeError::MissingDataKeyId)?;
                let deks = self.deks.read().unwrap_or_else(PoisonError::into_inner);
                let dek = deks.get(&id).ok_or(EnvelopeError::UnknownDataKey(id))?;
                let aad = self.ctx.aad(row);
                dek.open(&aad, stored)
            }
        }
    }

    /// Prepares `plaintext` for storage in the configured write format.
    ///
    /// Same as [`StorageCrypto::seal_as`] with the configured write target.
    ///
    /// # Errors
    /// - [`EnvelopeError::ReadOnly`] if no write target is configured.
    /// - Otherwise as [`StorageCrypto::seal_as`].
    pub fn seal(&self, row: &RowId, plaintext: &[u8]) -> Result<Sealed, EnvelopeError> {
        let target = self.write.ok_or(EnvelopeError::ReadOnly)?;
        let data_key_id = match target {
            WriteTarget::Direct => None,
            WriteTarget::EnvelopeV1(id) => Some(id),
        };
        self.seal_as(target.format(), data_key_id, row, plaintext)
    }

    /// Prepares `plaintext` for storage in `format`, for `envelopeV1` under the known data key
    /// `data_key_id`.
    ///
    /// Used to rewrite a row in the format and under the data key it already has. For `direct`
    /// the plaintext is returned as is; for `envelopeV1` it is sealed with the AAD of `row`.
    /// Requires a write-enabled instance, like [`StorageCrypto::seal`].
    ///
    /// # Errors
    /// - [`EnvelopeError::ReadOnly`] if no write target is configured.
    /// - [`EnvelopeError::FormatNotAllowed`] if `format` is not in the allowed set.
    /// - [`EnvelopeError::UnexpectedDataKeyId`] if `format` is `direct` and `data_key_id` is set.
    /// - [`EnvelopeError::MissingDataKeyId`] if `format` is `envelopeV1` and `data_key_id` is
    ///   `None`.
    /// - [`EnvelopeError::UnknownDataKey`] if the data key is not known.
    pub fn seal_as(
        &self,
        format: StorageFormat,
        data_key_id: Option<Uuid>,
        row: &RowId,
        plaintext: &[u8],
    ) -> Result<Sealed, EnvelopeError> {
        if self.write.is_none() {
            return Err(EnvelopeError::ReadOnly);
        }
        if !self.allows(format) {
            return Err(EnvelopeError::FormatNotAllowed(format));
        }
        match format {
            StorageFormat::Direct => {
                if data_key_id.is_some() {
                    return Err(EnvelopeError::UnexpectedDataKeyId);
                }
                Ok(Sealed {
                    format,
                    data_key_id: None,
                    bytes: Zeroizing::new(plaintext.to_vec()),
                })
            }
            StorageFormat::EnvelopeV1 => {
                let id = data_key_id.ok_or(EnvelopeError::MissingDataKeyId)?;
                let deks = self.deks.read().unwrap_or_else(PoisonError::into_inner);
                let dek = deks.get(&id).ok_or(EnvelopeError::UnknownDataKey(id))?;
                let aad = self.ctx.aad(row);
                Ok(Sealed {
                    format,
                    data_key_id: Some(id),
                    bytes: Zeroizing::new(dek.seal(&aad, plaintext)),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use alloy::primitives::Address;
    use ark_ec::AffineRepr;
    use oprf_types::{
        OprfKeyId, ShareEpoch,
        crypto::{OprfPublicKey, PartyId},
    };
    use ruint::aliases::U160;
    use uuid::Uuid;

    use super::*;
    use crate::aad::Kind;

    const CURRENT: Uuid = Uuid::from_u128(1);

    fn dek(id: Uuid) -> Dek {
        Dek::new(id, &[7u8; 32])
    }

    fn ctx() -> AadContext {
        AadContext {
            chain_id: 31337,
            registry: Address::from([0xAA; 20]),
            party_id: PartyId(1),
            threshold: NonZeroU16::new(2).expect("nonzero"),
        }
    }

    fn pk() -> OprfPublicKey {
        OprfPublicKey::from(ark_babyjubjub::EdwardsAffine::generator())
    }

    fn row(kind: Kind) -> RowId {
        RowId {
            kind,
            oprf_key_id: OprfKeyId::new(U160::from(5u64)),
            epoch: ShareEpoch::new(3),
        }
    }

    fn writer(allowed: &[StorageFormat]) -> StorageCrypto {
        StorageCrypto::new(allowed, ctx(), vec![dek(CURRENT)])
            .with_write(WriteTarget::EnvelopeV1(CURRENT))
            .expect("with_write")
    }

    fn all() -> [StorageFormat; 2] {
        [StorageFormat::Direct, StorageFormat::EnvelopeV1]
    }

    #[test]
    fn direct_passthrough() {
        let c = StorageCrypto::new(&[StorageFormat::Direct], ctx(), vec![]);
        let out = c
            .open("direct", None, &row(Kind::PendingShare), b"plain")
            .expect("open");
        assert_eq!(out.as_slice(), b"plain", "bytes unchanged");
    }

    #[test]
    fn direct_row_with_data_key_id_is_rejected() {
        let c = StorageCrypto::new(&[StorageFormat::Direct], ctx(), vec![]);
        assert!(
            matches!(
                c.open("direct", Some(CURRENT), &row(Kind::PendingShare), b"plain"),
                Err(EnvelopeError::UnexpectedDataKeyId)
            ),
            "a direct row must not carry a data key id"
        );
    }

    #[test]
    fn envelope_round_trip() {
        let c = writer(&all());
        let pk = pk();
        let r = row(Kind::Share(pk));
        let sealed = c.seal(&r, b"secret").expect("seal");
        assert_eq!(sealed.format, StorageFormat::EnvelopeV1, "format");
        assert_eq!(sealed.data_key_id, Some(CURRENT), "data key id");
        assert_ne!(sealed.bytes.as_slice(), b"secret", "must be encrypted");
        let out = c
            .open(
                sealed.format.as_str(),
                sealed.data_key_id,
                &r,
                &sealed.bytes,
            )
            .expect("open");
        assert_eq!(out.as_slice(), b"secret", "plaintext");
    }

    #[test]
    fn direct_seal() {
        let c = StorageCrypto::new(&[StorageFormat::Direct], ctx(), vec![])
            .with_write(WriteTarget::Direct)
            .expect("with_write");
        assert_eq!(c.write_target(), Some(WriteTarget::Direct), "target");
        let s = c.seal(&row(Kind::Intermediates), b"x").expect("seal");
        assert_eq!(s.format, StorageFormat::Direct, "format");
        assert_eq!(s.data_key_id, None, "no key id");
        assert_eq!(s.bytes.as_slice(), b"x", "plain bytes");
    }

    #[test]
    fn direct_rejected_when_not_allowed() {
        let c = writer(&[StorageFormat::EnvelopeV1]);
        let r = row(Kind::PendingShare);
        assert!(
            matches!(
                c.open("direct", None, &r, b"valid plaintext bytes"),
                Err(EnvelopeError::FormatNotAllowed(StorageFormat::Direct))
            ),
            "direct must be rejected"
        );
    }

    #[test]
    fn envelope_rejected_when_not_allowed() {
        let writer_crypto = writer(&all());
        let r = row(Kind::PendingShare);
        let sealed = writer_crypto.seal(&r, b"x").expect("seal");
        let c = StorageCrypto::new(&[StorageFormat::Direct], ctx(), vec![dek(CURRENT)]);
        assert!(
            matches!(
                c.open("envelopeV1", sealed.data_key_id, &r, &sealed.bytes),
                Err(EnvelopeError::FormatNotAllowed(StorageFormat::EnvelopeV1))
            ),
            "envelope must be rejected"
        );
    }

    #[test]
    fn unknown_format_string() {
        let c = writer(&all());
        let r = row(Kind::PendingShare);
        for s in ["envelopeV2", ""] {
            assert!(
                matches!(
                    c.open(s, Some(CURRENT), &r, b"x"),
                    Err(EnvelopeError::UnknownFormat(_))
                ),
                "{s:?} must be unknown"
            );
        }
    }

    #[test]
    fn missing_data_key_id() {
        let c = writer(&all());
        let r = row(Kind::PendingShare);
        let sealed = c.seal(&r, b"x").expect("seal");
        assert!(
            matches!(
                c.open("envelopeV1", None, &r, &sealed.bytes),
                Err(EnvelopeError::MissingDataKeyId)
            ),
            "missing id"
        );
    }

    /// Seals a share row under the base context and row, then opens it with the given
    /// (changed) context and row. Must fail with `Decrypt`.
    fn assert_open_fails(field: &str, open_ctx: AadContext, open_row: &RowId) {
        let base_pk = pk();
        let sealed = writer(&all())
            .seal(&row(Kind::Share(base_pk)), b"secret")
            .expect("seal");
        let c = StorageCrypto::new(&all(), open_ctx, vec![dek(CURRENT)]);
        let res = c.open("envelopeV1", Some(CURRENT), open_row, &sealed.bytes);
        assert!(
            matches!(res, Err(EnvelopeError::Decrypt)),
            "changing {field} must fail with Decrypt"
        );
    }

    #[test]
    fn open_under_other_row_or_context_fails() {
        let pk = pk();
        let mut r = row(Kind::Share(pk));
        r.epoch = ShareEpoch::new(4);
        assert_open_fails("epoch", ctx(), &r);

        let mut c = ctx();
        c.chain_id += 1;
        assert_open_fails("chain_id", c, &row(Kind::Share(pk)));
    }

    #[test]
    fn kind_swap_fails() {
        let c = writer(&all());
        let sealed = c.seal(&row(Kind::PendingShare), b"x").expect("seal");
        let pk = pk();
        // A `PendingShare` ciphertext opened as a `Share` (with a public key, as AAD requires).
        let res = c.open(
            "envelopeV1",
            sealed.data_key_id,
            &row(Kind::Share(pk)),
            &sealed.bytes,
        );
        assert!(matches!(res, Err(EnvelopeError::Decrypt)), "kind swap");
        let res = c.open(
            "envelopeV1",
            sealed.data_key_id,
            &row(Kind::Intermediates),
            &sealed.bytes,
        );
        assert!(matches!(res, Err(EnvelopeError::Decrypt)), "kind swap");
    }

    #[test]
    fn insert_dek_makes_row_readable() {
        let writer_crypto = writer(&all());
        let r = row(Kind::PendingShare);
        let sealed = writer_crypto.seal(&r, b"x").expect("seal");
        let reader = StorageCrypto::new(&all(), ctx(), vec![]);
        assert!(!reader.has_dek(CURRENT), "not yet known");
        assert!(
            matches!(
                reader.open("envelopeV1", Some(CURRENT), &r, &sealed.bytes),
                Err(EnvelopeError::UnknownDataKey(_))
            ),
            "unreadable before insert"
        );
        reader.insert_dek(dek(CURRENT));
        assert!(reader.has_dek(CURRENT), "known after insert");
        let out = reader
            .open("envelopeV1", Some(CURRENT), &r, &sealed.bytes)
            .expect("open");
        assert_eq!(out.as_slice(), b"x", "plaintext");
    }

    #[test]
    fn with_write_validation() {
        let new =
            |allowed: &[StorageFormat]| StorageCrypto::new(allowed, ctx(), vec![dek(CURRENT)]);
        assert!(
            matches!(
                new(&[StorageFormat::Direct]).with_write(WriteTarget::EnvelopeV1(CURRENT)),
                Err(EnvelopeError::WriteFormatNotAllowed(
                    StorageFormat::EnvelopeV1
                ))
            ),
            "envelope write not allowed"
        );
        assert!(
            matches!(
                new(&[StorageFormat::EnvelopeV1]).with_write(WriteTarget::Direct),
                Err(EnvelopeError::WriteFormatNotAllowed(StorageFormat::Direct))
            ),
            "direct write not allowed"
        );
        let unknown = Uuid::from_u128(42);
        assert!(
            matches!(
                new(&all()).with_write(WriteTarget::EnvelopeV1(unknown)),
                Err(EnvelopeError::UnknownDataKey(id)) if id == unknown
            ),
            "envelope with unknown current id"
        );
        let ok = new(&all())
            .with_write(WriteTarget::EnvelopeV1(CURRENT))
            .expect("valid");
        assert_eq!(
            ok.write_target(),
            Some(WriteTarget::EnvelopeV1(CURRENT)),
            "target"
        );
        assert!(ok.allows(StorageFormat::Direct), "allows direct");
        assert!(
            !new(&[StorageFormat::Direct]).allows(StorageFormat::EnvelopeV1),
            "denies"
        );
    }

    #[test]
    fn seal_as_uses_given_key() {
        let other = Uuid::from_u128(2);
        let c = StorageCrypto::new(
            &all(),
            ctx(),
            vec![dek(CURRENT), Dek::new(other, &[8u8; 32])],
        )
        .with_write(WriteTarget::EnvelopeV1(CURRENT))
        .expect("with_write");
        let r = row(Kind::PendingShare);
        let sealed = c
            .seal_as(StorageFormat::EnvelopeV1, Some(other), &r, b"x")
            .expect("seal_as");
        assert_eq!(sealed.format, StorageFormat::EnvelopeV1, "format");
        assert_eq!(sealed.data_key_id, Some(other), "data key id");
        assert!(
            matches!(
                c.open("envelopeV1", Some(CURRENT), &r, &sealed.bytes),
                Err(EnvelopeError::Decrypt)
            ),
            "not sealed under the current key"
        );
        let out = c
            .open("envelopeV1", Some(other), &r, &sealed.bytes)
            .expect("open");
        assert_eq!(out.as_slice(), b"x", "plaintext");
    }

    #[test]
    fn seal_as_rejects_disallowed_format() {
        let c = writer(&[StorageFormat::EnvelopeV1]);
        assert!(
            matches!(
                c.seal_as(StorageFormat::Direct, None, &row(Kind::PendingShare), b"x"),
                Err(EnvelopeError::FormatNotAllowed(StorageFormat::Direct))
            ),
            "direct is not allowed"
        );
    }

    #[test]
    fn read_only_cannot_seal() {
        let c = StorageCrypto::new(&all(), ctx(), vec![dek(CURRENT)]);
        assert_eq!(c.write_target(), None, "no write target");
        assert!(
            matches!(
                c.seal(&row(Kind::PendingShare), b"x"),
                Err(EnvelopeError::ReadOnly)
            ),
            "read-only"
        );
    }
}
