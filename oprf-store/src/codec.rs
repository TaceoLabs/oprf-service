//! Canonical byte encoding of key material stored in the database.
//!
//! Values are stored in arkworks' uncompressed canonical serialization.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use zeroize::Zeroizing;

use crate::StoreError;

/// Serializes `t` into its uncompressed canonical byte representation.
///
/// The returned buffer is zeroized on drop, as it may contain secret key material.
///
/// # Panics
/// Panics if serialization into a `Vec` fails, which cannot happen for well-formed values.
#[inline]
#[must_use]
pub fn to_bytes<T: CanonicalSerialize>(t: &T) -> Zeroizing<Vec<u8>> {
    let mut bytes = Vec::with_capacity(t.uncompressed_size());
    t.serialize_uncompressed(&mut bytes).expect("Can serialize");
    Zeroizing::new(bytes)
}

/// Deserializes a `T` from its uncompressed canonical byte representation, running all validity checks.
///
/// The whole input must be consumed: trailing bytes after a valid encoding are rejected.
///
/// # Errors
/// Returns [`StoreError::Corrupt`] if `b` is not exactly a valid encoding of `T`.
#[inline]
pub fn from_bytes<T: CanonicalDeserialize>(b: &[u8]) -> Result<T, StoreError> {
    let mut reader = b;
    let t = T::deserialize_uncompressed(&mut reader)
        .map_err(|e| StoreError::Corrupt(format!("cannot deserialize bytes: {e}")))?;
    if !reader.is_empty() {
        return Err(StoreError::Corrupt(format!(
            "{} trailing bytes after encoded value",
            reader.len()
        )));
    }
    Ok(t)
}

/// Like [`from_bytes`], but takes ownership of the buffer and zeroizes it afterwards.
///
/// Database drivers hand out column values as owned `Vec<u8>` buffers that may hold secret key
/// material. This wipes the buffer after decoding, on success and on error alike.
///
/// # Errors
/// Returns [`StoreError::Corrupt`] if `b` is not exactly a valid encoding of `T`.
#[inline]
pub fn from_vec<T: CanonicalDeserialize>(b: Vec<u8>) -> Result<T, StoreError> {
    from_bytes(Zeroizing::new(b).as_slice())
}
