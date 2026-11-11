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
/// # Errors
/// Returns [`StoreError::Corrupt`] if `b` is not a valid encoding of `T`.
#[inline]
pub fn from_bytes<T: CanonicalDeserialize>(b: &[u8]) -> Result<T, StoreError> {
    T::deserialize_uncompressed(b)
        .map_err(|e| StoreError::Corrupt(format!("cannot deserialize bytes: {e}")))
}
