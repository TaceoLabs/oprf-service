//! AES-256-GCM sealing and opening of stored bytes with a data encryption key.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, KeyInit, Payload},
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::EnvelopeError;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// A data encryption key (DEK) with its identifier.
///
/// Seals and opens stored bytes laid out as `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
/// The key is zeroized on drop and never exposed or printed.
///
/// Every call builds a short-lived `Aes256Gcm`. With the `zeroize` feature of `aes-gcm` (which
/// enables it on `aes`, `ghash` and `polyval`), all of its key-dependent state is wiped when it
/// is dropped: the expanded AES round keys, the GHASH subkey `H = AES_K(0^128)` with its
/// precomputed powers, and the per-call copy of the GHASH state used to compute a tag. Not
/// covered: transient values on the stack or in registers that no zeroizing type owns, such as
/// intermediate copies made while the AES key schedule is built and counter-mode keystream
/// blocks.
pub struct Dek {
    id: Uuid,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Dek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dek")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Dek {
    /// Creates a data key from its identifier and raw key bytes.
    #[must_use]
    pub fn new(id: Uuid, key: Zeroizing<[u8; 32]>) -> Self {
        Self { id, key }
    }

    /// The identifier of this data key.
    #[must_use]
    pub fn id(&self) -> Uuid {
        self.id
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(self.key.as_slice()).expect("the key is exactly 32 bytes")
    }

    /// Encrypts `plaintext` bound to `aad` under a fresh random nonce.
    ///
    /// Returns `nonce || ciphertext || tag`.
    ///
    /// # Panics
    ///
    /// Panics if the operating system RNG fails or the plaintext exceeds the AES-GCM size limit.
    #[must_use]
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        // Drawn from the operating system RNG (`getrandom`).
        let nonce = Nonce::generate();
        let ct = self
            .cipher()
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("AES-256-GCM encryption of an in-memory buffer cannot fail");
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Decrypts bytes produced by [`Dek::seal`] with the same `aad`.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::Decrypt`] for every failure (too short, wrong key, wrong AAD,
    /// modified bytes), so callers cannot tell them apart.
    pub fn open(&self, aad: &[u8], stored: &[u8]) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        if stored.len() < NONCE_LEN + TAG_LEN {
            return Err(EnvelopeError::Decrypt);
        }
        let (nonce, ct) = stored.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| EnvelopeError::Decrypt)?;
        self.cipher()
            .decrypt(&Nonce::from(nonce), Payload { msg: ct, aad })
            .map(Zeroizing::new)
            .map_err(|_| EnvelopeError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dek(byte: u8) -> Dek {
        Dek::new(Uuid::from_u128(1), Zeroizing::new([byte; 32]))
    }

    #[test]
    fn seal_open_round_trip() {
        let d = dek(7);
        let pt = b"some secret share bytes";
        let sealed = d.seal(b"aad", pt);
        assert_eq!(sealed.len(), pt.len() + 28, "nonce + tag overhead");
        assert_eq!(&**d.open(b"aad", &sealed).expect("open must succeed"), pt);
    }

    #[test]
    fn nonce_is_fresh() {
        let d = dek(7);
        let a = d.seal(b"aad", b"same");
        let b = d.seal(b"aad", b"same");
        assert_ne!(a[..12], b[..12], "nonces must differ");
        assert_ne!(a, b, "ciphertexts must differ");
    }

    #[test]
    fn wrong_aad_fails() {
        let d = dek(7);
        let sealed = d.seal(b"aad", b"pt");
        assert!(matches!(
            d.open(b"other", &sealed),
            Err(EnvelopeError::Decrypt)
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = dek(7).seal(b"aad", b"pt");
        assert!(matches!(
            dek(8).open(b"aad", &sealed),
            Err(EnvelopeError::Decrypt)
        ));
    }

    fn flipped(region: usize) {
        let d = dek(7);
        let mut sealed = d.seal(b"aad", b"plaintext");
        sealed[region] ^= 1;
        assert!(matches!(
            d.open(b"aad", &sealed),
            Err(EnvelopeError::Decrypt)
        ));
    }

    #[test]
    fn flipped_bit_in_nonce_fails() {
        flipped(0);
    }

    #[test]
    fn flipped_bit_in_ciphertext_fails() {
        flipped(12);
    }

    #[test]
    fn flipped_bit_in_tag_fails() {
        let len = dek(7).seal(b"aad", b"plaintext").len();
        flipped(len - 1);
    }

    #[test]
    fn short_input_fails() {
        let d = dek(7);
        for n in [0, 11, 27] {
            assert!(
                matches!(d.open(b"aad", &vec![0u8; n]), Err(EnvelopeError::Decrypt)),
                "length {n} must fail"
            );
        }
        let sealed = d.seal(b"aad", b"");
        assert_eq!(sealed.len(), 28, "empty plaintext seals to 28 bytes");
        assert!(
            d.open(b"aad", &sealed)
                .expect("open must succeed")
                .is_empty()
        );
    }
}
