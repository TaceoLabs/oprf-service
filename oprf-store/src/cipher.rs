//! AES-256-GCM sealing and opening of stored bytes with a data encryption key.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, KeyInit, Payload},
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::EnvelopeError;

const NONCE_LEN: usize = 12;

/// A data encryption key (DEK) with its identifier.
///
/// Seals and opens stored bytes laid out as `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
/// The key is never exposed or printed. It is held as the keyed cipher, which the `zeroize`
/// feature of `aes-gcm` wipes on drop, and boxed so that moving a `Dek` copies no key material.
pub struct Dek {
    id: Uuid,
    cipher: Box<Aes256Gcm>,
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
    pub fn new(id: Uuid, key: &[u8; 32]) -> Self {
        Self {
            id,
            cipher: Box::new(Aes256Gcm::new(key.into())),
        }
    }

    /// The identifier of this data key.
    #[must_use]
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Encrypts `plaintext` bound to `aad` under a fresh random nonce.
    ///
    /// Returns `nonce || ciphertext || tag`.
    ///
    /// # Panics
    ///
    /// Panics if the operating system RNG fails or the plaintext exceeds the AES-GCM size limit.
    #[must_use]
    pub(crate) fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        // Drawn from the operating system RNG (`getrandom`).
        let nonce = Nonce::generate();
        let ct = self
            .cipher
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
    pub(crate) fn open(
        &self,
        aad: &[u8],
        stored: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        let (nonce, ct) = stored
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(EnvelopeError::Decrypt)?;
        self.cipher
            .decrypt(nonce.into(), Payload { msg: ct, aad })
            .map(Zeroizing::new)
            .map_err(|_| EnvelopeError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dek(byte: u8) -> Dek {
        Dek::new(Uuid::from_u128(1), &[byte; 32])
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

    /// Known-answer test of the stored layout `nonce || ciphertext || tag`.
    ///
    /// Produced with OpenSSL's `EVP_aes_256_gcm` (libcrypto 4.1, called from Python via
    /// `ctypes`), not with this crate; the same harness reproduces test case 16
    /// of the original GCM specification (AES-256 with AAD).
    #[test]
    fn open_known_answer() {
        let key = std::array::from_fn(|i| u8::try_from(i).expect("index fits into u8"));
        let d = Dek::new(Uuid::from_u128(1), &key);
        let aad = b"taceo-oprf-store kat aad";
        let nonce = [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
        ];
        let ciphertext = [
            0x92, 0x79, 0x1f, 0x48, 0x2a, 0xe6, 0x6d, 0xcf, 0x10, 0x03, 0xaa, 0xa0, 0x73, 0x15,
            0xb2, 0xbb, 0x50, 0xc7, 0x37, 0x7f, 0xe5, 0xd9, 0x62, 0x0d, 0xf2, 0x7d, 0x51, 0xe3,
            0x0d,
        ];
        let tag = [
            0xa7, 0x92, 0xb9, 0x2e, 0x30, 0xfa, 0x78, 0x1e, 0xcd, 0x2d, 0x2b, 0x87, 0xc0, 0x21,
            0xaf, 0x09,
        ];
        let stored = [&nonce[..], &ciphertext, &tag].concat();
        assert_eq!(
            d.open(aad, &stored).expect("open must succeed").as_slice(),
            b"taceo-oprf-store known answer",
            "known answer"
        );
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
