//! Common cryptographic types used in the OPRF-nullifier service.
//!
//! This module defines the public keys, identifiers, commitments and
//! ciphertext structures exchanged between participants in the OPRF-
//! nullifier service.
//!
//! Main types:
//! * [`PartyId`]
//! * [`EphemeralEncryptionPublicKey`]
//! * [`OprfPublicKey`]
//! * [`SecretGenCommitment`]
//! * [`SecretGenCiphertexts`] / [`SecretGenCiphertext`]

use std::fmt;

use ark_serde_compat::babyjubjub;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use circom_types::{ark_bn254::Bn254, groth16::Proof};
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use serde::{Deserialize, Serialize};

use crate::{ShareEpoch, api::OprfPublicKeyWithEpoch};

/// The party id of the OPRF node.
#[derive(Debug, Clone, Serialize, Deserialize, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartyId(pub u16);

/// The ephemeral public key of an OPRF node.
///
/// Can only be constructed if on curve and on correct subgroup.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Hash, PartialEq, Eq)]
#[serde(transparent)]
pub struct EphemeralEncryptionPublicKey(
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    ark_babyjubjub::EdwardsAffine,
);

/// The OPRF public-key.
///
/// Constructed by multiplying the BabyJubJub generator with the secret shared among the OPRF nodes.
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
#[serde(transparent)]
pub struct OprfPublicKey(
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    ark_babyjubjub::EdwardsAffine,
);

/// The public contribution of one OPRF node for the first round of the OPRF-nullifier generation protocol.
///
/// Contains the public commitments to the random share and the
/// polynomial. Additionally, contains an ephemeral public key for this
/// key-generation. Nodes should use this public key to encrypt the ciphertexts
/// for round2.
///
/// See [Appendix B.2 of our design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf)
/// for more information about the OPRF-nullifier generation protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenCommitment {
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    /// The commitment to the random value sampled by the node.
    pub comm_share: ark_babyjubjub::EdwardsAffine,
    #[serde(serialize_with = "babyjubjub::serialize_fq")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fq")]
    /// The commitment to the polynomial used to hide the sampled secret.
    pub comm_coeffs: ark_babyjubjub::Fq,
    /// The ephemeral public key for this key generation.
    pub eph_pub_key: EphemeralEncryptionPublicKey,
}

/// The public contribution of one OPRF node for the second round of the OPRF-nullifier generation protocol.
///
/// Contains ciphertexts for all OPRF nodes (including the node itself) with the evaluations
/// of the polynomial generated in the first round. The ciphertexts of the nodes
/// is sorted according to their respective party ID.  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenCiphertexts {
    /// The proof that the ciphertexts were computed correctly
    pub proof: Proof<Bn254>,
    /// All ciphers for nodes (including node itself).
    pub ciphers: Vec<SecretGenCiphertext>,
}

/// A ciphertext for an OPRF node used in round 2 of the OPRF-nullifier generation protocol.
///
/// Contains the [`EphemeralEncryptionPublicKey`] of the sender, the ciphertext itself, and a nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenCiphertext {
    #[serde(serialize_with = "babyjubjub::serialize_fq")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fq")]
    /// The nonce used during encryption.
    pub nonce: ark_babyjubjub::Fq,
    #[serde(serialize_with = "babyjubjub::serialize_fq")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fq")]
    /// The ciphertext.
    pub cipher: ark_babyjubjub::Fq,
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    /// The commitment to the encrypted value. Computed as xG, where x
    /// is the plaintext and G the generator of BabyJubJub.
    pub commitment: ark_babyjubjub::EdwardsAffine,
}

impl PartyId {
    /// Converts to a `u16`.
    pub fn into_inner(self) -> u16 {
        self.0
    }
}

impl From<ark_babyjubjub::EdwardsAffine> for OprfPublicKey {
    fn from(value: ark_babyjubjub::EdwardsAffine) -> Self {
        Self(value)
    }
}

impl OprfPublicKey {
    /// Create a new `NullifierKey` by wrapping an BabyJubJub Point.
    pub fn new(value: ark_babyjubjub::EdwardsAffine) -> Self {
        Self::from(value)
    }

    /// Gets the inner value (a BabyJubJub point in Affine representation).
    pub fn inner(self) -> ark_babyjubjub::EdwardsAffine {
        self.0
    }
}

impl EphemeralEncryptionPublicKey {
    /// Create a new `EphemeralEncryptionPublicKey` by wrapping an BabyJubJub Point.
    ///
    /// Checks if the the point is on the curve and in correct subgroup.
    /// Returns an error iff those checks fail.
    pub fn new(value: ark_babyjubjub::EdwardsAffine) -> eyre::Result<Self> {
        Self::try_from(value)
    }

    /// Create a new `EphemeralEncryptionPublicKey` by wrapping an BabyJubJub Point.
    ///
    /// Does **not** check if the the point is on the curve and in correct subgroup.
    /// Only use this function if you know what you are doing.
    /// Prefer [`Self::new`].
    pub fn new_unchecked(value: ark_babyjubjub::EdwardsAffine) -> Self {
        Self(value)
    }

    /// Gets the inner value (a BabyJubJub point in Affine representation).
    pub fn inner(self) -> ark_babyjubjub::EdwardsAffine {
        self.0
    }
}

impl TryFrom<ark_babyjubjub::EdwardsAffine> for EphemeralEncryptionPublicKey {
    type Error = eyre::Report;

    fn try_from(value: ark_babyjubjub::EdwardsAffine) -> Result<Self, Self::Error> {
        if !value.is_on_curve() {
            eyre::bail!("PublicKey is not on curve!");
        }
        if !value.is_in_correct_subgroup_assuming_on_curve() {
            eyre::bail!("PublicKey is not in correct subgroup!");
        }
        Ok(Self(value))
    }
}

impl fmt::Display for OprfPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("OprfPublicKey({})", self.0))
    }
}

impl fmt::Display for EphemeralEncryptionPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("EphemeralEncryptionPublicKey({})", self.0))
    }
}

impl SecretGenCiphertexts {
    /// Creates a new instance by wrapping the provided value.
    pub fn new(proof: Proof<Bn254>, ciphers: Vec<SecretGenCiphertext>) -> Self {
        Self { proof, ciphers }
    }
}

impl SecretGenCiphertext {
    /// Creates a new ciphertext contribution for an OPRF node by wrapping a nonce, a ciphertext and a commitment to the plain text.
    pub fn new(
        cipher: ark_babyjubjub::Fq,
        commitment: ark_babyjubjub::EdwardsAffine,
        nonce: ark_babyjubjub::Fq,
    ) -> Self {
        Self {
            nonce,
            cipher,
            commitment,
        }
    }
}

impl fmt::Display for PartyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("PartyId({})", self.0))
    }
}

impl From<u16> for PartyId {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<PartyId> for u16 {
    fn from(value: PartyId) -> Self {
        value.0
    }
}

/// The cryptographic material for one OPRF key.
///
/// Stores:
/// * The [`DLogShareShamir`].
/// * The [`OprfPublicKey`].
/// * The [`ShareEpoch`].
#[derive(Clone, Serialize, Deserialize)]
pub struct OprfKeyMaterial {
    share: DLogShareShamir,
    oprf_public_key: OprfPublicKey,
    epoch: ShareEpoch,
}

impl OprfKeyMaterial {
    /// Creates a new [`OprfKeyMaterial`] from the provided [`DLogShareShamir`], [`OprfPublicKey`], and [`ShareEpoch`].
    pub fn new(share: DLogShareShamir, oprf_public_key: OprfPublicKey, epoch: ShareEpoch) -> Self {
        Self {
            share,
            oprf_public_key,
            epoch,
        }
    }

    /// Returns the latest [`ShareEpoch`].
    pub fn epoch(&self) -> ShareEpoch {
        self.epoch
    }

    /// Returns the [`DLogShareShamir`] for the given epoch, or `None` if not found.
    pub fn share(&self) -> DLogShareShamir {
        self.share.clone()
    }

    /// Returns `true` iff the the material contains the requested epoch.
    pub fn is_epoch(&self, epoch: ShareEpoch) -> bool {
        self.epoch == epoch
    }

    /// Returns the [`OprfPublicKey`].
    pub fn public_key(&self) -> OprfPublicKey {
        self.oprf_public_key
    }

    /// Returns the [`OprfPublicKeyWithEpoch`].
    pub fn public_key_with_epoch(&self) -> OprfPublicKeyWithEpoch {
        OprfPublicKeyWithEpoch {
            key: self.oprf_public_key,
            epoch: self.epoch,
        }
    }
}
