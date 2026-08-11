//! Types for on-chain messages.
//!
//! This module defines the events emitted by the blockchain
//! and the contributions submitted in response to these events.
//!
//! Use these types to encode the payloads that nodes send and receive on-chain.

// we need this because the sol macro is angry otherwise

#![allow(
    missing_docs,
    clippy::too_many_arguments,
    clippy::exhaustive_enums,
    reason = "Get lints from sol macro"
)]
use std::fmt;

use alloy::{primitives::U256, sol};
use ark_ff::PrimeField as _;

use crate::{
    chain::{OprfKeyRegistry::OprfKeyRegistryErrors, Verifier::VerifierErrors},
    crypto::{
        EphemeralEncryptionPublicKey, SecretGenCiphertext, SecretGenCiphertexts,
        SecretGenCommitment,
    },
};

sol!(
    #[sol(rpc)]
    library BabyJubJub {
        struct Affine {
            uint256 x;
            uint256 y;
        }
    }

    library OprfKeyGen {
        struct Round1Contribution {
            BabyJubJub.Affine commShare;
            uint256 commCoeffs;
            BabyJubJub.Affine ephPubKey;
        }

        struct Round2Contribution {
            uint256[4] compressedProof;
            SecretGenCiphertext[] ciphers;
        }

        struct SecretGenCiphertext {
            uint256 nonce;
            uint256 cipher;
            BabyJubJub.Affine commitment;
        }
    }

    #[sol(rpc, abi)]
    contract OprfKeyRegistry {
        function addRound1KeyGenContribution(uint160 oprfKeyId, OprfKeyGen.Round1Contribution calldata data) external;
        function addRound1ReshareContribution(uint160 oprfKeyId, OprfKeyGen.Round1Contribution calldata data) external;
        function addRound2Contribution(uint160 oprfKeyId, OprfKeyGen.Round2Contribution calldata data) external;
        function addRound3Contribution(uint160 oprfKeyId) external;
        function checkIsParticipantAndReturnRound2Ciphers(uint160 oprfKeyId) external view returns (OprfKeyGen.SecretGenCiphertext[] memory);
        function getOprfPublicKey(uint160 oprfKeyId) external view returns (BabyJubJub.Affine memory);
        function getPartyIdForParticipant(address participant) external view returns (uint256);
        function loadPeerPublicKeysForConsumers(uint160 oprfKeyId) external view returns (BabyJubJub.Affine[] memory);
        function loadPeerPublicKeysForProducers(uint160 oprfKeyId) external view returns (BabyJubJub.Affine[] memory);
        function numPeers() external view returns (uint16);
        function threshold() external view returns (uint16);

        event KeyDeletion(uint160 indexed oprfKeyId);
        event KeyGenAbort(uint160 indexed oprfKeyId);
        event NotEnoughProducers(uint160 indexed oprfKeyId);
        event ReshareRound1(uint160 indexed oprfKeyId, uint256 threshold, uint32 indexed epoch);
        event ReshareRound3(uint160 indexed oprfKeyId, uint256[] lagrange, uint32 indexed epoch);
        event SecretGenFinalize(uint160 indexed oprfKeyId, uint32 indexed epoch);
        event SecretGenRound1(uint160 indexed oprfKeyId, uint256 threshold);
        event SecretGenRound2(uint160 indexed oprfKeyId, uint32 indexed epoch);
        event SecretGenRound3(uint160 indexed oprfKeyId);
        error AlreadySubmitted();
        error BadContribution();
        error DeletedId(uint160 id);
        error NotAParticipant();
        error NotReady();
        error UnknownId(uint160 id);
        error WrongRound(uint8);
    }
);

sol!(
    #[allow(
        missing_docs,
        clippy::too_many_arguments,
        clippy::exhaustive_structs,
        clippy::exhaustive_enums,
        reason = "Get lints from sol macro"
    )]
    #[derive(Debug, PartialEq, Eq)]
    contract Verifier {
        error PublicInputNotInField();
        error ProofInvalid();

        function verifyCompressedProof(uint256[4] calldata compressedProof, uint256[24] calldata input) public view;

        function verifyProof(uint256[8] calldata proof, uint256[24] calldata input) public view;
    }
);

#[derive(Debug)]
#[non_exhaustive]
/// Errors obtained from on-chain `OprfKeyRegistry` contract and transient contract errors converted to Rust errors.
pub enum RevertError {
    /// Errors from the `OprfKeyRegistry`
    OprfKeyRegistry(OprfKeyRegistryErrors),
    /// Error from the groth16 verifier contract.
    Verifier(VerifierErrors),
}

impl fmt::Display for RevertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RevertError::OprfKeyRegistry(oprf_key_registry_errors) => {
                f.write_str(&format!("{oprf_key_registry_errors}"))
            }
            RevertError::Verifier(verifier_errors) => f.write_str(&format!("{verifier_errors}")),
        }
    }
}

impl fmt::Display for VerifierErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{self:?}"))
    }
}

impl fmt::Display for OprfKeyRegistryErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{self:?}"))
    }
}

impl fmt::Debug for OprfKeyRegistryErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadySubmitted(_) => f.debug_tuple("AlreadySubmitted").finish(),
            Self::BadContribution(_) => f.debug_tuple("BadContribution").finish(),
            Self::DeletedId(_) => f.debug_tuple("DeletedId").finish(),
            Self::NotAParticipant(_) => f.debug_tuple("NotAParticipant").finish(),
            Self::NotReady(_) => f.debug_tuple("NotReady").finish(),
            Self::UnknownId(_) => f.debug_tuple("UnknownId").finish(),
            Self::WrongRound(_) => f.debug_tuple("WrongRound").finish(),
        }
    }
}

impl From<EphemeralEncryptionPublicKey> for BabyJubJub::Affine {
    fn from(value: EphemeralEncryptionPublicKey) -> Self {
        Self::from(value.inner())
    }
}

impl TryFrom<BabyJubJub::Affine> for EphemeralEncryptionPublicKey {
    type Error = eyre::Report;

    fn try_from(value: BabyJubJub::Affine) -> Result<Self, Self::Error> {
        let point = ark_babyjubjub::EdwardsAffine::try_from(value)?;
        Ok(Self::new_unchecked(point))
    }
}

impl TryFrom<BabyJubJub::Affine> for ark_babyjubjub::EdwardsAffine {
    type Error = eyre::Report;

    fn try_from(value: BabyJubJub::Affine) -> Result<Self, Self::Error> {
        let p = Self::new_unchecked(value.x.try_into()?, value.y.try_into()?);
        if !p.is_on_curve() {
            eyre::bail!("point not on curve");
        }
        if !p.is_in_correct_subgroup_assuming_on_curve() {
            eyre::bail!("point not in correct subgroup");
        }
        Ok(p)
    }
}

impl From<ark_babyjubjub::EdwardsAffine> for BabyJubJub::Affine {
    fn from(value: ark_babyjubjub::EdwardsAffine) -> Self {
        Self {
            x: value.x.into(),
            y: value.y.into(),
        }
    }
}

impl From<SecretGenCommitment> for OprfKeyGen::Round1Contribution {
    fn from(value: SecretGenCommitment) -> Self {
        Self {
            commShare: value.comm_share.into(),
            commCoeffs: value.comm_coeffs.into(),
            ephPubKey: value.eph_pub_key.into(),
        }
    }
}

impl From<EphemeralEncryptionPublicKey> for OprfKeyGen::Round1Contribution {
    fn from(value: EphemeralEncryptionPublicKey) -> Self {
        Self {
            // zero values indicate to the smart contract that we are a consumer
            commShare: BabyJubJub::Affine {
                x: U256::ZERO,
                y: U256::ZERO,
            },
            commCoeffs: U256::ZERO,
            ephPubKey: value.into(),
        }
    }
}

impl From<SecretGenCiphertext> for OprfKeyGen::SecretGenCiphertext {
    fn from(value: SecretGenCiphertext) -> Self {
        Self {
            nonce: value.nonce.into(),
            cipher: value.cipher.into(),
            commitment: value.commitment.into(),
        }
    }
}

impl TryFrom<OprfKeyGen::SecretGenCiphertext> for SecretGenCiphertext {
    type Error = eyre::Report;

    fn try_from(value: OprfKeyGen::SecretGenCiphertext) -> Result<Self, Self::Error> {
        Ok(Self {
            nonce: value.nonce.try_into()?,
            cipher: value.cipher.try_into()?,
            commitment: value.commitment.try_into()?,
        })
    }
}

impl From<SecretGenCiphertexts> for OprfKeyGen::Round2Contribution {
    fn from(value: SecretGenCiphertexts) -> Self {
        Self {
            compressedProof: groth16_sol::prepare_compressed_proof(&value.proof.into()),
            ciphers: value.ciphers.into_iter().map(Into::into).collect(),
        }
    }
}

/// Converts a `U256` into a `Fr` element of the `BabyJubJub` scalar field.
///
/// Checks that the input fits within the field modulus. Returns an error
/// if the value is too large.
///
/// This function exists because of Rust's orphan rules: we cannot implement
/// `From<U256>` for `ark_babyjubjub::Fr` directly.
///
/// # Errors
///
/// Returns an `eyre::Report` if the input value does not fit into the
/// `BabyJubJub` scalar field.
pub fn try_u256_into_bjj_fr(value: U256) -> eyre::Result<ark_babyjubjub::Fr> {
    let big_int = ark_ff::BigInt(value.into_limbs());
    if ark_babyjubjub::Fr::MODULUS <= big_int {
        eyre::bail!("{value} doesn't fit into requested prime field");
    }
    Ok(ark_babyjubjub::Fr::new(big_int))
}
