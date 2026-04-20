//! Types for on-chain messages.
//!
//! This module defines the events emitted by the blockchain
//! and the contributions submitted in response to these events.
//!
//! Use these types to encode the payloads that nodes send and receive on-chain.

// we need this because the sol macro is angry otherwise

#![allow(missing_docs, reason = "Get this error from sol macro")]
use std::fmt;

use alloy::{primitives::U256, sol};
use ark_ff::PrimeField as _;

use crate::{
    chain::{
        OprfKeyRegistry::{KeyGenConfirmation, OprfKeyRegistryErrors},
        Verifier::VerifierErrors,
    },
    crypto::{
        EphemeralEncryptionPublicKey, SecretGenCiphertext, SecretGenCiphertexts,
        SecretGenCommitment,
    },
};

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(
        clippy::too_many_arguments,
        clippy::exhaustive_enums,
        reason = "Get lints from sol macro"
    )]
    #[sol(rpc)]
    OprfKeyRegistry,
    "./OprfKeyRegistry.json"
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

impl fmt::Debug for KeyGenConfirmation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyGenConfirmation")
            .field("oprfKeyId", &self.oprfKeyId)
            .field("party_id", &self.partyId)
            .field("round", &self.round)
            .field("epoch", &self.epoch)
            .finish()
    }
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
            Self::PartiesNotDistinct(_) => f.debug_tuple("PartiesNotDistinct").finish(),
            Self::AddressEmptyCode(_) => f.debug_tuple("AddressEmptyCode").finish(),
            Self::AlreadySubmitted(_) => f.debug_tuple("AlreadySubmitted").finish(),
            Self::BadContribution(_) => f.debug_tuple("BadContribution").finish(),
            Self::DeletedId(_) => f.debug_tuple("DeletedId").finish(),
            Self::ERC1967InvalidImplementation(_) => {
                f.debug_tuple("ERC1967InvalidImplementation").finish()
            }
            Self::ERC1967NonPayable(_) => f.debug_tuple("ERC1967NonPayable").finish(),
            Self::FailedCall(_) => f.debug_tuple("FailedCall").finish(),
            Self::ImplementationNotInitialized(_) => {
                f.debug_tuple("ImplementationNotInitialized").finish()
            }
            Self::InvalidInitialization(_) => f.debug_tuple("InvalidInitialization").finish(),
            Self::LastAdmin(_) => f.debug_tuple("LastAdmin").finish(),
            Self::NotAParticipant(_) => f.debug_tuple("NotAParticipant").finish(),
            Self::NotAProducer(_) => f.debug_tuple("NotAProducer").finish(),
            Self::NotInitializing(_) => f.debug_tuple("NotInitializing").finish(),
            Self::NotReady(_) => f.debug_tuple("NotReady").finish(),
            Self::OnlyAdmin(_) => f.debug_tuple("OnlyAdmin").finish(),
            Self::OwnableInvalidOwner(_) => f.debug_tuple("OwnableInvalidOwner").finish(),
            Self::OwnableUnauthorizedAccount(_) => {
                f.debug_tuple("OwnableUnauthorizedAccount").finish()
            }
            Self::UUPSUnauthorizedCallContext(_) => {
                f.debug_tuple("UUPSUnauthorizedCallContext").finish()
            }
            Self::UUPSUnsupportedProxiableUUID(_) => {
                f.debug_tuple("UUPSUnsupportedProxiableUUID").finish()
            }
            Self::UnexpectedAmountPeers(_) => f.debug_tuple("UnexpectedAmountPeers").finish(),
            Self::UnknownId(_) => f.debug_tuple("UnknownId").finish(),
            Self::UnsupportedNumPeersThreshold(_) => {
                f.debug_tuple("UnsupportedNumPeersThreshold").finish()
            }
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
