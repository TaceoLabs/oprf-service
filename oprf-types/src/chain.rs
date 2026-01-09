//! Types for on-chain messages.
//!
//! This module defines the events emitted by the blockchain
//! and the contributions submitted in response to these events.
//!
//! Use these types to encode the payloads that nodes send and receive on-chain.

use std::fmt;

use alloy::{primitives::U256, sol};
use ark_ff::PrimeField as _;
use serde::{Deserialize, Serialize};

use crate::{
    OprfKeyId,
    chain::OprfKeyRegistry::{KeyGenConfirmation, OprfKeyRegistryErrors},
    crypto::{
        EphemeralEncryptionPublicKey, SecretGenCiphertext, SecretGenCiphertexts,
        SecretGenCommitment,
    },
};

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc)]
    OprfKeyRegistry,
    "./OprfKeyRegistry.json"
);

impl fmt::Debug for KeyGenConfirmation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransactionConfirmation")
            .field("oprfKeyId", &self.oprfKeyId)
            .field("party_id", &self.partyId)
            .field("round", &self.round)
            .field("epoch", &self.epoch)
            .finish()
    }
}

impl fmt::Debug for OprfKeyRegistryErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
            Self::OutdatedNullifier(_) => f.debug_tuple("OutdatedNullifier").finish(),
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
            Self::PartiesNotDistinct(_) => f.debug_tuple("PartiesNotDistinct").finish(),
        }
    }
}

/// A first-round key-generation contribution submitted on-chain.
///
/// Contains the relying-party identifier, the sending node’s identifier,
/// and its first-round [`SecretGenCommitment`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound1Contribution {
    /// Identifier of key this contribution belongs to.
    pub oprf_key_id: OprfKeyId,
    /// The node’s first-round commitment.
    pub contribution: SecretGenCommitment,
}

/// A second-round key-generation contribution submitted on-chain.
///
/// Contains the relying-party identifier, the sending node’s identifier,
/// and its second-round [`SecretGenCiphertexts`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound2Contribution {
    /// Identifier this contribution belongs to.
    pub oprf_key_id: OprfKeyId,
    /// The node’s second-round ciphertexts.
    pub contribution: SecretGenCiphertexts,
}

/// A finalization message for key generation submitted on-chain.
///
/// Contains only the relying-party identifier. Finalize simply notifies
/// everyone that the sending node successfully computed its share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound3Contribution {
    /// Identifier this contribution belongs to.
    pub oprf_key_id: OprfKeyId,
}

impl From<EphemeralEncryptionPublicKey> for Types::BabyJubJubElement {
    fn from(value: EphemeralEncryptionPublicKey) -> Self {
        Self::from(value.inner())
    }
}

impl TryFrom<Types::BabyJubJubElement> for EphemeralEncryptionPublicKey {
    type Error = eyre::Report;

    fn try_from(value: Types::BabyJubJubElement) -> Result<Self, Self::Error> {
        let point = ark_babyjubjub::EdwardsAffine::try_from(value)?;
        Ok(Self::new_unchecked(point))
    }
}

impl TryFrom<Types::BabyJubJubElement> for ark_babyjubjub::EdwardsAffine {
    type Error = eyre::Report;

    fn try_from(value: Types::BabyJubJubElement) -> Result<Self, Self::Error> {
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

impl From<ark_babyjubjub::EdwardsAffine> for Types::BabyJubJubElement {
    fn from(value: ark_babyjubjub::EdwardsAffine) -> Self {
        Self {
            x: value.x.into(),
            y: value.y.into(),
        }
    }
}

impl From<SecretGenCommitment> for Types::Round1Contribution {
    fn from(value: SecretGenCommitment) -> Self {
        Self {
            commShare: value.comm_share.into(),
            commCoeffs: value.comm_coeffs.into(),
            ephPubKey: value.eph_pub_key.inner().into(),
        }
    }
}

impl From<SecretGenCiphertext> for Types::SecretGenCiphertext {
    fn from(value: SecretGenCiphertext) -> Self {
        Self {
            nonce: value.nonce.into(),
            cipher: value.cipher.into(),
            commitment: value.commitment.into(),
        }
    }
}

impl TryFrom<Types::SecretGenCiphertext> for SecretGenCiphertext {
    type Error = eyre::Report;

    fn try_from(value: Types::SecretGenCiphertext) -> Result<Self, Self::Error> {
        Ok(Self {
            nonce: value.nonce.try_into()?,
            cipher: value.cipher.try_into()?,
            commitment: value.commitment.try_into()?,
        })
    }
}

impl From<SecretGenCiphertexts> for Types::Round2Contribution {
    fn from(value: SecretGenCiphertexts) -> Self {
        Self {
            compressedProof: groth16_sol::prepare_compressed_proof(&value.proof.into()),
            ciphers: value.ciphers.into_iter().map(Into::into).collect(),
        }
    }
}

/// Tries to convert an u256 into a value on the scalar field of babyjubjub.
/// We need this function because of orphan rule.
pub fn try_u256_into_bjj_fr(value: U256) -> eyre::Result<ark_babyjubjub::Fr> {
    let big_int = ark_ff::BigInt(value.into_limbs());
    if ark_babyjubjub::Fr::MODULUS <= big_int {
        eyre::bail!("{value} doesn't fit into requested prime field");
    }
    Ok(ark_babyjubjub::Fr::new(big_int))
}
