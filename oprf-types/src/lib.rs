#![deny(missing_docs)]
//! Core type definitions for the OPRF service and client.
//!
//! This crate groups together the strongly-typed values and message
//! structures used across the OPRF system. It provides:
//!
//! * Thin wrappers around primitive values such as epochs, relying-party
//!   identifiers, and Merkle roots, with consistent serialization and
//!   display implementations.
//! * Cryptographic types used in the OPRF protocol (see [`crypto`] module).
//! * On-chain contribution types exchanged during key generation (see
//!   [`chain`] module).
//! * API versioned types for client/server communication (see [`api`] module).
//!
//! Use these types to pass, store, and (de)serialize identifiers and
//! cryptographic values in a type-safe way throughout your application.

use std::fmt;

use alloy::primitives::{U160, U256};
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};

/// Re-export async-trait for convenience.
pub use async_trait;

pub mod api;
pub mod chain;
pub mod crypto;

/// Represents an epoch for the DLog secret-share.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct ShareEpoch(u128);

/// The id of a relying party.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OprfKeyId(U160);

impl ShareEpoch {
    /// Converts the key epoch to an u128
    pub fn into_inner(self) -> u128 {
        self.0
    }

    /// Creates a new `ShareEpoch` by wrapping a `u128`
    pub fn new(value: u128) -> Self {
        Self(value)
    }

    /// Returns `true` iff this epoch is the 0 epoch.
    pub fn is_initial_epoch(&self) -> bool {
        self.0 == 0
    }

    /// Returns the previous epoch. If already initial epoch, returns `self`.
    pub fn prev(self) -> ShareEpoch {
        if self.is_initial_epoch() {
            self
        } else {
            Self(self.0 - 1)
        }
    }

    /// Returns the next epoch.
    pub fn next(self) -> ShareEpoch {
        Self(self.0 + 1)
    }
}

impl OprfKeyId {
    /// Converts the RP id to an u128
    pub fn into_inner(self) -> U160 {
        self.0
    }

    /// Creates a new `OprfKeyId` by wrapping a `U160`
    pub fn new(value: U160) -> Self {
        Self(value)
    }
}

impl From<U160> for OprfKeyId {
    fn from(value: U160) -> Self {
        Self(value)
    }
}

impl fmt::Display for OprfKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{}", self.0))
    }
}

impl fmt::Display for ShareEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string())
    }
}

impl From<OprfKeyId> for ark_babyjubjub::Fq {
    fn from(value: OprfKeyId) -> Self {
        let u256 = U256::from(value.0);
        let big_int = ark_ff::BigInt(u256.into_limbs());
        // Explicitly check if value is larger than modulus.
        if ark_babyjubjub::Fq::MODULUS <= big_int {
            // This can't happen with the current implementation, but still we want to take extra care. If e.g., someone promotes the underlying primitive type from uint160 to uint256, this might happen without realizing which would be a nasty bug.
            panic!("Field element larger than bjj-basefield")
        }
        ark_babyjubjub::Fq::new(big_int)
    }
}

impl From<u128> for ShareEpoch {
    fn from(value: u128) -> Self {
        Self(value)
    }
}
