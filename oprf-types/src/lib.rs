#![deny(missing_docs)]
#![deny(clippy::all, clippy::pedantic)]
#![deny(
    clippy::allow_attributes_without_reason,
    clippy::assertions_on_result_states,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::exhaustive_enums,
    clippy::iter_over_hash_type,
    clippy::let_underscore_must_use,
    clippy::missing_assert_message,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_safety_comment,
    clippy::unwrap_used
)]
#![allow(
    clippy::exhaustive_structs,
    reason = "If we change the structs we would need a breaking change because the API changed anyways"
)]
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

pub use ark_babyjubjub;
pub use async_trait;

pub mod api;
pub mod chain;
pub mod crypto;

/// Represents an epoch for the `DLog` secret-share.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct ShareEpoch(u32);

/// The id of a relying party.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OprfKeyId(U160);

impl ShareEpoch {
    /// Converts the key epoch to an u32
    #[must_use]
    pub fn into_inner(self) -> u32 {
        self.0
    }

    /// Creates a new `ShareEpoch` by wrapping a `u32`
    #[must_use]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns `true` iff this epoch is the 0 epoch.
    #[must_use]
    pub fn is_initial_epoch(&self) -> bool {
        self.0 == 0
    }

    /// Returns the previous epoch. If already initial epoch, returns `self`.
    #[must_use]
    pub fn prev(self) -> ShareEpoch {
        if self.is_initial_epoch() {
            self
        } else {
            Self(self.0 - 1)
        }
    }

    /// Returns the next epoch.
    ///
    /// # Panics
    /// If called on epoch `u32::MAX`.
    #[must_use]
    pub fn next(self) -> ShareEpoch {
        assert!(self.0 != u32::MAX, "epoch is already max");
        Self(self.0 + 1)
    }
}

impl OprfKeyId {
    /// Converts the RP id to an u128
    #[must_use]
    pub fn into_inner(self) -> U160 {
        self.0
    }

    /// Creates a new `OprfKeyId` by wrapping a `U160`
    #[must_use]
    pub fn new(value: U160) -> Self {
        Self(value)
    }

    /// Converts the `OprfKeyId` to bytes in little-endian form
    #[inline]
    #[must_use]
    pub fn to_le_bytes(&self) -> Vec<u8> {
        self.into_inner().to_le_bytes_vec()
    }

    /// Creates a new `OprfKeyId` from a slice of bytes in little-endian form.
    ///
    /// # Panics
    /// Panics if the value is larger than the underlying [`U160`].
    #[inline]
    #[must_use]
    pub fn from_le_slice(b: &[u8]) -> Self {
        OprfKeyId(U160::from_le_slice(b))
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
        // This can't happen with the current implementation, but still we want to take extra care. If e.g., someone promotes the underlying primitive type from uint160 to uint256, this might happen without realizing which would be a nasty bug.
        assert!(
            ark_babyjubjub::Fq::MODULUS > big_int,
            "Field element larger than bjj-basefield"
        );
        ark_babyjubjub::Fq::new(big_int)
    }
}

impl From<u32> for ShareEpoch {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<ShareEpoch> for i64 {
    fn from(value: ShareEpoch) -> Self {
        i64::from(value.0)
    }
}

macro_rules! from_impl {
    ($($type:ty),+ $(,)?) => {
        $(
            impl From<$type> for OprfKeyId {
                fn from(value: $type) -> Self {
                    Self(U160::from(value))
                }
            }
        )+
    };
}

from_impl!(usize, u8, u16, u32, u64, u128);
