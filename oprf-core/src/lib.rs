#![deny(missing_docs)]
#![deny(clippy::all, clippy::pedantic)]
#![deny(
    clippy::allow_attributes_without_reason,
    clippy::assertions_on_result_states,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
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
    clippy::many_single_char_names,
    reason = "implementing an crypto RFC is bound to use single char names"
)]
//! This crate implements privacy-preserving protocols for verifiable, threshold, and distributed Oblivious Pseudorandom Functions (OPRF) using elliptic curves.
//!
//! Modules include:
//! - **keygen**: Distributed key generation and secret-sharing utilities.
//! - **oprf**: Blinded OPRF protocol types and client/server operations.
//! - **`dlog_equality`**: Chaum-Pedersen proofs for discrete log equality.
//! - **shamir**: Shamir polynomial secret sharing over finite fields.
pub mod ddlog_equality;
pub mod dlog_equality;
pub mod keygen;
pub mod oprf;
pub mod shamir;
