#![deny(missing_docs)]
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
