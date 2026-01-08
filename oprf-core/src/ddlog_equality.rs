//! Distributed DLogEquality Proof Commitments for Threshold OPRF
//!
//! This module defines the core types and helpers for constructing distributed (threshold) Chaum-Pedersen
//! discrete log equality proofs. Each participating party generates commitment shares and proof shares that
//! are then aggregated to produce a non-interactive zero-knowledge proof demonstrating that two points share
//! the same discrete logarithm.
//!
//! The primitives defined here are agnostic to the underlying threshold sharing scheme and are used by both
//! additive and Shamir variants, which are implemented in their respective submodules `additive` and `shamir`.
//!
//! This module provides:
//! - Per-party commitment structures for partial commitment (nonce splits and result share).
//! - Aggregation mechanisms to combine commitments from all parties, forming the input to the proof challenge hash.
//! - Proof share creation and combination into a joint (aggregated) proof.
//! - Deterministic nonce recombination using a domain-separated hash function.
//!
//! Secret randomness is never clonable, and session types deliberately do not implement `Debug` to avoid accidental leakage.
use crate::{
    dlog_equality::DLogEqualityProof,
    oprf::{Affine, ScalarField},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_serde_compat::babyjubjub;
use ark_serialize::CanonicalSerialize;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

#[cfg(feature = "additive")]
pub mod additive;
pub mod shamir;

const FROST_2_NONCE_COMBINER_LABEL: &[u8] = b"FROST_2_NONCE_COMBINER";

/// Per-party commitments to the distributed DLogEquality proof protocol.
///
/// Each party sends these commitments, which consist of a split of the actual response and two nonce splits, for aggregation and creation of the global challenge hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialDLogEqualityCommitments {
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    pub(crate) c: Affine, // The share of the actual result C=B*x
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    /// The share of G*d1, the first part of the two-nonce commitment to the randomness r1 = d1 + e1*b
    pub(crate) d1: Affine,
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    /// The share of G*d2, the first part of the two-nonce commitment to the randomness r2 = d2 + e2*b
    pub(crate) d2: Affine,
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    /// The share of G*e1, the second part of the two-nonce commitment to the randomness r1 = d1 + e1*b
    pub(crate) e1: Affine,
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    /// The share of G*e2, the second part of the two-nonce commitment to the randomness r2 = d2 + e2*b
    pub(crate) e2: Affine,
}

/// Aggregated commitments for the distributed DLogEquality proof protocol.
///
/// This struct aggregates the per-party commitment shares, to be used as the challenge hash input, and to verify against the full proof after all shares are combined.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DLogEqualityCommitments {
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    pub(crate) c: Affine,
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    /// The aggregated G*d1.
    pub(crate) d1: Affine,
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    /// The aggregated G*d2.
    pub(crate) d2: Affine,
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    /// The aggregated G*e1.
    pub(crate) e1: Affine,
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    /// The aggregated G*e2.
    pub(crate) e2: Affine,
    /// The parties that contributed to this commitment.
    pub(crate) contributing_parties: Vec<u16>,
}

/// Individual party's proof share for the DLogEquality protocol.
/// Carries a response share for the Chaum-Pedersen protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct DLogEqualityProofShare(
    // The share of the response s
    #[serde(serialize_with = "babyjubjub::serialize_fr")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fr")]
    pub(crate) ScalarField,
);

/// The internal storage of a party in a distributed DlogEqualityProof protocol.
///
/// This is not `Clone` because it contains secret randomness that may only be used once. We also don't implement `Debug` so we do don't print it by accident.
/// The `challenge` method consumes the session.
#[derive(ZeroizeOnDrop)]
pub struct DLogEqualitySession {
    pub(crate) d: ScalarField,
    pub(crate) e: ScalarField,
    pub(crate) blinded_query: Affine,
}

impl DLogEqualitySession {
    /// Computes C=B·x_share and commitments to two random values d_share and e_share, which will be the shares of the randomness used in the DlogEqualityProof.
    /// The result is meant to be sent to one accumulating party (e.g., the verifier) who combines all the shares of all parties and creates the challenge hash.
    pub fn partial_commitments(
        b: Affine,
        x_share: ScalarField,
        rng: &mut (impl CryptoRng + Rng),
    ) -> (Self, PartialDLogEqualityCommitments) {
        let d_share = ScalarField::rand(rng);
        let e_share = ScalarField::rand(rng);
        let d1 = (Affine::generator() * d_share).into_affine();
        let e1 = (Affine::generator() * e_share).into_affine();
        let d2 = (b * d_share).into_affine();
        let e2 = (b * e_share).into_affine();
        let c_share = (b * x_share).into_affine();

        let comm = PartialDLogEqualityCommitments {
            c: c_share,
            d1,
            d2,
            e1,
            e2,
        };

        let session = DLogEqualitySession {
            d: d_share,
            e: e_share,
            blinded_query: b,
        };

        (session, comm)
    }
}

impl DLogEqualityCommitments {
    /// Combine all parties' proof shares into a single Chaum-Pedersen proof object.
    ///
    /// Must use the same order of contributing parties as in aggregation
    pub(crate) fn combine_proofs<'a>(
        self,
        session_id: Uuid,
        proofs: impl Iterator<Item = &'a DLogEqualityProofShare>,
        a: Affine,
        b: Affine,
    ) -> DLogEqualityProof {
        let mut s = ScalarField::zero();
        for proof in proofs {
            s += proof.0;
        }
        let (r1, r2, _) = combine_two_nonce_randomness(
            session_id,
            a,
            self.c,
            self.d1,
            self.d2,
            self.e1,
            self.e2,
            &self.contributing_parties,
        );

        let d = Affine::generator();
        let e = crate::dlog_equality::challenge_hash(a, b, self.c, d, r1, r2);

        DLogEqualityProof { e, s }
    }
}

#[allow(clippy::too_many_arguments)]
/// Combines the two-nonce randomness shares into the full randomness used in the challenge.
/// Returns (r1, r2, b) where r1 = d1 + e1*b and r2 = d2 + e2*b
pub(crate) fn combine_two_nonce_randomness(
    session_id: Uuid,
    public_key: Affine,
    oprf_output: Affine,
    d1: Affine,
    d2: Affine,
    e1: Affine,
    e2: Affine,
    parties: &[u16],
) -> (Affine, Affine, ScalarField) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FROST_2_NONCE_COMBINER_LABEL);
    hasher.update(session_id.as_bytes());
    for party in parties {
        hasher.update(&party.to_le_bytes());
    }
    let mut buf = Vec::with_capacity(d1.compressed_size());

    // serialize an Affine point in canonical compressed form
    let mut serialize_point = |point: &Affine| {
        point
            .serialize_compressed(&mut buf)
            .expect("can serialize point into a vec");
        hasher.update(&buf);
        buf.clear();
    };
    serialize_point(&public_key);
    serialize_point(&oprf_output);
    serialize_point(&d1);
    serialize_point(&d2);
    serialize_point(&e1);
    serialize_point(&e2);

    let mut hash_output = hasher.finalize_xof();

    // We use 64 bytes to have enough statistical security against modulo bias
    let mut unreduced_b = [0u8; 64];
    hash_output.fill(&mut unreduced_b);

    let b = ScalarField::from_le_bytes_mod_order(&unreduced_b);
    let r1 = d1 + e1 * b;
    let r2 = d2 + e2 * b;
    (r1.into_affine(), r2.into_affine(), b)
}
