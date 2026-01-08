//! Additive Secret Sharing variant of distributed DLogEquality proof combination.
//!
//! This module implements the distributed Chaum-Pedersen discrete log equality proof for the
//! simple additive secret sharing scenario. All parties collaborate using additive shares of
//! the underlying secret and nonces, allowing for straightforward aggregation of commitments
//! and proof shares via simple arithmetic without interpolation.
//!
//! This variant is efficient when all parties are required for reconstruction and no threshold security is needed:
//! - Commitment and proof aggregation is performed via direct summation of shares from each participant.
//! - No polynomial interpolation or Shamir reconstruction is involved.
//! - Each participant must be present for combining and verification.
//!
//! Provides wrapper types and helper functions specialized for additive aggregation, building upon the
//! generic primitives in the parent [`crate::dlog_equality`] module.
//!
//! For threshold security with partial reconstruction, see the `super::shamir` submodule.
//!
//! Secret state wrappers purposefully do not implement `Debug` or `Clone` to avoid accidental leakage.
use crate::{
    ddlog_equality::{
        DLogEqualityCommitments, DLogEqualityProofShare, DLogEqualitySession,
        PartialDLogEqualityCommitments,
    },
    dlog_equality::DLogEqualityProof,
    oprf::{Affine, Projective, ScalarField},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_serde_compat::babyjubjub;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

/// Additive Secret-share of an OPRF nullifier secret.
///
/// Serializable so it can be persisted via a secret manager.
/// Not `Debug`/`Display` to avoid accidental leaks.
///
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct DLogShareAdditive(
    #[serde(serialize_with = "babyjubjub::serialize_fr")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fr")]
    ScalarField,
);

/// Wrapper for the internal DLogEquality session state in the additive sharing variant.
///
/// Stores secret, non-clonable session state for a participant in the additive DLogEquality protocol,
/// used to generate commitment shares and construct proof shares. Not `Debug` to prevent unintended leakage.
#[derive(ZeroizeOnDrop)]
pub struct DLogSessionAdditive(DLogEqualitySession);

/// Aggregated commitment object for additive DLogEquality proof.
///
/// Transparent wrapper for the core `DLogEqualityCommitments` struct, grouping aggregate commitments
/// and participating party IDs as combined by simple additive summation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DLogCommitmentsAdditive(DLogEqualityCommitments);

/// Per-party commitment shares for additive DLogEquality proof.
///
/// Transparent wrapper for individual commitment shares produced by each participant in the additive
/// secret sharing case, ready for simple sum aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PartialDLogCommitmentsAdditive(PartialDLogEqualityCommitments);

/// Individual additive proof share for the DLogEquality protocol.
///
/// Wraps the per-party Chaum-Pedersen response share for additive aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DLogProofShareAdditive(DLogEqualityProofShare);

impl From<ark_babyjubjub::Fr> for DLogShareAdditive {
    fn from(value: ark_babyjubjub::Fr) -> Self {
        Self(value)
    }
}

impl From<DLogShareAdditive> for ark_babyjubjub::Fr {
    fn from(value: DLogShareAdditive) -> Self {
        value.0
    }
}
impl DLogSessionAdditive {
    /// Computes C=B·x_share and commitments to two random values d_share and e_share, which will be the shares of the randomness used in the DlogEqualityProof.
    /// The result is meant to be sent to one accumulating party (e.g., the verifier) who combines all the shares of all parties and creates the challenge hash.
    pub fn partial_commitments(
        b: Affine,
        DLogShareAdditive(x_share): DLogShareAdditive,
        rng: &mut (impl CryptoRng + Rng),
    ) -> (Self, PartialDLogCommitmentsAdditive) {
        let (session, comm) = DLogEqualitySession::partial_commitments(b, x_share, rng);
        (Self(session), PartialDLogCommitmentsAdditive(comm))
    }
}

impl DLogCommitmentsAdditive {
    /// Create an aggregated commitment object from component affine points and party IDs.
    pub fn new(
        c: Affine,
        d1: Affine,
        d2: Affine,
        e1: Affine,
        e2: Affine,
        parties: Vec<u16>,
    ) -> Self {
        let commitments = DLogEqualityCommitments {
            c,
            d1,
            d2,
            e1,
            e2,
            contributing_parties: parties,
        };
        Self(commitments)
    }

    /// Returns the parties that contributed to this commitment.
    pub fn get_contributing_parties(&self) -> &[u16] {
        &self.0.contributing_parties
    }

    /// Combine all parties' proof shares into a single Chaum-Pedersen proof object.
    ///
    /// Must use the same order of contributing parties as in aggregation
    pub fn combine_proofs(
        self,
        session_id: Uuid,
        proofs: &[DLogProofShareAdditive],
        a: Affine,
        b: Affine,
    ) -> DLogEqualityProof {
        self.0
            .combine_proofs(session_id, proofs.iter().map(|x| &x.0), a, b)
    }
    /// The accumulating party (e.g., the verifier) combines all the shares of all parties.
    /// The returned points are the combined commitments C, R1, R2.
    pub fn combine_commitments(commitments: &[(u16, PartialDLogCommitmentsAdditive)]) -> Self {
        let mut c = Projective::zero();
        let mut d1 = Projective::zero();
        let mut d2 = Projective::zero();
        let mut e1 = Projective::zero();
        let mut e2 = Projective::zero();
        let mut contributing_parties = Vec::with_capacity(commitments.len());

        for (party_id, PartialDLogCommitmentsAdditive(comm)) in commitments {
            c += comm.c;
            d1 += comm.d1;
            d2 += comm.d2;
            e1 += comm.e1;
            e2 += comm.e2;
            contributing_parties.push(*party_id);
        }

        let c = c.into_affine();
        let d1 = d1.into_affine();
        let d2 = d2.into_affine();
        let e1 = e1.into_affine();
        let e2 = e2.into_affine();

        let commitments = DLogEqualityCommitments {
            c,
            d1,
            d2,
            e1,
            e2,
            contributing_parties,
        };
        DLogCommitmentsAdditive(commitments)
    }

    /// Returns the combined blinded response C=B*x.
    pub fn blinded_response(&self) -> Affine {
        self.0.c
    }
}

impl DLogSessionAdditive {
    /// Finalizes a proof share for a given challenge hash and session.
    /// The session and information therein is consumed to prevent reuse of the randomness.
    pub fn challenge(
        self,
        session_id: Uuid,
        contributing_parties: &[u16],
        DLogShareAdditive(x_share): DLogShareAdditive,
        a: Affine,
        DLogCommitmentsAdditive(challenge_input): DLogCommitmentsAdditive,
    ) -> DLogProofShareAdditive {
        // Recombine the two-nonce randomness shares into the full randomness used in the challenge.
        let (r1, r2, b) = super::combine_two_nonce_randomness(
            session_id,
            a,
            challenge_input.c,
            challenge_input.d1,
            challenge_input.d2,
            challenge_input.e1,
            challenge_input.e2,
            contributing_parties,
        );

        // Recompute the challenge hash to ensure the challenge is well-formed.
        let d = Affine::generator();
        let e = crate::dlog_equality::challenge_hash(
            a,
            self.0.blinded_query,
            challenge_input.c,
            d,
            r1,
            r2,
        );

        // The following modular reduction in convert_base_to_scalar is required in rust to perform the scalar multiplications. Using all 254 bits of the base field in a double/add ladder would apply this reduction implicitly. We show in the docs of convert_base_to_scalar why this does not introduce a bias when applied to a uniform element of the base field.
        let e_ = crate::dlog_equality::convert_base_to_scalar(e);
        let share = DLogEqualityProofShare(self.0.d + b * self.0.e + e_ * x_share);
        DLogProofShareAdditive(share)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    fn test_distributed_dlog_equality(num_parties: usize) {
        let mut rng = rand::thread_rng();

        // Random x shares
        let x_shares = (0..num_parties)
            .map(|_| DLogShareAdditive(ScalarField::rand(&mut rng)))
            .collect::<Vec<_>>();

        // Combine x shares
        let x = x_shares
            .iter()
            .fold(ScalarField::zero(), |acc, x| acc + x.0);

        // Create public keys
        let public_key = (Affine::generator() * x).into_affine();
        let public_key_ = x_shares
            .iter()
            .map(|x| (Affine::generator() * x.0).into_affine())
            .fold(Projective::zero(), |acc, x| acc + x)
            .into_affine();
        assert_eq!(public_key, public_key_);

        // Crete session
        let session_id = Uuid::new_v4();
        let b = Affine::rand(&mut rng);

        // 1) Client requests commitments from all servers
        let mut sessions = Vec::with_capacity(num_parties);
        let mut commitments = Vec::with_capacity(num_parties);
        for (id, x_) in x_shares.iter().enumerate() {
            let (session, comm) =
                DLogSessionAdditive::partial_commitments(b, x_.to_owned(), &mut rng);
            sessions.push(session);
            commitments.push((id as u16 + 1, comm));
        }

        // 2) Client accumulates commitments and creates challenge
        let challenge = DLogCommitmentsAdditive::combine_commitments(&commitments);
        let c = challenge.blinded_response();

        // 3) Client challenges all servers
        let contributing_parties = (1u16..=(num_parties as u16)).collect::<Vec<_>>();
        let mut proofs = Vec::with_capacity(num_parties);
        for (session, x_) in sessions.into_iter().zip(x_shares.iter().cloned()) {
            let proof = session.challenge(
                session_id,
                &contributing_parties,
                x_,
                public_key,
                challenge.to_owned(),
            );
            proofs.push(proof);
        }

        // 4) Client combines all proofs
        let proof = challenge.combine_proofs(session_id, &proofs, public_key, b);

        // Verify the result and the proof
        let d = Affine::generator();
        assert_eq!(c, b * x, "Result must be correct");
        assert!(proof.verify(public_key, b, c, d).is_ok());
    }

    #[test]
    fn test_distributed_dlog_equality_3_parties() {
        test_distributed_dlog_equality(3);
    }

    #[test]
    fn test_distributed_dlog_equality_30_parties() {
        test_distributed_dlog_equality(30);
    }
}
