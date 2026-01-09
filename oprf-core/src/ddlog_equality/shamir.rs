//! Shamir Secret Sharing variant of distributed DLogEquality proof combination.
//!
//! This module implements threshold (Shamir) secret sharing for distributed Chaum-Pedersen
//! discrete log equality proofs, enabling a group of parties to collectively prove knowledge
//! of a shared discrete logarithm without interactive multiplications or additional setup rounds.
//!
//! In this variant, each server samples its nonce independently; the resulting nonce set forms
//! valid Shamir shares. Accumulations and proof aggregation are performed using Lagrange
//! interpolation, avoiding the need for extra round trips or communication to share randomness.
//!
//! This module provides:
//! - Extension types that encapsulate the core DLogEquality structs for Shamir sharing.
//! - Methods for combining Shamir-shared commitments and proof shares via Lagrange interpolation.
//! - Drop-in integration with the [`crate::dlog_equality`] primitives for session handling and proof creation.
//!
//! For the simple additive variant, see the `super::additive` submodule in this crate.
//!
//! Secret state wrappers purposefully do not implement `Debug` or `Clone` to avoid accidental leakage.
use crate::ddlog_equality::{
    DLogEqualityCommitments, DLogEqualityProofShare, DLogEqualitySession,
    PartialDLogEqualityCommitments,
};
use crate::dlog_equality::DLogEqualityProof;
use ark_ec::CurveGroup;
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::Zero;
use ark_serde_compat::babyjubjub;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

type ScalarField = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;
type Projective = ark_babyjubjub::EdwardsProjective;

/// Shamir Secret-share of an OPRF nullifier secret.
///
/// Serializable so it can be persisted via a secret manager.
/// Not `Debug`/`Display` to avoid accidental leaks.
///
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct DLogShareShamir(
    #[serde(serialize_with = "babyjubjub::serialize_fr")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fr")]
    ScalarField,
);

/// Wrapper for the internal DLogEquality session state in the Shamir-sharing variant.
///
/// Stores non-clonable, non-debug secret state for a threshold party during the DLogEquality protocol.
/// Used to generate the commitment shares and construct the proof share for Shamir secret sharing.
#[derive(ZeroizeOnDrop)]
pub struct DLogSessionShamir(DLogEqualitySession);

/// Commitment aggregation object for the Shamir DLogEquality protocol.
///
/// This is a transparent wrapper around the core `DLogEqualityCommitments` struct, grouping
/// together the aggregate commitments and participating party identifiers as reconstructed
/// via Shamir Lagrange interpolation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DLogCommitmentsShamir(DLogEqualityCommitments);

/// Per-party commitment shares for Shamir DLogEquality protocol.
///
/// Wraps and serializes individual party commitments to the distributed DLogEquality proof,
/// in the context of Shamir secret sharing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PartialDLogCommitmentsShamir(PartialDLogEqualityCommitments);

/// Individual party's proof share for the Shamir DLogEquality proof protocol.
///
/// Wraps the share of the challenge response for Shamir secret sharing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DLogProofShareShamir(DLogEqualityProofShare);

impl From<ark_babyjubjub::Fr> for DLogShareShamir {
    fn from(value: ark_babyjubjub::Fr) -> Self {
        Self(value)
    }
}

impl From<DLogShareShamir> for ark_babyjubjub::Fr {
    fn from(value: DLogShareShamir) -> Self {
        value.0
    }
}

impl DLogSessionShamir {
    /// Computes C=B·x_share and commitments to two random values d_share and e_share, which will be the shares of the randomness used in the DlogEqualityProof.
    /// The result is meant to be sent to one accumulating party (e.g., the verifier) who combines all the shares of all parties and creates the challenge hash.
    pub fn partial_commitments(
        b: Affine,
        DLogShareShamir(x_share): DLogShareShamir,
        rng: &mut (impl CryptoRng + Rng),
    ) -> (Self, PartialDLogCommitmentsShamir) {
        let (session, comm) = DLogEqualitySession::partial_commitments(b, x_share, rng);
        (Self(session), PartialDLogCommitmentsShamir(comm))
    }
}

impl DLogCommitmentsShamir {
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
        proofs: &[DLogProofShareShamir],
        a: Affine,
        b: Affine,
    ) -> DLogEqualityProof {
        self.0
            .combine_proofs(session_id, proofs.iter().map(|x| &x.0), a, b)
    }
    /// Returns the combined blinded response C=B*x.
    pub fn blinded_response(&self) -> Affine {
        self.0.c
    }

    /// The accumulating party (e.g., the verifier) combines the shares of `d + 1` parties.
    ///
    /// # Panics
    /// Panics if the number of commitments does not match the number of contributing parties,
    /// i.e. `commitments.len() != contributing_parties.len()`.
    /// Additionally, panics if the contributing parties contain duplicate party IDs.
    /// The call site is expected to enforce these checks.
    pub fn combine_commitments(
        commitments: &[PartialDLogCommitmentsShamir],
        contributing_parties: Vec<u16>,
    ) -> Self {
        let mut contributing_parties_dedup = contributing_parties.clone();
        contributing_parties_dedup.sort();
        contributing_parties_dedup.dedup();
        assert_eq!(
            contributing_parties.len(),
            contributing_parties_dedup.len(),
            "Party IDs must be unique"
        );
        assert_eq!(
            contributing_parties.len(),
            commitments.len(),
            "Number of commitments must match number of contributing parties"
        );
        let lagrange = crate::shamir::lagrange_from_coeff(&contributing_parties);

        let c = Projective::msm_unchecked(
            &commitments.iter().map(|comm| comm.0.c).collect::<Vec<_>>(),
            &lagrange,
        );
        let mut d1 = Projective::zero();
        let mut d2 = Projective::zero();
        let mut e1 = Projective::zero();
        let mut e2 = Projective::zero();

        for PartialDLogCommitmentsShamir(comm) in commitments.iter() {
            d1 += comm.d1;
            d2 += comm.d2;
            e1 += comm.e1;
            e2 += comm.e2;
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

        DLogCommitmentsShamir(commitments)
    }
}

// The Shamir version uses the same prover implementation as the additive version. The reason is that if each server samples the value k_i individually at random (instead of using the Shamir.rand() subroutine), then for each set of d servers, their k_i represent a valid random Shamir share. Since only d servers are ever required (e.g., we do not have a shared multiplication), we do not need all n random k_i to be on the same polynomial. Thus, we do not require an extra communication round to create shares of a random k.

impl DLogSessionShamir {
    /// Finalizes a proof share for a given challenge hash and session.
    /// The session and information therein is consumed to prevent reuse of the randomness.
    ///
    /// Prerequisites:
    /// * The lagrange_coefficient is computed from the same set of contributing parties as in the commitments.
    /// * The set of contributing parties in challenge_input is checked for duplicates, has the correct number of parties and contains the party corresponding to this session.
    pub fn challenge(
        self,
        session_id: Uuid,
        DLogShareShamir(x_share): DLogShareShamir,
        a: Affine,
        DLogCommitmentsShamir(challenge_input): DLogCommitmentsShamir,
        lagrange_coefficient: ScalarField,
    ) -> DLogProofShareShamir {
        // Recombine the two-nonce randomness shares into the full randomness used in the challenge.
        let (r1, r2, b) = super::combine_two_nonce_randomness(
            session_id,
            a,
            challenge_input.c,
            challenge_input.d1,
            challenge_input.d2,
            challenge_input.e1,
            challenge_input.e2,
            &challenge_input.contributing_parties,
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
        let share =
            DLogEqualityProofShare(self.0.d + b * self.0.e + lagrange_coefficient * e_ * x_share);
        DLogProofShareShamir(share)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir::{self, evaluate_poly};
    use ark_ff::UniformRand;
    use rand::{Rng, seq::IteratorRandom};

    fn share<R: Rng>(
        secret: ScalarField,
        num_shares: usize,
        degree: usize,
        rng: &mut R,
    ) -> Vec<DLogShareShamir> {
        let mut shares = Vec::with_capacity(num_shares);
        let mut coeffs = Vec::with_capacity(degree + 1);
        coeffs.push(secret);
        for _ in 0..degree {
            coeffs.push(ScalarField::rand(rng));
        }
        for i in 1..=num_shares {
            let share = evaluate_poly(&coeffs, ScalarField::from(i as u64));
            shares.push(DLogShareShamir(share));
        }
        shares
    }

    fn test_distributed_dlog_equality(num_parties: usize, degree: usize) {
        let mut rng = rand::thread_rng();

        let x = ScalarField::rand(&mut rng);
        let x_shares = share(x, num_parties, degree, &mut rng);

        // Create public keys
        let public_key = (Affine::generator() * x).into_affine();
        let public_key_shares = x_shares
            .iter()
            .map(|x| Affine::generator() * x.0)
            .collect::<Vec<_>>();
        let public_key_ = shamir::test_utils::reconstruct_random_pointshares(
            &public_key_shares,
            degree,
            &mut rng,
        );
        assert_eq!(public_key, public_key_);

        // Crete session and choose the used set of parties
        let session_id = Uuid::new_v4();
        let b = Affine::rand(&mut rng);
        let used_parties = (1..=num_parties as u16).choose_multiple(&mut rng, degree + 1);

        // 1) Client requests commitments from all servers
        let mut sessions = Vec::with_capacity(num_parties);
        let mut commitments = Vec::with_capacity(num_parties);
        for x_ in x_shares.iter().cloned() {
            let (session, comm) = DLogSessionShamir::partial_commitments(b, x_, &mut rng);
            sessions.push(Some(session));
            commitments.push(comm);
        }

        // 2) Client accumulates commitments and creates challenge
        // Choose the commitments of the used parties
        let used_commitments = used_parties
            .iter()
            .map(|&i| commitments[i as usize - 1].clone())
            .collect::<Vec<_>>();

        let challenge =
            DLogCommitmentsShamir::combine_commitments(&used_commitments, used_parties.clone());
        let c = challenge.blinded_response();

        // 3) Client challenges used servers (not needed, could only challenge used parties)
        let mut used_proofs = Vec::with_capacity(num_parties);

        for server_idx in &used_parties {
            // we just use an option here in tests to be able to move out of the vector since the session is consumed
            let session = sessions[*server_idx as usize - 1]
                .take()
                .expect("have not used this session before");
            let x_ = x_shares[*server_idx as usize - 1].clone();
            let proof = session.challenge(
                session_id,
                x_,
                public_key,
                challenge.clone(),
                shamir::single_lagrange_from_coeff(*server_idx, &used_parties),
            );
            used_proofs.push(proof);
        }

        // 4) Client combines received proof shares
        let proof = challenge.combine_proofs(session_id, &used_proofs, public_key, b);

        // Verify the result and the proof
        let d = Affine::generator();
        assert_eq!(c, b * x, "Result must be correct");
        assert!(proof.verify(public_key, b, c, d).is_ok());
    }

    #[test]
    fn test_distributed_dlog_equality_shamir_3_1() {
        test_distributed_dlog_equality(3, 1);
    }

    #[test]
    fn test_distributed_dlog_equality_shamir_31_15() {
        test_distributed_dlog_equality(31, 15);
    }
}
