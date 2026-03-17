//! This module provides types and functionality for creating and verifying Chaum-Pedersen proofs,
//! enabling the demonstration that two group elements are related by the same discrete logarithm
//! (i.e., knowledge of a secret x such that A = x*D and C = x*B), without revealing x itself.
//!
//! This is primarily used to prove correctness of OPRF operations over `BabyJubJub` elliptic curve elements.
//!
//! ## Features
//! - Proof creation given secret
//! - Proof verification, including group membership and field fit checks
//! - Uses Poseidon2 for Fiat-Shamir challenge generation

use std::fmt;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use num_bigint::BigUint;
use rand::{CryptoRng, Rng};

/// A Chaum-Pedersen discrete logarithm equality proof.
///
/// Proves in zero-knowledge that two group elements share the same discrete logarithm (i.e., for known base points B and D, prover knows x such that A = x·D and C = x·B), without revealing x. Used to ensure correct OPRF evaluations.
///
/// The verifier needs to check that `s` fits in the base field to avoid malleability attacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DLogEqualityProof {
    ///Fiat-Shamir challenge, represented as a field element.
    pub(crate) e: BaseField,
    /// Proof response, represented as a scalar. The verifier checks that it fits in the base field to avoid malleability attacks.
    pub(crate) s: ScalarField,
}

type ScalarField = ark_babyjubjub::Fr;
type BaseField = ark_babyjubjub::Fq;
type Affine = ark_babyjubjub::EdwardsAffine;

/// Error indicating that the DLog-Proof could not be verified.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(clippy::exhaustive_structs, reason = "Simple error for a single use")]
pub struct InvalidProof;

impl std::error::Error for InvalidProof {}

impl fmt::Display for InvalidProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Invalid DLogProof")
    }
}

impl DLogEqualityProof {
    const DLOG_DS: &[u8] = b"DLOG Equality Proof";

    /// Creates a new `DLogEqualityProof` from existing `e` and `s` values.
    #[must_use]
    pub fn new(e: BaseField, s: ScalarField) -> Self {
        Self { e, s }
    }

    ///Fiat-Shamir challenge, represented as a field element.
    #[must_use]
    pub fn e(&self) -> BaseField {
        self.e
    }

    /// Proof response, represented as a scalar.
    ///
    /// The verifier checks that it fits in the base field to avoid malleability attacks.
    #[must_use]
    pub fn s(&self) -> ScalarField {
        self.s
    }

    // Returns the domain separator for the query finalization as a field element
    fn get_dlog_ds() -> BaseField {
        BaseField::from_be_bytes_mod_order(Self::DLOG_DS)
    }

    /// Creates a Chaum-Pedersen proof which shows that C=x*B and A=x*D share the same dlog x. This proof can be verified using B, C, and A=x*D. D is currently hard coded as the generator of the group.
    pub fn proof(b: Affine, x: ScalarField, rng: &mut (impl CryptoRng + Rng)) -> Self {
        let k = ScalarField::rand(rng);
        let r1 = (Affine::generator() * k).into_affine();
        let r2 = (b * k).into_affine();
        let a = (Affine::generator() * x).into_affine();
        let c = (b * x).into_affine();
        let d = Affine::generator();
        let e = challenge_hash(a, b, c, d, r1, r2);

        // The following modular reduction in convert_base_to_scalar is required in rust to perform the scalar multiplications. Using all 254 bits of the base field in a double/add ladder would apply this reduction implicitly. We show in the docs of convert_base_to_scalar why this does not introduce a bias when applied to a uniform element of the base field.
        let e_ = convert_base_to_scalar(e);
        let s = k + e_ * x;
        DLogEqualityProof { e, s }
    }

    /// Takes the Chaum-Pedersen proof e,s and verifies that A=x*D and C=x*B have the same dlog x, given A,B,C,D.
    ///
    /// # Errors
    /// Returns an error if proof verification fails.
    pub fn verify(&self, a: Affine, b: Affine, c: Affine, d: Affine) -> Result<(), InvalidProof> {
        // All points need to be valid curve elements.
        if [a, b, c, d]
            .iter()
            .any(|p| !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve())
        {
            return Err(InvalidProof);
        }
        if [a, b, c, d].iter().any(Affine::is_zero) {
            return Err(InvalidProof);
        }

        // The following check is required to prevent malleability of the proofs by using different s, such as s + p.
        // In Rust this check is not required since self.s is a ScalarField element already, but we keep it to have the same implementation as in circom (where it is required).
        let s_biguint: BigUint = self.s.into();
        if s_biguint >= ScalarField::MODULUS.into() {
            return Err(InvalidProof);
        }

        // The following modular reduction in convert_base_to_scalar is required in rust to perform the scalar multiplications. Using all 254 bits of the base field in a double/add ladder would apply this reduction implicitly. We show in the docs of convert_base_to_scalar why this does not introduce a bias when applied to a uniform element of the base field.
        let e = convert_base_to_scalar(self.e);

        let r_1 = d * self.s - a * e;
        if r_1.is_zero() {
            return Err(InvalidProof);
        }
        let r_2 = b * self.s - c * e;
        if r_2.is_zero() {
            return Err(InvalidProof);
        }
        let e = challenge_hash(a, b, c, d, r_1.into_affine(), r_2.into_affine());
        if e == self.e {
            Ok(())
        } else {
            Err(InvalidProof)
        }
    }
}

pub(crate) fn challenge_hash(
    a: Affine,
    b: Affine,
    c: Affine,
    d: Affine,
    r1: Affine,
    r2: Affine,
) -> BaseField {
    let hash_input = [
        DLogEqualityProof::get_dlog_ds(), // Domain separator in capacity of hash
        a.x,
        a.y,
        b.x,
        b.y,
        c.x,
        c.y,
        d.x,
        d.y,
        r1.x,
        r1.y,
        r2.x,
        r2.y,
        BaseField::zero(),
        BaseField::zero(),
        BaseField::zero(),
    ];
    poseidon2::bn254::t16::permutation(&hash_input)[1] // output first state element as hash output
}

// This is just a modular reduction. We show in the docs why this does not introduce a bias when applied to a uniform element of the base field.
pub(crate) fn convert_base_to_scalar(f: BaseField) -> ScalarField {
    let bytes = f.into_bigint().to_bytes_le();
    ScalarField::from_le_bytes_mod_order(&bytes)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_dlog_equality() {
        let mut rng = rand::thread_rng();
        let x = ScalarField::rand(&mut rng);
        let d = Affine::generator();
        let a = (d * x).into_affine();
        let b = Affine::rand(&mut rng);
        let c = (b * x).into_affine();

        let proof = DLogEqualityProof::proof(b, x, &mut rng);
        proof.verify(a, b, c, d).expect("Can verify proof");
        let b2 = Affine::rand(&mut rng);
        let invalid_proof = DLogEqualityProof::proof(b2, x, &mut rng);
        assert!(invalid_proof.verify(a, b, c, d).is_err());
    }
}
