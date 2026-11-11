//! A post-quantum private, verifiable, threshold OPRF based on the Legendre PRF.
//!
//! The PRF is `F_k(h) = (chi(k + h + j))_{j < n}` over the `BabyJubJub` scalar field, where `chi` is the quadratic character. Unlike `TwoHashDH`, no public value determines the key even for an unbounded adversary: the key is only ever published inside a perfectly hiding Pedersen commitment, and every group element the nodes send is perfectly hiding as well. Soundness of the evaluation proof rests on the discrete logarithm assumption (classical), privacy of the key on the Legendre PRF.
//!
//! - [`circuit`]: witness generation for verifying the proof inside a circuit.
//! - [`params`]: generators and constants.
//! - [`proof`]: the PRF, the evaluation proof and its verifier.
//! - [`threshold`]: threshold evaluation with a jointly produced proof.
//! - [`transcript`]: Fiat-Shamir challenges.

pub mod circuit;
pub mod params;
pub mod proof;
pub mod threshold;
pub mod transcript;

pub use params::LegendreParams;
pub use proof::{InvalidLegendreProof, LegendreProof, commit_key, legendre_prf};

type ScalarField = ark_babyjubjub::Fr;
type BaseField = ark_babyjubjub::Fq;
type Affine = ark_babyjubjub::EdwardsAffine;
type Projective = ark_babyjubjub::EdwardsProjective;

#[cfg(test)]
mod tests {
    use ark_ff::{UniformRand, Zero};

    use super::*;

    #[test]
    fn proof_roundtrip_and_rejections() {
        let mut rng = rand::thread_rng();
        let params = LegendreParams::new(32);
        let (k, rho, h) = (
            ScalarField::rand(&mut rng),
            ScalarField::rand(&mut rng),
            ScalarField::rand(&mut rng),
        );
        let c_k = commit_key(&params, k, rho);
        let (bits, proof) = LegendreProof::prove(&params, k, rho, h, &mut rng).expect("non-zero");
        assert_eq!(Some(bits.clone()), legendre_prf(k, h, 32));
        proof.verify(&params, c_k, h, &bits).expect("valid proof");

        // any flipped output bit is rejected
        for j in [0, 7, 31] {
            let mut wrong = bits.clone();
            wrong[j] = !wrong[j];
            assert!(proof.verify(&params, c_k, h, &wrong).is_err());
        }
        // wrong input, wrong key commitment, tampered response
        assert!(
            proof
                .verify(&params, c_k, h + ScalarField::from(1u64), &bits)
                .is_err()
        );
        let other = commit_key(&params, k + ScalarField::from(1u64), rho);
        assert!(proof.verify(&params, other, h, &bits).is_err());
        let mut tampered = proof.clone();
        tampered.z[3] += ScalarField::from(1u64);
        assert!(tampered.verify(&params, c_k, h, &bits).is_err());
        assert!(!proof.e.is_zero());
    }

    #[test]
    fn prover_cannot_claim_wrong_bit() {
        // A prover that knows the key and runs the honest algorithm on flipped targets has no witness: the square root does not exist.
        let mut rng = rand::thread_rng();
        let (k, h) = (ScalarField::rand(&mut rng), ScalarField::rand(&mut rng));
        let bits = legendre_prf(k, h, 8).expect("non-zero");
        for (j, bit) in bits.iter().enumerate() {
            let kappa = k + h + proof::index(j);
            let wrong = proof::target(!*bit) * ark_ff::Field::inverse(&kappa).expect("non-zero");
            assert!(!params::is_square(wrong));
        }
    }
}
