//! Public parameters of the Legendre OPRF: output length, commitment generators and the quadratic non-residue.

use ark_ec::AffineRepr;
use ark_ff::{Field, PrimeField, Zero};

use crate::oprf::mappings::hash_to_curve;

use super::{Affine, BaseField, ScalarField};

/// Default number of PRF output bits.
pub const DEFAULT_BITS: usize = 128;

/// Largest supported number of output bits. Bounded by the number of batching challenges one Poseidon2 squeeze yields.
pub const MAX_BITS: usize = 224;

/// The smallest quadratic non-residue in the `BabyJubJub` scalar field.
pub const NON_RESIDUE: u64 = 19;

const GEN_H_DS: &[u8] = b"Legendre OPRF generator H";
const GEN_G_DS: &[u8] = b"Legendre OPRF generator G";

/// Returns [`NON_RESIDUE`] as a field element.
#[must_use]
pub fn non_residue() -> ScalarField {
    ScalarField::from(NON_RESIDUE)
}

/// Returns `true` iff `x` is a non-zero quadratic residue.
#[must_use]
pub fn is_square(x: ScalarField) -> bool {
    !x.is_zero() && x.legendre().is_qr()
}

/// Public parameters shared by nodes, clients and verifiers.
///
/// All generators are derived with [`hash_to_curve`] from fixed domain separators, so nobody knows a discrete-logarithm relation between them. This is what makes the Pedersen commitments binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegendreParams {
    /// Vector-commitment generators `G_0, ..., G_{n-1}`, one per output bit.
    pub gens: Vec<Affine>,
    /// Blinding generator `H`.
    pub h: Affine,
}

impl LegendreParams {
    /// Derives the parameters for `n_bits` output bits.
    ///
    /// # Panics
    /// If `n_bits` is zero or larger than [`MAX_BITS`].
    #[must_use]
    pub fn new(n_bits: usize) -> Self {
        assert!(
            (1..=MAX_BITS).contains(&n_bits),
            "n_bits must be in 1..={MAX_BITS}"
        );
        let h = hash_to_curve(BaseField::from_be_bytes_mod_order(GEN_H_DS));
        let ds = BaseField::from_be_bytes_mod_order(GEN_G_DS);
        let gens = (0..n_bits)
            .map(|j| {
                let input = poseidon2::bn254::t3::permutation(&[
                    ds,
                    BaseField::from(u64::try_from(j).expect("fits into u64")),
                    BaseField::zero(),
                ])[1];
                hash_to_curve(input)
            })
            .collect();
        Self { gens, h }
    }

    /// Number of output bits.
    #[must_use]
    pub fn n_bits(&self) -> usize {
        self.gens.len()
    }

    /// The generator `G` used for scalar commitments (the `BabyJubJub` subgroup generator).
    #[must_use]
    pub fn g() -> Affine {
        Affine::generator()
    }
}

impl Default for LegendreParams {
    fn default() -> Self {
        Self::new(DEFAULT_BITS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_residue_is_smallest() {
        assert!(!is_square(non_residue()));
        for n in 1..NON_RESIDUE {
            assert!(is_square(ScalarField::from(n)), "{n} must be a residue");
        }
    }

    #[test]
    fn generators_are_distinct_subgroup_points() {
        let params = LegendreParams::new(DEFAULT_BITS);
        let mut all = params.gens.clone();
        all.push(params.h);
        all.push(LegendreParams::g());
        for (i, p) in all.iter().enumerate() {
            assert!(p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve());
            assert!(!p.is_zero());
            assert!(all[..i].iter().all(|q| q != p), "duplicate generator");
        }
    }
}
