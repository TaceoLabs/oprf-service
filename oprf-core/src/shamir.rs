//! Utilities for Lagrange interpolation and polynomial evaluation over finite fields.
//
//! Provides functions to compute Lagrange coefficients, evaluate polynomials, and reconstruct secrets from shares.

use ark_ff::PrimeField;

/// Computes the Lagrange coefficients for the provided party indices.
///
/// # Arguments
///
/// * `coeffs` - Slice of party indices.
///
/// # Returns
///
/// Vector of Lagrange coefficients for each party.
pub fn lagrange_from_coeff<F: PrimeField + From<T>, T: Copy + Eq>(coeffs: &[T]) -> Vec<F> {
    let num = coeffs.len();
    let mut res = Vec::with_capacity(num);
    for i in coeffs {
        res.push(single_lagrange_from_coeff(*i, coeffs));
    }
    res
}

/// Computes the Lagrange coefficient for a specific party identifier.
///
/// # Arguments
///
/// * `my_id` - Party identifier.
/// * `coeffs` - Slice of party indices.
///
/// # Returns
///
/// The Lagrange coefficient for `my_id`.
///
/// # Panics
/// Might panic if chosen `T` does not fit into `Primefield`.
pub fn single_lagrange_from_coeff<F: PrimeField + From<T>, T: Copy + Eq>(
    my_id: T,
    coeffs: &[T],
) -> F {
    let mut num = F::one();
    let mut den = F::one();
    let i_ = F::from(my_id);
    for j in coeffs {
        if my_id != *j {
            let j_ = F::from(*j);
            num *= j_;
            den *= j_ - i_;
        }
    }
    num * den.inverse().expect("Has an inverse")
}

/// Evaluates a polynomial at the given point.
///
/// # Arguments
///
/// * `poly` - Coefficients of the polynomial, low to high degree.
/// * `x` - The point at which to evaluate.
///
/// # Returns
///
/// The polynomial evaluated at `x`.
///
/// # Panics
/// If the provided polynomial is empty.
pub(crate) fn evaluate_poly<F: PrimeField>(poly: &[F], x: F) -> F {
    assert!(!poly.is_empty(), "Poly must not be empty");
    let mut iter = poly.iter().rev();
    let mut eval = iter.next().expect("Checked that not empty").to_owned();
    for coeff in iter {
        eval *= x;
        eval += coeff;
    }
    eval
}

/// Recovers the secret by combining shares with Lagrange coefficients.
///
/// # Arguments
///
/// * `shares` - The shares from different parties.
/// * `lagrange` - Corresponding Lagrange coefficients.
///
/// # Returns
///
/// The reconstructed secret value.
///
/// # Panics
/// If provided shares and lagrange coefficients are not same length
pub fn reconstruct<F: PrimeField>(shares: &[F], lagrange: &[F]) -> F {
    assert_eq!(
        shares.len(),
        lagrange.len(),
        "Shares and lagrange coeffs must be same length"
    );
    let mut res = F::zero();
    for (s, l) in shares.iter().zip(lagrange.iter()) {
        res += *s * l;
    }
    res
}

#[cfg(test)]
pub(crate) mod test_utils {
    use ark_ec::CurveGroup;
    use ark_ff::PrimeField;
    use rand::{Rng, seq::IteratorRandom as _};

    use crate::shamir::{lagrange_from_coeff, reconstruct};

    /// Reconstructs a curve point from its Shamir shares and lagrange coefficients.
    pub(crate) fn reconstruct_point<C: CurveGroup>(
        shares: &[C::Affine],
        lagrange: &[C::ScalarField],
    ) -> C {
        debug_assert_eq!(shares.len(), lagrange.len());
        C::msm_unchecked(shares, lagrange)
    }

    pub(crate) fn reconstruct_random_shares<F: PrimeField, R: Rng>(
        shares: &[F],
        degree: usize,
        rng: &mut R,
    ) -> F {
        let num_parties = shares.len();
        let parties = (1..=num_parties as u64).choose_multiple(rng, degree + 1);
        let shares = parties
            .iter()
            .map(|&i| shares[usize::try_from(i - 1).expect("Fits into usize")])
            .collect::<Vec<_>>();
        let lagrange = lagrange_from_coeff(&parties);
        reconstruct(&shares, &lagrange)
    }

    pub(crate) fn reconstruct_random_pointshares<C: CurveGroup, R: Rng>(
        shares: &[C],
        degree: usize,
        rng: &mut R,
    ) -> C {
        let num_parties = shares.len();
        let parties = (1..=num_parties as u64).choose_multiple(rng, degree + 1);
        // maybe sufficient to into_affine in the following map
        let shares = parties
            .iter()
            .map(|&i| shares[usize::try_from(i - 1).expect("Fits into usize")])
            .collect::<Vec<_>>();
        let shares = C::batch_convert_to_mul_base(&shares);
        let lagrange = lagrange_from_coeff(&parties);
        reconstruct_point(&shares, &lagrange)
    }
}
