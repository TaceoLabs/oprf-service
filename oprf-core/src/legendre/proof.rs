//! The Legendre PRF, its evaluation proof and the proof verifier.
//!
//! The PRF maps an input `h` under key `k` to the bits `b_j = [k + h + j is a non-residue]` for `j = 0..n`.
//!
//! The proof shows, relative to a Pedersen commitment `C_k = k*G + rho*H`, that for every `j` there is a `sigma_j` with `sigma_j^2 * (k + h + j) = N^{b_j}`, where `N` is a fixed non-residue. Such a `sigma_j` exists iff `b_j` is the correct output bit. It is a sigma protocol for a cubic relation, batched over `j` with Fiat-Shamir coefficients `gamma_j`.

use ark_ec::{CurveGroup, VariableBaseMSM as _};
use ark_ff::{AdditiveGroup as _, BigInteger as _, Field, PrimeField, UniformRand, Zero};
use rand::{CryptoRng, Rng};

use super::{
    Affine, Projective, ScalarField,
    params::{LegendreParams, is_square, non_residue},
    transcript::{CHALLENGE_BITS, batch_challenges, sigma_challenge},
};

/// Error returned when a Legendre evaluation proof does not verify.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(clippy::exhaustive_structs, reason = "Simple error for a single use")]
pub struct InvalidLegendreProof;

impl std::error::Error for InvalidLegendreProof {}

impl std::fmt::Display for InvalidLegendreProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Invalid Legendre evaluation proof")
    }
}

/// Proof that a bit string is the Legendre PRF output for a committed key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::exhaustive_structs, reason = "Plain proof data")]
pub struct LegendreProof {
    /// Commitment `sum_j sigma_j*G_j + nu*H` to the witness vector.
    pub c_sigma: Affine,
    /// Commitment to the linear coefficient of the batched relation polynomial.
    pub t1: Affine,
    /// Commitment to the quadratic coefficient of the batched relation polynomial.
    pub t2: Affine,
    /// Fiat-Shamir challenge, [`CHALLENGE_BITS`] bits.
    pub e: ScalarField,
    /// Responses `z_j = a_j + e*sigma_j`.
    pub z: Vec<ScalarField>,
    /// Response for the blinding of `c_sigma`.
    pub z_nu: ScalarField,
    /// Response `a_k + e*k`.
    pub z_k: ScalarField,
    /// Response for the blinding of the key commitment.
    pub z_rho: ScalarField,
    /// Response for the blinding of the coefficient commitments.
    pub z_tau: ScalarField,
}

/// Pedersen commitment `k*G + rho*H` to a PRF key.
#[must_use]
pub fn commit_key(params: &LegendreParams, k: ScalarField, rho: ScalarField) -> Affine {
    (LegendreParams::g() * k + params.h * rho).into_affine()
}

/// Evaluates the Legendre PRF in the clear. Returns `None` in the negligible case that `k + h + j = 0` for some `j`.
#[must_use]
pub fn legendre_prf(k: ScalarField, h: ScalarField, n_bits: usize) -> Option<Vec<bool>> {
    (0..n_bits)
        .map(|j| {
            let kappa = k + h + index(j);
            (!kappa.is_zero()).then(|| !is_square(kappa))
        })
        .collect()
}

pub(super) fn index(j: usize) -> ScalarField {
    ScalarField::from(u64::try_from(j).expect("fits into u64"))
}

/// `N^b`: the constant the witness relation must hit for output bit `b`.
pub(super) fn target(bit: bool) -> ScalarField {
    if bit { non_residue() } else { ScalarField::ONE }
}

/// The scalar `sum_j gamma_j * (z_j^2 * (z_k + e*(h + j)) - e^3 * N^{b_j})`.
pub(super) fn batched_scalar(
    gammas: &[ScalarField],
    z: &[ScalarField],
    z_k: ScalarField,
    e: ScalarField,
    h: ScalarField,
    bits: &[bool],
) -> ScalarField {
    let e3 = e * e * e;
    itertools::izip!(gammas, z, bits)
        .enumerate()
        .map(|(j, (gamma, z_j, bit))| {
            *gamma * (z_j.square() * (z_k + e * (h + index(j))) - e3 * target(*bit))
        })
        .sum()
}

fn is_valid_point(p: &Affine) -> bool {
    p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()
}

impl LegendreProof {
    /// Verifies that `bits` is the Legendre PRF output on input `h` under the key committed to in `c_k`.
    ///
    /// # Errors
    /// Returns [`InvalidLegendreProof`] if the proof does not verify.
    pub fn verify(
        &self,
        params: &LegendreParams,
        c_k: Affine,
        h: ScalarField,
        bits: &[bool],
    ) -> Result<(), InvalidLegendreProof> {
        let n = params.n_bits();
        if bits.len() != n || self.z.len() != n {
            return Err(InvalidLegendreProof);
        }
        if ![c_k, self.c_sigma, self.t1, self.t2]
            .iter()
            .all(is_valid_point)
        {
            return Err(InvalidLegendreProof);
        }
        if self.e.into_bigint().num_bits() as usize > CHALLENGE_BITS {
            return Err(InvalidLegendreProof);
        }
        let e = self.e;
        let batch = batch_challenges(c_k, self.c_sigma, h, bits);

        let a = Projective::msm_unchecked(&params.gens, &self.z) + params.h * self.z_nu
            - self.c_sigma * e;
        let a_k = LegendreParams::g() * self.z_k + params.h * self.z_rho - c_k * e;
        let s = batched_scalar(&batch.gammas(n), &self.z, self.z_k, e, h, bits);
        let t0 = LegendreParams::g() * s + params.h * self.z_tau - (self.t1 + self.t2 * e) * e;

        let e_check = sigma_challenge(
            &batch,
            a.into_affine(),
            a_k.into_affine(),
            t0.into_affine(),
            self.t1,
            self.t2,
        );
        if e_check == e {
            Ok(())
        } else {
            Err(InvalidLegendreProof)
        }
    }

    /// Reference prover that knows the full key. The threshold protocol in [`super::threshold`] produces the same proofs without any party knowing `k`.
    ///
    /// Returns the PRF output bits and the proof, or `None` in the negligible case that `k + h + j = 0` for some `j`.
    pub fn prove<R: Rng + CryptoRng>(
        params: &LegendreParams,
        k: ScalarField,
        rho: ScalarField,
        h: ScalarField,
        rng: &mut R,
    ) -> Option<(Vec<bool>, Self)> {
        let n = params.n_bits();
        let g = LegendreParams::g();
        let bits = legendre_prf(k, h, n)?;
        let kappas = (0..n).map(|j| k + h + index(j)).collect::<Vec<_>>();
        // sigma_j = sqrt(N^{b_j} / kappa_j), which exists by the choice of b_j
        let sigmas = kappas
            .iter()
            .zip(&bits)
            .map(|(kappa, bit)| (target(*bit) * kappa.inverse()?).sqrt())
            .collect::<Option<Vec<_>>>()?;

        let c_k = commit_key(params, k, rho);
        let nu = ScalarField::rand(rng);
        let c_sigma =
            (Projective::msm_unchecked(&params.gens, &sigmas) + params.h * nu).into_affine();
        let batch = batch_challenges(c_k, c_sigma, h, &bits);
        let gammas = batch.gammas(n);

        let nonces = (0..n).map(|_| ScalarField::rand(rng)).collect::<Vec<_>>();
        let (alpha, a_k, alpha_k) = (
            ScalarField::rand(rng),
            ScalarField::rand(rng),
            ScalarField::rand(rng),
        );
        let a = (Projective::msm_unchecked(&params.gens, &nonces) + params.h * alpha).into_affine();
        let a_k_point = (g * a_k + params.h * alpha_k).into_affine();

        // coefficients of sum_j gamma_j * (a_j + e*sigma_j)^2 * (a_k + e*kappa_j) in e
        let mut coeffs = [ScalarField::zero(); 3];
        for (gamma, a_j, sigma, kappa) in itertools::izip!(&gammas, &nonces, &sigmas, &kappas) {
            let c = relation_coefficients(*a_j, *sigma, a_k, *kappa);
            for (acc, c) in coeffs.iter_mut().zip(c) {
                *acc += *gamma * c;
            }
        }
        let taus = [(); 3].map(|()| ScalarField::rand(rng));
        let [t0, t1, t2] = [0, 1, 2].map(|c| (g * coeffs[c] + params.h * taus[c]).into_affine());

        let e = sigma_challenge(&batch, a, a_k_point, t0, t1, t2);
        let z = nonces
            .iter()
            .zip(&sigmas)
            .map(|(a_j, sigma)| *a_j + e * sigma)
            .collect();
        let proof = Self {
            c_sigma,
            t1,
            t2,
            e,
            z,
            z_nu: alpha + e * nu,
            z_k: a_k + e * k,
            z_rho: alpha_k + e * rho,
            z_tau: taus[0] + e * taus[1] + e * e * taus[2],
        };
        Some((bits, proof))
    }
}

/// Coefficients of `e^0, e^1, e^2` in `(a + e*s)^2 * (a_k + e*kappa)`. The coefficient of `e^3` is `s^2 * kappa`.
pub(super) fn relation_coefficients(
    a: ScalarField,
    s: ScalarField,
    a_k: ScalarField,
    kappa: ScalarField,
) -> [ScalarField; 3] {
    let a2 = a.square();
    let two_as = (a * s).double();
    [
        a2 * a_k,
        a2 * kappa + two_as * a_k,
        two_as * kappa + s.square() * a_k,
    ]
}
