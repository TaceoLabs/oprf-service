//! Witness generation for verifying a [`LegendreProof`] inside a circuit over the `BabyJubJub` base field.
//!
//! The group equations of the verifier are native to such a circuit. The scalar `S = sum_j gamma_j * (z_j^2 * (z_k + e*(h + j)) - e^3 * N^{b_j})` lives in the scalar field, which is foreign to the circuit. The circuit therefore computes it over the integers on 42-bit limbs without intermediate reductions and checks three reductions modulo the scalar field order `q` with prover-supplied quotients and carries (the *hints* computed here):
//!
//! 1. `xi = z_k + e*h mod q`
//! 2. `e3 = e^3 mod q`
//! 3. `s = P(2^42) mod q` for the limb polynomial `P(X) = sum_j gamma_j(X) * z_j(X)^2 * (xi(X) + j*e(X)) - e3(X) * sum_j gamma_j(X) * N^{b_j}` with `gamma_j(X) = alpha_a(X) * beta_b(X)`.
//!
//! An integer `D(2^42) = 0` is checked as the polynomial identity `D(X) = (X - 2^42) * C(X)` with range-checked carry coefficients `C`. [`check_hints`] mirrors these constraints and is the reference for the circuit.

use ark_ff::PrimeField;
use num_bigint::{BigInt, BigUint, Sign};

use super::{
    Affine, BaseField, ScalarField,
    params::{LegendreParams, NON_RESIDUE},
    proof::LegendreProof,
    transcript::{BatchChallenges, TENSOR_WIDTH, batch_challenges},
};

/// Limb width in bits.
pub const LIMB_BITS: usize = 42;
/// Limbs of a scalar-field element.
pub const SCALAR_LIMBS: usize = 6;
/// Limbs of a challenge.
pub const CHALLENGE_LIMBS: usize = 3;
/// Limbs of the quotient of the main reduction.
pub const MAIN_QUOTIENT_LIMBS: usize = 19;
/// Number of coefficients of the main identity, which is also the number of points it is checked at.
pub const MAIN_COEFFS: usize = MAIN_QUOTIENT_LIMBS + SCALAR_LIMBS - 1;
/// The main identity adds `q * 2^MAIN_OFFSET_SHIFT` so that the reduced value is never negative.
pub const MAIN_OFFSET_SHIFT: usize = 272;
/// Bit bounds (without sign) of the carries of the three reductions.
pub const CARRY_BITS: [usize; 3] = [46, 92, 193];

type Poly = Vec<BigInt>;

fn scalar_modulus() -> BigInt {
    BigInt::from(BigUint::from(ScalarField::MODULUS))
}

fn to_int(x: ScalarField) -> BigInt {
    BigInt::from(BigUint::from(x.into_bigint()))
}

/// Little-endian limbs of a non-negative integer.
fn limbs(x: &BigInt, count: usize) -> Poly {
    let mask = (BigInt::from(1u8) << LIMB_BITS) - 1;
    let out = (0..count)
        .map(|i| (x >> (i * LIMB_BITS)) & &mask)
        .collect::<Poly>();
    assert!(
        x.sign() != Sign::Minus && (x >> (count * LIMB_BITS)).bits() == 0,
        "value does not fit into {count} limbs"
    );
    out
}

fn poly_mul(a: &[BigInt], b: &[BigInt]) -> Poly {
    let mut out = vec![BigInt::from(0u8); a.len() + b.len() - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            out[i + j] += x * y;
        }
    }
    out
}

/// `acc += factor * b`
fn poly_add_scaled(acc: &mut Poly, b: &[BigInt], factor: &BigInt) {
    if acc.len() < b.len() {
        acc.resize(b.len(), BigInt::from(0u8));
    }
    for (x, y) in acc.iter_mut().zip(b) {
        *x += factor * y;
    }
}

fn poly_eval(a: &[BigInt], x: &BigInt) -> BigInt {
    a.iter().rev().fold(BigInt::from(0u8), |acc, c| acc * x + c)
}

/// Carries `C` with `D(X) = (X - 2^LIMB_BITS) * C(X)`. Panics if `D(2^LIMB_BITS) != 0`.
fn carries(d: &[BigInt]) -> Poly {
    let mut out = Vec::with_capacity(d.len() - 1);
    let mut prev = BigInt::from(0u8);
    for coeff in &d[..d.len() - 1] {
        let num: BigInt = &prev - coeff;
        let mask: BigInt = (BigInt::from(1u8) << LIMB_BITS) - 1;
        assert!((&num & &mask).bits() == 0, "carry is not integral");
        prev = num >> LIMB_BITS;
        out.push(prev.clone());
    }
    assert_eq!(
        prev,
        d[d.len() - 1],
        "identity does not vanish at the limb base"
    );
    out
}

/// Prover-supplied auxiliary values for the foreign-field arithmetic of the circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::exhaustive_structs, reason = "Plain witness data")]
pub struct CircuitHints {
    /// `z_k + e*h mod q`
    pub xi: BigInt,
    /// Quotient of the `xi` reduction.
    pub xi_quotient: BigInt,
    /// `e^3 mod q`
    pub e3: BigInt,
    /// Quotient of the `e3` reduction.
    pub e3_quotient: BigInt,
    /// The batched scalar `S mod q`.
    pub s: BigInt,
    /// Limbs of the (offset) quotient of the main reduction.
    pub s_quotient: Vec<BigInt>,
    /// Carries of the `xi`, `e3` and main reductions. May be negative.
    pub carries: [Vec<BigInt>; 3],
}

struct Reductions {
    xi: Poly,
    e3: Poly,
    main: Poly,
}

/// The three integer polynomials that must vanish at `2^LIMB_BITS`, built exactly as the circuit builds them.
fn reductions(
    batch: &BatchChallenges,
    h: ScalarField,
    bits: &[bool],
    proof: &LegendreProof,
    hints: &CircuitHints,
) -> Reductions {
    let q = limbs(&scalar_modulus(), SCALAR_LIMBS);
    let minus_one = BigInt::from(-1i8);
    let e = limbs(&to_int(proof.e), CHALLENGE_LIMBS);
    let xi = limbs(&hints.xi, SCALAR_LIMBS);
    let e3 = limbs(&hints.e3, SCALAR_LIMBS);

    // xi: z_k + e*h - xi - quotient*q
    let mut d_xi = limbs(&to_int(proof.z_k), SCALAR_LIMBS);
    poly_add_scaled(
        &mut d_xi,
        &poly_mul(&e, &limbs(&to_int(h), SCALAR_LIMBS)),
        &BigInt::from(1u8),
    );
    poly_add_scaled(&mut d_xi, &xi, &minus_one);
    poly_add_scaled(
        &mut d_xi,
        &poly_mul(&limbs(&hints.xi_quotient, CHALLENGE_LIMBS + 1), &q),
        &minus_one,
    );

    // e3: e^3 - e3 - quotient*q
    let mut d_e3 = poly_mul(&poly_mul(&e, &e), &e);
    poly_add_scaled(&mut d_e3, &e3, &minus_one);
    poly_add_scaled(
        &mut d_e3,
        &poly_mul(&limbs(&hints.e3_quotient, CHALLENGE_LIMBS + 1), &q),
        &minus_one,
    );

    // main: P + offset - s - quotient*q
    let alphas = batch
        .alphas
        .iter()
        .map(|a| limbs(&to_int(*a), CHALLENGE_LIMBS))
        .collect::<Vec<_>>();
    let betas = batch
        .betas
        .iter()
        .map(|b| limbs(&to_int(*b), CHALLENGE_LIMBS))
        .collect::<Vec<_>>();
    let mut d_main: Poly = Vec::new();
    let mut targets: Poly = Vec::new();
    for (b, beta) in betas.iter().enumerate() {
        let mut inner: Poly = Vec::new();
        let mut mu: Poly = Vec::new();
        for (j, (z_j, bit)) in proof
            .z
            .iter()
            .zip(bits)
            .enumerate()
            .skip(b * TENSOR_WIDTH)
            .take(TENSOR_WIDTH)
        {
            let alpha = &alphas[j % TENSOR_WIDTH];
            let z = limbs(&to_int(*z_j), SCALAR_LIMBS);
            let mut lin = xi.clone();
            poly_add_scaled(&mut lin, &e, &BigInt::from(j));
            let f = poly_mul(&poly_mul(&z, &z), &lin);
            poly_add_scaled(&mut inner, &poly_mul(alpha, &f), &BigInt::from(1u8));
            let target = if *bit { NON_RESIDUE } else { 1 };
            poly_add_scaled(&mut mu, alpha, &BigInt::from(target));
        }
        poly_add_scaled(&mut d_main, &poly_mul(beta, &inner), &BigInt::from(1u8));
        poly_add_scaled(&mut targets, &poly_mul(beta, &mu), &BigInt::from(1u8));
    }
    poly_add_scaled(&mut d_main, &poly_mul(&e3, &targets), &minus_one);
    let offset = scalar_modulus() << MAIN_OFFSET_SHIFT;
    poly_add_scaled(
        &mut d_main,
        &limbs(&offset, MAIN_OFFSET_SHIFT / LIMB_BITS + SCALAR_LIMBS + 1),
        &BigInt::from(1u8),
    );
    poly_add_scaled(&mut d_main, &limbs(&hints.s, SCALAR_LIMBS), &minus_one);
    poly_add_scaled(&mut d_main, &poly_mul(&hints.s_quotient, &q), &minus_one);
    assert_eq!(
        d_main.len(),
        MAIN_COEFFS,
        "unexpected degree of the main identity"
    );

    Reductions {
        xi: d_xi,
        e3: d_e3,
        main: d_main,
    }
}

impl CircuitHints {
    /// Computes the hints for a proof. The proof does not have to be valid.
    ///
    /// # Panics
    /// If `bits` or the proof do not match the parameters.
    #[must_use]
    pub fn new(
        params: &LegendreParams,
        c_k: Affine,
        h: ScalarField,
        bits: &[bool],
        proof: &LegendreProof,
    ) -> Self {
        assert!(
            bits.len() == params.n_bits() && proof.z.len() == params.n_bits(),
            "length mismatch"
        );
        let q = scalar_modulus();
        let batch = batch_challenges(c_k, proof.c_sigma, h, bits);
        let e = to_int(proof.e);
        let xi_full = to_int(proof.z_k) + &e * to_int(h);
        let e3_full = &e * &e * &e;
        let zero = BigInt::from(0u8);
        let mut hints = Self {
            xi: &xi_full % &q,
            xi_quotient: &xi_full / &q,
            e3: &e3_full % &q,
            e3_quotient: &e3_full / &q,
            s: zero.clone(),
            s_quotient: vec![zero; MAIN_QUOTIENT_LIMBS],
            carries: [Vec::new(), Vec::new(), Vec::new()],
        };
        // with s = 0 and quotient = 0 the main polynomial evaluates to the value that has to be reduced
        let value = poly_eval(
            &reductions(&batch, h, bits, proof, &hints).main,
            &(BigInt::from(1u8) << LIMB_BITS),
        );
        assert!(
            value.sign() != Sign::Minus,
            "offset makes the value non-negative"
        );
        hints.s = &value % &q;
        hints.s_quotient = limbs(&(&value / &q), MAIN_QUOTIENT_LIMBS);
        let d = reductions(&batch, h, bits, proof, &hints);
        hints.carries = [carries(&d.xi), carries(&d.e3), carries(&d.main)];
        hints
    }
}

/// Converts a possibly negative integer into the base field.
#[must_use]
pub fn int_to_base(x: &BigInt) -> BaseField {
    let (sign, bytes) = x.to_bytes_le();
    let abs = BaseField::from_le_bytes_mod_order(&bytes);
    if sign == Sign::Minus { -abs } else { abs }
}

/// Mirrors the foreign-field constraints of the circuit: range checks of all hints, and the three carry identities evaluated in the base field at the points `0..len`.
///
/// # Errors
/// Returns a description of the first violated constraint.
pub fn check_hints(
    params: &LegendreParams,
    c_k: Affine,
    h: ScalarField,
    bits: &[bool],
    proof: &LegendreProof,
    hints: &CircuitHints,
) -> Result<(), String> {
    let in_range = |x: &BigInt, bits: usize| x.sign() != Sign::Minus && x.bits() <= bits as u64;
    if !(in_range(&hints.xi, 251) && in_range(&hints.e3, 251) && in_range(&hints.s, 251)) {
        return Err("reduced value out of range".into());
    }
    if !(in_range(&hints.xi_quotient, 128) && in_range(&hints.e3_quotient, 128)) {
        return Err("quotient out of range".into());
    }
    if hints.s_quotient.len() != MAIN_QUOTIENT_LIMBS
        || !hints.s_quotient.iter().all(|l| in_range(l, LIMB_BITS))
    {
        return Err("main quotient out of range".into());
    }
    if bits.len() != params.n_bits() || proof.z.len() != params.n_bits() {
        return Err("length mismatch".into());
    }
    let batch = batch_challenges(c_k, proof.c_sigma, h, bits);
    let d = reductions(&batch, h, bits, proof, hints);
    for (name, d, carries, carry_bits) in [
        ("xi", &d.xi, &hints.carries[0], CARRY_BITS[0]),
        ("e3", &d.e3, &hints.carries[1], CARRY_BITS[1]),
        ("main", &d.main, &hints.carries[2], CARRY_BITS[2]),
    ] {
        if carries.len() + 1 != d.len() {
            return Err(format!("{name}: wrong number of carries"));
        }
        let offset = BigInt::from(1u8) << carry_bits;
        if !carries
            .iter()
            .all(|c| in_range(&(c + &offset), carry_bits + 1))
        {
            return Err(format!("{name}: carry out of range"));
        }
        // the base-field coefficients must be the integer coefficients: they are far below the field size
        if !d.iter().all(|c| c.bits() < 250) {
            return Err(format!("{name}: coefficient overflow"));
        }
        let base = BaseField::from(1u64 << LIMB_BITS);
        for point in 0..d.len() {
            let x = BaseField::from(point as u64);
            let eval = |poly: &[BigInt]| {
                poly.iter()
                    .rev()
                    .fold(BaseField::from(0u64), |acc, c| acc * x + int_to_base(c))
            };
            if eval(d) != (x - base) * eval(carries) {
                return Err(format!("{name}: identity fails at point {point}"));
            }
        }
    }
    Ok(())
}

/// All input signals of the verification circuit, by signal name, in the order the circuit declares them.
#[must_use]
pub fn circuit_inputs(
    params: &LegendreParams,
    c_k: Affine,
    h: ScalarField,
    bits: &[bool],
    proof: &LegendreProof,
) -> Vec<(&'static str, Vec<BaseField>)> {
    use super::transcript::scalar_to_base;
    let hints = CircuitHints::new(params, c_k, h, bits, proof);
    let point = |p: Affine| vec![p.x, p.y];
    let scalar = |x: ScalarField| vec![scalar_to_base(x)];
    let ints = |xs: &[BigInt]| xs.iter().map(int_to_base).collect::<Vec<_>>();
    vec![
        ("c_k", point(c_k)),
        ("h", scalar(h)),
        (
            "bits",
            bits.iter()
                .map(|b| BaseField::from(u64::from(*b)))
                .collect(),
        ),
        ("c_sigma", point(proof.c_sigma)),
        ("t1", point(proof.t1)),
        ("t2", point(proof.t2)),
        ("e", scalar(proof.e)),
        ("z", proof.z.iter().map(|z| scalar_to_base(*z)).collect()),
        ("z_nu", scalar(proof.z_nu)),
        ("z_k", scalar(proof.z_k)),
        ("z_rho", scalar(proof.z_rho)),
        ("z_tau", scalar(proof.z_tau)),
        ("xi", ints(std::slice::from_ref(&hints.xi))),
        (
            "xi_quotient",
            ints(std::slice::from_ref(&hints.xi_quotient)),
        ),
        ("e3", ints(std::slice::from_ref(&hints.e3))),
        (
            "e3_quotient",
            ints(std::slice::from_ref(&hints.e3_quotient)),
        ),
        ("s", ints(std::slice::from_ref(&hints.s))),
        ("s_quotient", ints(&hints.s_quotient)),
        ("carry_xi", ints(&hints.carries[0])),
        ("carry_e3", ints(&hints.carries[1])),
        ("carry_main", ints(&hints.carries[2])),
    ]
}

#[cfg(test)]
mod tests;
