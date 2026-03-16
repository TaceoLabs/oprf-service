use crate::oprf::{Affine, BaseField};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt, BigInteger, Field, One, PrimeField, Zero};
use subtle::{Choice, ConstantTimeEq};

const HASH_TO_FIELD_DS: &[u8] = b"OPRF_HashToField_BabyJubJub";

// Returns the domain separator for the hash_to_field function as a field element
fn get_hash_to_field_ds() -> BaseField {
    BaseField::from_be_bytes_mod_order(HASH_TO_FIELD_DS)
}

fn ct_is_zero<F: PrimeField>(v: F) -> Choice {
    // Ideally the ark ecosystem would support subtle, so this is currently
    // the best thing we can do. Serialize the elements and then compare the
    // byte representation.
    let mut lhs_v = Vec::with_capacity(v.uncompressed_size());
    let rhs_v = vec![0; v.uncompressed_size()];
    v.serialize_uncompressed(&mut lhs_v)
        .expect("Can serialize primefield into pre-allocated vec");
    lhs_v.ct_eq(&rhs_v)
}

fn ct_select<F: PrimeField>(lhs: F, rhs: F, choice: Choice) -> F {
    // Ideally the ark ecosystem would support subtle.
    let choice = F::from(choice.unwrap_u8());
    rhs + (lhs - rhs) * choice
}

fn ct_is_square<F: PrimeField>(x: F) -> Choice {
    let x = x.pow(F::MODULUS_MINUS_ONE_DIV_TWO);
    // Ideally the ark ecosystem would support subtle, so this is currently
    // the best thing we can do. Serialize the elements and then compare the
    // byte representation.
    let mut x_v = Vec::with_capacity(x.uncompressed_size());
    let mut one_v = Vec::with_capacity(x.uncompressed_size());
    let zero_v = vec![0; x.uncompressed_size()];
    x.serialize_uncompressed(&mut x_v)
        .expect("Can serialize primefield into pre-allocated vec");
    F::one()
        .serialize_uncompressed(&mut one_v)
        .expect("Can serialize primefield into pre-allocated vec");
    let is_zero = x_v.ct_eq(&zero_v);
    let is_one = x_v.ct_eq(&one_v);
    is_zero ^ is_one
}

/// A curve encoding function that maps a field element to a point on the curve, based on [RFC9380, Section 3](https://www.rfc-editor.org/rfc/rfc9380.html#name-encoding-byte-strings-to-el).
///
/// As mentioned in the RFC, this encoding is non uniformly random in E, as this can only hit about half of the of the curve points.
pub fn encode_to_curve(input: BaseField) -> Affine {
    // Map the input to a point on the curve using Elligator2
    let u = hash_to_field(input);
    let q = map_to_curve_twisted_edwards(u);
    q.clear_cofactor()
}

/// A curve encoding function that maps a field element to a point on the curve, based on [RFC9380, Section 3](https://www.rfc-editor.org/rfc/rfc9380.html#name-encoding-byte-strings-to-el).
///
/// In contrast to `encode_to_curve`, this function uses a two-step mapping to ensure that the output is uniformly random over the curve.
#[allow(
    dead_code,
    reason = "currently not used but maybe relevant in the future"
)]
pub fn hash_to_curve(input: BaseField) -> Affine {
    // Map the input to a point on the curve using Elligator2
    let [u0, u1] = hash_to_field2(input);
    let q0 = map_to_curve_twisted_edwards(u0);
    let q1 = map_to_curve_twisted_edwards(u1);
    let r = (q0 + q1).into_affine();
    r.clear_cofactor()
}

/// An implementation of `hash_to_field` based on [RFC9380](https://www.rfc-editor.org/rfc/rfc9380.html).
/// Since we use poseidon as the hash function, this automatically ensures the property that the output is a uniformly random field element, without needing to sample extra output and reduce mod p.
fn hash_to_field(input: BaseField) -> BaseField {
    // hash the input to a field element using poseidon hash
    let output =
        poseidon2::bn254::t3::permutation(&[get_hash_to_field_ds(), input, BaseField::zero()]);
    output[1] // Return the first element of the state as the field element, element 0 is the capacity of the sponge
}

/// An implementation of `hash_to_field` based on [RFC9380](https://www.rfc-editor.org/rfc/rfc9380.html).
/// Since we use poseidon as the hash function, this automatically ensures the property that the output is a uniformly random field element, without needing to sample extra output and reduce mod p.
fn hash_to_field2(input: BaseField) -> [BaseField; 2] {
    // hash the input to a field element using poseidon hash
    // use 1 instead of 0 in input[2] as an additional domain separation from the 1-field hash_to_field
    let output =
        poseidon2::bn254::t3::permutation(&[get_hash_to_field_ds(), input, BaseField::one()]);

    [output[1], output[2]] // Return the first two elements of the state as the field elements, element 0 is the capacity of the sponge
}

/// Maps the input to a point on the curve, without anyone knowing the DLOG of the curve point.
///
/// This is based on `map_to_curve` from [RFC9380](https://www.rfc-editor.org/rfc/rfc9380.html).
/// We use section 6.8 ("Mappings for Twisted Edwards Curves") to map the input to a point on the curve.
/// This internally uses a birationally equivalent Montgomery curve to perform the mapping, then uses a rational map to convert the point to the Edwards curve.
fn map_to_curve_twisted_edwards(input: BaseField) -> Affine {
    let (s, t) = map_to_curve_elligator2(input);
    let (v, w) = rational_map_mont_to_twisted_edwards(s, t);
    Affine { x: v, y: w }
}

/// Maps the input to a point on the Montgomery curve, without anyone knowing the DLOG of the curve point.
///
/// Returns the s and t coordinates of the point on the Montgomery curve.
///
/// let the Montgomery curve be defined by the equation $K*t^2 = s^3 + J*s^2 + s$.
/// We follow the Elligator2 mapping as described in [RFC9380, Section 6.7.1](https://www.rfc-editor.org/rfc/rfc9380.html#name-elligator-2-method).
fn map_to_curve_elligator2(input: BaseField) -> (BaseField, BaseField) {
    // constant c1 = J/K;
    let j = BaseField::from(168_698);
    // since k = 1 for Baby JubJub, this simplifies a few operations below
    let c1 = j;
    // The constant c2 would be 1/(k*k) = 1, so we also skip it
    // constant Z = 5, based on RFC9380, Appendix H.3.
    // ```sage
    // # Argument:
    // # - F, a field object, e.g., F = GF(2^255 - 19)
    // def find_z_ell2(F):
    //     ctr = F.gen()
    //     while True:
    //         for Z_cand in (F(ctr), F(-ctr)):
    //             # Z must be a non-square in F.
    //             if is_square(Z_cand):
    //                 continue
    //             return Z_cand
    //         ctr += 1
    // # BaseField of Baby JubJub curve:
    // F = GF(21888242871839275222246405745257275088548364400416034343698204186575808495617)
    // find_z_ell2(F) # 5
    // ```
    let z = BaseField::from(5);
    let tv1 = input * input;
    let tv1 = z * tv1;
    let e = ct_is_zero(tv1 + BaseField::ONE);
    let tv1 = ct_select(BaseField::zero(), tv1, e);
    let x1 = tv1 + BaseField::one();
    let x1 = inv0(x1);
    let x1 = -c1 * x1;
    let gx1 = x1 + c1;
    // normally the calculation of gx1 below would involve c2, but since c2 = 1 for Baby JubJub, we can simplify it
    let gx1 = gx1 * x1.square() + x1;
    let x2 = -x1 - c1;
    let gx2 = tv1 * gx1;
    let e2 = ct_is_square(gx1);
    let (x, y2) = (ct_select(x1, x2, e2), ct_select(gx1, gx2, e2));
    let y = y2
        .sqrt()
        .expect("y2 should be a square based on our conditional selection above");
    let e3 = Choice::from(u8::from(sgn0(y)));
    let y = ct_select(-y, y, e2 ^ e3);
    // the reduced (s,t) would normally be (x*k,y*k), but since k = 1 for Baby JubJub, we can skip that step
    (x, y)
}

/// Converts a point from Montgomery to Twisted Edwards using the rational map.
///
/// This is based on appendix D1 of [RFC9380](https://www.rfc-editor.org/rfc/rfc9380.html).
///
/// Let the twisted Edwards curve be defined by the equation $a*v^2 + w^2 = 1 + d*v^2*w^2$.
/// let the Montgomery curve be defined by the equation $K*t^2 = s^3 + J*s^2 + s$, with
/// $J = 2 * (a + d) / (a - d)$ and $K = 4 / (a - d)$.
///
/// For the concrete case of `BabyJubJub`, we have:
/// - $K = 1$
/// - $J = 168698$
/// - $a = 168700$
/// - $d = 168696$
///
/// Input: (s, t), a point on the curve $K * t^2 = s^3 + J * s^2 + s$.
/// Output: (v, w), a point on the equivalent twisted Edwards curve.
/// (This function also handles exceptional cases where the point is at infinity correctly.)
fn rational_map_mont_to_twisted_edwards(s: BaseField, t: BaseField) -> (BaseField, BaseField) {
    // Convert the point from Montgomery to Twisted Edwards using the rational map
    let tv1 = s + BaseField::one();
    let tv2 = tv1 * t;
    let tv2 = inv0(tv2);
    let v = tv1 * tv2;
    let v = v * s;
    let w = tv2 * t;
    let tv1 = s - BaseField::one();
    let w = w * tv1;
    let e = ct_is_zero(tv2);
    let w = ct_select(BaseField::one(), w, e);
    (v, w)
}

trait Inv0Constants: PrimeField {
    const MODULUS_MINUS_2: Self::BigInt;
}

impl Inv0Constants for BaseField {
    const MODULUS_MINUS_2: Self::BigInt =
        BigInt!("21888242871839275222246405745257275088548364400416034343698204186575808495615");
}

/// Computes the inverse of a field element, returning zero if the element is zero.
fn inv0<F: PrimeField + Inv0Constants>(x: F) -> F {
    x.pow(F::MODULUS_MINUS_2)
}

/// Computes the `sgn0` function for a field element, based on the definition in [RFC9380, Section 4.1](https://www.rfc-editor.org/rfc/rfc9380.html#name-the-sgn0-function).
fn sgn0<F: PrimeField>(x: F) -> bool {
    x.into_bigint().is_odd()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use std::str::FromStr;

    #[test]
    fn test_map_to_curve_twisted_edwards() {
        let input = BaseField::from(42);
        let (s, t) = map_to_curve_elligator2(input);
        let (v, w) = rational_map_mont_to_twisted_edwards(s, t);
        let point = Affine { x: v, y: w };
        assert!(point.is_on_curve());
    }
    #[test]
    fn test_map_to_curve_twisted_edwards_rand() {
        for _ in 0..100 {
            // Test with random inputs
            let input = BaseField::rand(&mut rand::thread_rng());
            let (s, t) = map_to_curve_elligator2(input);
            let (v, w) = rational_map_mont_to_twisted_edwards(s, t);
            let point = Affine { x: v, y: w };
            assert!(point.is_on_curve(), "Failed for input: {input:?}");
        }
    }

    #[test]
    fn test_encode_to_curve() {
        let input = BaseField::from(42);
        let point = encode_to_curve(input);
        assert!(point.is_on_curve());

        let expected_point = Affine {
            x: BaseField::from_str(
                "1368536874988764403285491466492470225763829673979223271328990939656695174872",
            )
            .expect("Valid basefield element"),
            y: BaseField::from_str(
                "5918944744409897789209151589310931911112404737084812644826989226820698253694",
            )
            .expect("Valid basefield element"),
        };
        assert_eq!(expected_point, point);
    }
    #[test]
    fn test_hash_to_curve() {
        let input = BaseField::from(42);
        let point = hash_to_curve(input);
        assert!(point.is_on_curve());
    }

    #[test]
    fn test_ct_is_zero() {
        assert_eq!(ct_is_zero(BaseField::zero()).unwrap_u8(), 1);
    }

    #[test]
    fn test_inv0() {
        for _ in 0..100 {
            let input = BaseField::rand(&mut rand::thread_rng());
            let output = inv0(input);
            assert_eq!(
                input * output,
                if input.is_zero() {
                    BaseField::zero()
                } else {
                    BaseField::ONE
                }
            );
        }

        assert_eq!(inv0(BaseField::zero()), BaseField::zero());
    }

    #[test]
    fn test_ct_is_square() {
        for i in 0..100 {
            let input = BaseField::from(i);
            let output = ct_is_square(input);
            let is = input.sqrt().is_some();
            assert_eq!(is, bool::from(output));
        }
    }
}
