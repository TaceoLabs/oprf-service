//! Fiat-Shamir transcript of the Legendre evaluation proof.
//!
//! A Poseidon2 sponge (state size 16, capacity 1) over the `BabyJubJub` base field, which is the native field of the proof system, so that the same transcript can be recomputed cheaply in a circuit.

use ark_ff::{BigInteger, PrimeField, Zero};

use super::{Affine, BaseField, ScalarField};

/// Bit length of all Fiat-Shamir challenges. Three 42-bit limbs in the circuit.
pub const CHALLENGE_BITS: usize = 126;

/// The batching coefficients have tensor structure `gamma_j = alpha_{j mod 16} * beta_{j div 16}`.
pub const TENSOR_WIDTH: usize = 16;

const RATE: usize = 15;
const PACK_BITS: usize = 248;
const PROOF_DS: &[u8] = b"Legendre OPRF proof";

/// Embeds a scalar-field element into the (larger) base field.
#[must_use]
pub fn scalar_to_base(x: ScalarField) -> BaseField {
    BaseField::from_le_bytes_mod_order(&x.into_bigint().to_bytes_le())
}

/// Sponge state after the statement has been absorbed, plus the batching challenges derived from it.
#[derive(Debug, Clone)]
pub struct BatchChallenges {
    /// `alpha_0..alpha_15`.
    pub alphas: Vec<ScalarField>,
    /// `beta_0..beta_{ceil(n/16)-1}`.
    pub betas: Vec<ScalarField>,
    state: [BaseField; 16],
}

impl BatchChallenges {
    /// The batching coefficient `gamma_j` for output bit `j`.
    #[must_use]
    pub fn gamma(&self, j: usize) -> ScalarField {
        self.alphas[j % TENSOR_WIDTH] * self.betas[j / TENSOR_WIDTH]
    }

    /// All batching coefficients `gamma_0..gamma_{n-1}`.
    #[must_use]
    pub fn gammas(&self, n_bits: usize) -> Vec<ScalarField> {
        (0..n_bits).map(|j| self.gamma(j)).collect()
    }
}

fn absorb(state: &mut [BaseField; 16], input: &[BaseField]) {
    for chunk in input.chunks(RATE) {
        for (s, c) in state[1..].iter_mut().zip(chunk) {
            *s += c;
        }
        *state = poseidon2::bn254::t16::permutation(state);
    }
}

/// Splits a field element into two [`CHALLENGE_BITS`]-bit challenges (bits `0..126` and `126..252` of its canonical representation).
fn split_challenges(x: BaseField) -> [ScalarField; 2] {
    let bits = x.into_bigint().to_bits_le();
    let take = |lo: usize| {
        let chunk = &bits[lo..lo + CHALLENGE_BITS];
        ScalarField::from_bigint(<ScalarField as PrimeField>::BigInt::from_bits_le(chunk))
            .expect("126 bits fit into the scalar field")
    };
    [take(0), take(CHALLENGE_BITS)]
}

/// Packs bits little-endian into field elements, [`PACK_BITS`] bits per element.
///
/// # Panics
/// Never: [`PACK_BITS`] bits always fit into a field element.
#[must_use]
pub fn pack_bits(bits: &[bool]) -> Vec<BaseField> {
    bits.chunks(PACK_BITS)
        .map(|chunk| {
            BaseField::from_bigint(<BaseField as PrimeField>::BigInt::from_bits_le(chunk))
                .expect("248 bits fit into the base field")
        })
        .collect()
}

/// Derives the batching challenges from the statement: key commitment, commitment to the witness vector, PRF input and claimed output bits.
///
/// # Panics
/// If there are more output bits than [`super::params::MAX_BITS`].
#[must_use]
pub fn batch_challenges(
    c_k: Affine,
    c_sigma: Affine,
    h: ScalarField,
    bits: &[bool],
) -> BatchChallenges {
    let n_bits = bits.len();
    let mut state = [BaseField::zero(); 16];
    state[0] = BaseField::from_be_bytes_mod_order(PROOF_DS);
    let mut input = vec![
        c_k.x,
        c_k.y,
        c_sigma.x,
        c_sigma.y,
        scalar_to_base(h),
        BaseField::from(u64::try_from(n_bits).expect("fits into u64")),
    ];
    input.extend(pack_bits(bits));
    absorb(&mut state, &input);

    let n_betas = n_bits.div_ceil(TENSOR_WIDTH);
    let n_elems = (TENSOR_WIDTH + n_betas).div_ceil(2);
    assert!(n_elems <= RATE, "too many output bits for one squeeze");
    let mut challenges = state[1..=n_elems]
        .iter()
        .flat_map(|x| split_challenges(*x))
        .collect::<Vec<_>>();
    challenges.truncate(TENSOR_WIDTH + n_betas);
    let betas = challenges.split_off(TENSOR_WIDTH);
    BatchChallenges {
        alphas: challenges,
        betas,
        state,
    }
}

/// Derives the sigma-protocol challenge `e` from the batching state and the prover's first message.
#[must_use]
pub fn sigma_challenge(
    batch: &BatchChallenges,
    a: Affine,
    a_k: Affine,
    t0: Affine,
    t1: Affine,
    t2: Affine,
) -> ScalarField {
    let mut state = batch.state;
    absorb(
        &mut state,
        &[a.x, a.y, a_k.x, a_k.y, t0.x, t0.y, t1.x, t1.y, t2.x, t2.y],
    );
    split_challenges(state[1])[0]
}
