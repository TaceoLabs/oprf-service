//! Key generation and secret sharing primitives for the threshold OPRF protocol.
//!
//! This module provides utilities to generate random or reshared polynomials for secret sharing, compute and commit to their coefficients, distribute encrypted shares to parties, and perform related helpers such as commitment and share accumulation.
//!
//! Commitments are produced both to the full coefficient vector (via a Poseidon2 sponge hash) and to the polynomial constant term (the secret, as a curve point). Secure share distribution is implemented using Diffie-Hellman-based symmetric encryption per node.
//!
//! We refer to [design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf) for more information about the threshold OPRF protocol.

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM as _};
use ark_ff::{PrimeField, UniformRand, Zero};
use itertools::izip;
use rand::{CryptoRng, Rng};
use zeroize::ZeroizeOnDrop;

use crate::{
    oprf::{Affine, BaseField, Projective, ScalarField},
    shamir,
};

// From SAFE-API paper (https://eprint.iacr.org/2023/522.pdf)
// Absorb 2, squeeze 1,  domainsep = 0x4142
// [0x80000002, 0x00000001, 0x4142]
const T1_DS: u128 = 0x80000002000000014142;
const COEFF_DS: &[u8] = b"KeyGenPolyCoeff";

/// Represents the generated polynomial for a single party during key generation.
///
/// This structure stores the polynomial coefficients (where the constant term, `a_0`, is the party's generated secret) and the corresponding commitments to the coefficients as a whole and `a_0` specifically.
///
/// The polynomial is of the form:
/// `f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_n*x^n`,
/// where `a_0` (or simply `a`) is the secret being shared.
///
/// Commitments are constructed as follows:
/// - The secret commitment is `comm_share = G * a_0`, where `G` is the curve generator.
/// - The remaining coefficients are committed by hashing them in chunks using a Poseidon2 sponge construction
///   (with a domain separator included for context separation), resulting in a hash commitment `comm_coeffs`.
///
/// During key generation, each party creates shares of this polynomial for their nodes. When all individual shares from different parties are accumulated, the resulting shares correspond to the final shared secret key (the sum of individual secrets).
///
/// Parties shall forget the polynomial after key-generation.
#[derive(ZeroizeOnDrop)]
pub struct KeyGenPoly {
    poly: Vec<ScalarField>,
    comm_share: Affine,
    comm_coeffs: BaseField,
}

// Returns the used domain separator as a field element for the encryption
fn get_t1_ds() -> BaseField {
    BaseField::from(T1_DS)
}

// Returns the used domain separator as a field element for the commitment to the coefficients
fn get_coeff_ds() -> BaseField {
    BaseField::from_be_bytes_mod_order(COEFF_DS)
}

/// Accumulates the provided shares by adding them together.
pub fn accumulate_shares(shares: &[ScalarField]) -> ScalarField {
    shares.iter().fold(ScalarField::zero(), |acc, x| acc + x)
}

/// Combines the provided shares using Lagrange coefficients to reconstruct the secret (or key share).
///
/// # Arguments
/// * `shares` - The shares to be combined.
/// * `lagrange` - Lagrange interpolation coefficients.
///
/// # Returns
/// Accumulated (reconstructed) secret or key share.
///
/// # Panics
/// This method panics if the len of `shares` and `lagrange` do not match. This method expects this check at callsite.
pub fn accumulate_lagrange_shares(shares: &[ScalarField], lagrange: &[ScalarField]) -> ScalarField {
    assert!(shares.len() == lagrange.len());
    let shares = &shares[0..lagrange.len()];
    let mut result = ScalarField::zero();
    for (share, l) in izip!(shares.iter(), lagrange.iter()) {
        result += *share * *l;
    }
    result
}

// Interprets an element in the scalarfield of babyjubjub as basefield element.
// Needed for using those elements in poseidon2.
fn interpret_scalarfield_as_basefield(s: ScalarField) -> BaseField {
    let s_bigint = s.into_bigint();
    BaseField::from_bigint(s_bigint).expect("scalar field element fits in base field")
}

// Interprets an element in the basefield of babyjubjub as scalarfield element.
// As the basefield modulus is larger than the scalarfield, this operation may potentially fail. Iff the basefield element doesn't fit into the scalarfield, returns None.
fn basefield_as_scalarfield_if_fits(s: BaseField) -> Option<ScalarField> {
    let s_bigint = s.into_bigint();
    ScalarField::from_bigint(s_bigint)
}

// Diffie-Hellman key derivation.
fn dh_key_derivation(my_sk: &ScalarField, their_pk: Affine) -> BaseField {
    (their_pk * my_sk).into_affine().x
}

// Use Poseidon2 for symmetric encryption.
fn sym_encrypt(key: BaseField, msg: ScalarField, nonce: BaseField) -> BaseField {
    let ks = poseidon2::bn254::t3::permutation(&[get_t1_ds(), key, nonce]);
    ks[1] + interpret_scalarfield_as_basefield(msg)
}

// Use Poseidon2 for symmetric decryption.
fn sym_decrypt(key: BaseField, ciphertext: BaseField, nonce: BaseField) -> Option<ScalarField> {
    let ks = poseidon2::bn254::t3::permutation(&[get_t1_ds(), key, nonce]);
    let msg = ciphertext - ks[1];
    basefield_as_scalarfield_if_fits(msg)
}

/// Decrypts a ciphertext using a symmetric key derived from Diffie-Hellman between `my_sk` and `their_pk`.
///
/// Returns the plaintext if decryption succeeds, or `None` otherwise.
pub fn decrypt_share(
    my_sk: &ScalarField,
    their_pk: Affine,
    ciphertext: BaseField,
    nonce: BaseField,
) -> Option<ScalarField> {
    let symm_key = dh_key_derivation(my_sk, their_pk);
    sym_decrypt(symm_key, ciphertext, nonce)
}

/// Multiplies and accumulates public keys with provided Lagrange coefficients using variable-base MSM.
///
/// Only the first `lagrange.len()` public keys are used.
///
/// # Arguments
/// * `pks` - Array of public keys.
/// * `lagrange` - Lagrange interpolation coefficients.
///
/// # Returns
/// The accumulated public key (as an affine point).
///
/// # Panics
/// This method panics if the len of `shares` is lower than the len of `lagrange`. This method expects this check at callsite.
pub fn accumulate_lagrange_pks(pks: &[Affine], lagrange: &[ScalarField]) -> Affine {
    assert!(pks.len() >= lagrange.len());
    let pks = &pks[0..lagrange.len()];
    Projective::msm_unchecked(pks, lagrange).into_affine()
}

impl KeyGenPoly {
    /// Creates a new polynomial by creating random coefficients with the provided random generator and commits to the coefficients and secret.
    pub fn new<R: Rng + CryptoRng>(rng: &mut R, degree: usize) -> Self {
        let secret = ScalarField::rand(rng);
        // Call reshare with a random generated secret
        Self::reshare(rng, secret, degree)
    }

    /// Creates a new polynomial for resharing.
    ///
    /// In contrast to [`Self::new`], this method doesn't create a random secret, but sets the provided `my_share` as secret. This value shall be a share from a previous key-gen process.
    pub fn reshare<R: Rng + CryptoRng>(rng: &mut R, my_share: ScalarField, degree: usize) -> Self {
        let mut poly = Vec::with_capacity(degree + 1);
        poly.push(my_share);
        for _ in 0..degree {
            poly.push(ScalarField::rand(rng));
        }

        let (comm_share, comm_coeffs) = Self::commit_poly(&poly);

        Self {
            poly,
            comm_share,
            comm_coeffs,
        }
    }

    /// Returns a reference to the coefficients.
    ///
    /// **Note**: use with care! The coefficients are sensitive data.
    pub fn coeffs(&self) -> &[ScalarField] {
        &self.poly
    }

    /// Commits to the polynomial coefficients and the generated secret.
    ///
    /// This function generates two commitments:
    /// - `comm_share`: A commitment to the secret (the constant term of the polynomial) created by multiplying the curve generator with `poly[0]`.
    /// - `comm_coeffs`: A hash-based commitment to the remaining polynomial coefficients using the Poseidon2 permutation in a "sponge" construction.
    ///
    /// The Poseidon2 sponge is initialized with a domain separator. The remaining polynomial coefficients are grouped in chunks of three and added to the sponge state, which is then permuted. The output `comm_coeffs` is the second state element after all coefficients have been absorbed.
    ///
    /// # Returns
    ///
    /// A tuple containing the commitment to the secret and the commitment to the coefficients.
    fn commit_poly(poly: &[ScalarField]) -> (Affine, BaseField) {
        let comm_share = Affine::generator() * poly[0];

        // Sponge mode for hashing
        let mut state = [BaseField::zero(); 4];
        state[0] = get_coeff_ds(); // domain separator in capacity
        for coeffs_ in poly[1..].chunks(3) {
            for (s, c) in izip!(state.iter_mut().skip(1), coeffs_) {
                *s += interpret_scalarfield_as_basefield(*c);
            }
            poseidon2::bn254::t4::permutation_in_place(&mut state);
        }
        let comm_coeffs = state[1];
        (comm_share.into_affine(), comm_coeffs)
    }

    /// Generates an encrypted key share and its commitment for a recipient party.
    ///
    /// - Computes the recipient party's Shamir share (`share`) by evaluating the secret polynomial at the party's index.
    /// - Encrypts the share using a symmetric key derived via Diffie-Hellman between `my_sk` and `their_pk`.
    /// - Returns the commitment to the share (as a curve point) and the encrypted share.
    ///
    /// # Arguments
    /// * `id` - Party index (0-based).
    /// * `my_sk` - Sender's private key.
    /// * `their_pk` - Recipient's public key.
    /// * `nonce` - Nonce for symmetric encryption.
    ///
    /// # Returns
    /// Commitment to the share and the encrypted share.
    ///
    /// # Panics
    /// This method panics if `their_pk` is not on the curve and is not in the large subgroup. We expect callsite to enforce those constraints.
    pub fn gen_share(
        &self,
        id: usize,
        my_sk: &ScalarField,
        their_pk: Affine,
        nonce: BaseField,
    ) -> (Affine, BaseField) {
        assert!(
            their_pk.is_on_curve() && their_pk.is_in_correct_subgroup_assuming_on_curve(),
            "their_pk must be on curve and in the large subgroup of the curve"
        );
        let index = ScalarField::from((id + 1) as u64);
        let share = shamir::evaluate_poly(&self.poly, index);

        let symm_key = dh_key_derivation(my_sk, their_pk);
        let ciphertext = sym_encrypt(symm_key, share, nonce);

        // The share is random, so no need for randomness here
        let commitment = Affine::generator() * share;
        (commitment.into_affine(), ciphertext)
    }

    /// Returns the degree of the polynomial.
    pub fn degree(&self) -> usize {
        self.poly.len() - 1
    }

    /// Returns the commitment to the secret `a_0`.
    pub fn get_pk_share(&self) -> Affine {
        self.comm_share
    }

    /// Returns the commitment to the coefficients.
    pub fn get_coeff_commitment(&self) -> BaseField {
        self.comm_coeffs
    }
}

#[cfg(test)]
mod tests {

    use itertools::Itertools;

    use super::*;

    fn accumulate_pks(pks: &[Affine]) -> Affine {
        pks.iter()
            .fold(ark_babyjubjub::EdwardsProjective::zero(), |acc, x| acc + *x)
            .into_affine()
    }

    fn lagrange_coeffs(degree: usize) -> Vec<ScalarField> {
        let indices: Vec<u64> = (1..=degree as u64 + 1).collect();
        shamir::lagrange_from_coeff(&indices)
    }

    fn test_distributed_keygen(num_parties: usize, degree: usize) {
        let mut rng = rand::thread_rng();

        // Init party secret keys and public keys
        let party_sks = (0..num_parties)
            .map(|_| ScalarField::rand(&mut rng))
            .collect::<Vec<_>>();
        let party_pks = party_sks
            .iter()
            .map(|x| (Affine::generator() * *x).into_affine())
            .collect::<Vec<_>>();

        // 1. Each party commits to a random polynomial
        let party_polys = (0..num_parties)
            .map(|_| KeyGenPoly::new(&mut rng, degree))
            .collect::<Vec<_>>();

        // The desired result based on the created polys
        let should_sk = party_polys
            .iter()
            .fold(ScalarField::zero(), |acc, x| acc + x.poly[0]);
        let should_pk = Affine::generator() * should_sk;

        // pk from commitments
        let pks = party_polys
            .iter()
            .map(|x| x.get_pk_share())
            .collect::<Vec<_>>();
        assert_eq!(should_pk, accumulate_pks(&pks));

        // 2. Each party creates all shares
        let mut encryption_nonces = Vec::with_capacity(num_parties);
        let mut party_ciphers = Vec::with_capacity(num_parties);
        for (poly, my_sk) in izip!(party_polys, party_sks.iter()) {
            let mut nonces = Vec::with_capacity(num_parties);
            let mut cipher = Vec::with_capacity(num_parties);
            for (i, their_pk) in party_pks.iter().enumerate() {
                let nonce = BaseField::rand(&mut rng);
                let (_, ciphertext) = poly.gen_share(i, my_sk, *their_pk, nonce);
                nonces.push(nonce);
                cipher.push(ciphertext);
            }
            encryption_nonces.push(nonces);
            party_ciphers.push(cipher);
        }

        // 3. Each party decrypts their shares
        let mut result_shares = Vec::with_capacity(num_parties);
        for (i, my_sk) in party_sks.iter().enumerate() {
            let mut my_shares = Vec::with_capacity(num_parties);
            for (cipher, nonce, their_pk) in izip!(
                party_ciphers.iter(),
                encryption_nonces.iter(),
                party_pks.iter()
            ) {
                let share = decrypt_share(my_sk, *their_pk, cipher[i], nonce[i])
                    .expect("decryption should work");
                my_shares.push(share);
            }
            let my_share = accumulate_shares(&my_shares);
            result_shares.push(my_share);
        }

        // Check if the correct secret share is obtained
        let sk_from_shares =
            shamir::test_utils::reconstruct_random_shares(&result_shares, degree, &mut rng);
        assert_eq!(should_sk, sk_from_shares);

        // Check if the correct public key is obtained
        let pk_shares = result_shares
            .iter()
            .map(|x| Affine::generator() * *x)
            .collect::<Vec<_>>();
        let pk_from_shares =
            shamir::test_utils::reconstruct_random_pointshares(&pk_shares, degree, &mut rng);
        assert_eq!(should_pk, pk_from_shares);
    }

    #[test]
    fn test_distributed_keygen_3_1() {
        test_distributed_keygen(3, 1);
    }

    #[test]
    fn test_distributed_keygen_31_15() {
        test_distributed_keygen(31, 15);
    }

    fn test_reshare(num_parties: usize, degree: usize) {
        let mut rng = rand::thread_rng();

        // Init party secret keys and public keys
        let party_sks = (0..num_parties)
            .map(|_| ScalarField::rand(&mut rng))
            .collect::<Vec<_>>();
        let party_pks = party_sks
            .iter()
            .map(|x| (Affine::generator() * *x).into_affine())
            .collect::<Vec<_>>();

        ///////////////////////////////////////////////////
        // PHASE 1: Initial key generation

        // 1. Each party commits to a random polynomial
        let party_polys = (0..num_parties)
            .map(|_| KeyGenPoly::new(&mut rng, degree))
            .collect::<Vec<_>>();

        // The desired result based on the created polys
        let should_sk = party_polys
            .iter()
            .fold(ScalarField::zero(), |acc, x| acc + x.poly[0]);
        let should_pk = Affine::generator() * should_sk;

        // pk from commitments
        let pks = party_polys
            .iter()
            .map(|x| x.get_pk_share())
            .collect::<Vec<_>>();
        assert_eq!(should_pk, accumulate_pks(&pks));

        // 2. Each party creates all shares
        let mut encryption_nonces = Vec::with_capacity(num_parties);
        let mut party_ciphers = Vec::with_capacity(num_parties);
        let mut party_commitments = Vec::with_capacity(num_parties);
        for (poly, my_sk) in izip!(party_polys, party_sks.iter()) {
            let mut nonces = Vec::with_capacity(num_parties);
            let mut cipher = Vec::with_capacity(num_parties);
            let mut commitments = Vec::with_capacity(num_parties);
            for (i, their_pk) in party_pks.iter().enumerate() {
                let nonce = BaseField::rand(&mut rng);
                let (comm, ciphertext) = poly.gen_share(i, my_sk, *their_pk, nonce);
                nonces.push(nonce);
                cipher.push(ciphertext);
                commitments.push(comm);
            }
            encryption_nonces.push(nonces);
            party_ciphers.push(cipher);
            party_commitments.push(commitments);
        }

        // 3. Each party decrypts their shares
        let mut result_shares = Vec::with_capacity(num_parties);
        for (i, my_sk) in party_sks.iter().enumerate() {
            let mut my_shares = Vec::with_capacity(num_parties);
            for (cipher, nonce, their_pk) in izip!(
                party_ciphers.iter(),
                encryption_nonces.iter(),
                party_pks.iter()
            ) {
                let share = decrypt_share(my_sk, *their_pk, cipher[i], nonce[i])
                    .expect("decryption should work");
                my_shares.push(share);
            }
            let my_share = accumulate_shares(&my_shares);
            result_shares.push(my_share);
        }

        // Check if the correct secret share is obtained
        let sk_from_shares =
            shamir::test_utils::reconstruct_random_shares(&result_shares, degree, &mut rng);
        assert_eq!(should_sk, sk_from_shares);

        // Check if the correct public key is obtained
        let pk_shares = result_shares
            .iter()
            .map(|x| Affine::generator() * *x)
            .collect::<Vec<_>>();
        let pk_from_shares =
            shamir::test_utils::reconstruct_random_pointshares(&pk_shares, degree, &mut rng);
        assert_eq!(should_pk, pk_from_shares);

        ///////////////////////////////////////////////////
        // PHASE 2: Reshare

        // Lagrange coefficients for the first degree+1 parties
        let lagrange = lagrange_coeffs(degree);

        // 1. First degree + 1 parties commit to a random polynomial
        let party_polys = result_shares
            .into_iter()
            .take(degree + 1)
            .map(|share| KeyGenPoly::reshare(&mut rng, share, degree))
            .collect::<Vec<_>>();

        // pk from commitments
        let pks = party_polys
            .iter()
            .map(|x| x.get_pk_share())
            .collect::<Vec<_>>();
        let pk_from_comm = accumulate_lagrange_pks(&pks, &lagrange);
        assert_eq!(should_pk, pk_from_comm);

        // 2. First degree + 1 parties create all shares
        let mut encryption_nonces = Vec::with_capacity(degree + 1);
        let mut party_ciphers = Vec::with_capacity(degree + 1);
        for (poly, my_sk) in izip!(party_polys.iter(), party_sks.iter()) {
            let mut nonces = Vec::with_capacity(num_parties);
            let mut cipher = Vec::with_capacity(num_parties);
            for (i, their_pk) in party_pks.iter().enumerate() {
                let nonce = BaseField::rand(&mut rng);
                let (_, ciphertext) = poly.gen_share(i, my_sk, *their_pk, nonce);
                nonces.push(nonce);
                cipher.push(ciphertext);
            }
            encryption_nonces.push(nonces);
            party_ciphers.push(cipher);
        }

        let lagrange = lagrange.into_iter().take(degree + 1).collect_vec();

        // 3. Each party decrypts their shares
        let mut result_shares = Vec::with_capacity(num_parties);
        for (i, my_sk) in party_sks.iter().enumerate() {
            let mut my_shares = Vec::with_capacity(degree + 1);
            for (cipher, nonce, their_pk) in izip!(
                party_ciphers.iter(),
                encryption_nonces.iter(),
                party_pks.iter()
            ) {
                let share = decrypt_share(my_sk, *their_pk, cipher[i], nonce[i])
                    .expect("decryption should work");
                my_shares.push(share);
            }
            let my_share = accumulate_lagrange_shares(&my_shares, &lagrange);
            result_shares.push(my_share);
        }

        // Check if the correct secret share is obtained
        let sk_from_shares =
            shamir::test_utils::reconstruct_random_shares(&result_shares, degree, &mut rng);
        assert_eq!(should_sk, sk_from_shares);

        // Check if the correct public key is obtained
        let pk_shares = result_shares
            .iter()
            .map(|x| Affine::generator() * *x)
            .collect::<Vec<_>>();
        let pk_from_shares =
            shamir::test_utils::reconstruct_random_pointshares(&pk_shares, degree, &mut rng);
        assert_eq!(should_pk, pk_from_shares);

        // Check that the correct share was used in the polynomial
        // This can be checked outside of the ZK proof (e.g., in the SC) using the commitments
        for (i, poly) in party_polys.iter().enumerate() {
            let mut reconstructed_commitment = Affine::zero();
            for comm in party_commitments.iter() {
                // For later reshares, the following sum needs to be replaced by a weighted sum using the lagrange coefficients
                reconstructed_commitment = (reconstructed_commitment + comm[i]).into_affine();
            }
            assert_eq!(poly.get_pk_share(), reconstructed_commitment);
        }
    }

    #[test]
    fn test_reshare_3_1() {
        test_reshare(3, 1);
    }

    #[test]
    fn test_reshare_31_15() {
        test_reshare(31, 15);
    }
}
