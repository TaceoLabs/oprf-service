//! This module defines the core functionality of the OPRF protocol.
//!
//! It provides types for representing client queries, blinding factors, and blinded server responses.
//!
//! Blinding is used to ensure the server cannot learn the client’s input. The roundtrip uses a blinding factor to blind queries,
//! and unblinding after server response to recover the OPRF output. This module is shared between both the client and, under the
//! `server` feature, the server implementations.
//!
//! See the `client` module for client-side helpers, and the `server` module (when enabled) for non-threshold server operations.

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{Field, UniformRand, Zero};
use rand::{CryptoRng, Rng};

pub(crate) type Affine = <Curve as CurveGroup>::Affine;
pub(crate) type BaseField = <Curve as CurveGroup>::BaseField;
pub(crate) type Curve = ark_babyjubjub::EdwardsProjective;
pub(crate) type Projective = ark_babyjubjub::EdwardsProjective;
pub(crate) type ScalarField = <Curve as PrimeGroup>::ScalarField;

pub mod client;
mod mappings;
#[cfg(feature = "server")]
pub mod server;

/// A blinded OPRF client request, containing the curve point encoding the blinded query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedOprfRequest(Affine);

impl BlindedOprfRequest {
    /// Construct a new [`BlindedOprfRequest`] from an affine point.
    pub fn new(value: Affine) -> Self {
        Self(value)
    }

    /// Returns the public x/y coordinates of the blinded query.
    pub fn blinded_query_as_public_output(&self) -> [BaseField; 2] {
        [self.0.x, self.0.y]
    }

    /// Returns the blinded query as an affine curve point.
    pub fn blinded_query(&self) -> Affine {
        self.0
    }
}

/// The OPRF query blinding factor, as well as the original query value.
///
/// The blinding factor shall not be zero, otherwise [`BlindingFactor::prepare`] will panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindingFactor(ScalarField);

/// Error indicating an invalid blinding factor (it may not be zero).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InvalidBlindingFactor;

impl std::fmt::Display for InvalidBlindingFactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid blinding factor, may not be zero")
    }
}

impl std::error::Error for InvalidBlindingFactor {}

impl BlindingFactor {
    /// Generate a new random blinding factor using the provided RNG.
    pub fn rand<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let beta = ScalarField::rand(rng);
        Self(beta)
    }

    /// Construct a new [`BlindingFactor`] from a scalar value.
    ///
    /// Strongly prefer using [`BlindingFactor::rand`] to generate a secure random blinding factor and only use this method
    /// if you have a specific need for constructing a [`BlindingFactor`] directly.
    ///
    /// # Errors
    /// Returns [`InvalidBlindingFactor`] if the provided value is zero.
    pub fn from_scalar(value: ScalarField) -> Result<Self, InvalidBlindingFactor> {
        if value.is_zero() {
            return Err(InvalidBlindingFactor);
        }
        Ok(Self(value))
    }

    /// Prepare the blinding factor for unblinding (by inverting the blinding scalar).
    ///
    /// # Panics
    /// This method panics if the blinding factor is 0.
    pub fn prepare(self) -> PreparedBlindingFactor {
        PreparedBlindingFactor(
            self.0
                .inverse()
                .expect("Blinding factor should not be zero"),
        )
    }

    /// Returns the (non-inverted) blinding factor.
    pub fn beta(&self) -> ScalarField {
        self.0
    }
}

/// Prepared blinding factor, storing the inverse for unblinding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedBlindingFactor(ScalarField);

impl PreparedBlindingFactor {
    /// Returns the (inverted) blinding factor.
    pub fn beta_inv(&self) -> ScalarField {
        self.0
    }
}

/// The blinded OPRF response from the server, as an affine curve point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedOprfResponse(Affine);

impl BlindedOprfResponse {
    /// Construct a new blinded response from an affine point.
    pub fn new(p: Affine) -> Self {
        Self(p)
    }

    /// Unblind the server response using the prepared blinding factor.
    pub fn unblind_response(&self, blinding_factor: &PreparedBlindingFactor) -> Affine {
        (self.0 * blinding_factor.beta_inv()).into_affine()
    }

    /// Return the affine curve point of the response.
    pub fn response(&self) -> Affine {
        self.0
    }
}

#[cfg(test)]
#[cfg(feature = "server")]
mod tests {

    use ark_ff::PrimeField as _;

    use crate::oprf::{
        self,
        server::{OprfKey, OprfServer},
    };

    use super::*;

    #[test]
    fn test_oprf_determinism() {
        let mut rng = rand::thread_rng();
        let key = OprfKey::random(&mut rng);
        let service = OprfServer::new(key);
        let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF");
        let blinding_factor = BlindingFactor::rand(&mut rng);
        let blinding_factor2 = BlindingFactor::rand(&mut rng);

        let query = BaseField::from(42);
        let blinded_request = oprf::client::blind_query(query, blinding_factor.clone());
        let blinded_request2 = oprf::client::blind_query(query, blinding_factor2.clone());
        assert_ne!(blinded_request, blinded_request2);
        let response = service.answer_query(blinded_request);

        let response = oprf::client::finalize_query(
            query,
            response,
            blinding_factor.prepare(),
            domain_separator,
        );

        let expected_response = &service.key * mappings::encode_to_curve(query);
        let out = poseidon2::bn254::t4::permutation(&[
            domain_separator,
            query,
            expected_response.x,
            expected_response.y,
        ]);
        let expected_output = out[1];

        assert_eq!(response, expected_output);
        let response2 = service.answer_query(blinded_request2);

        let unblinded_response2 = oprf::client::finalize_query(
            query,
            response2,
            blinding_factor2.prepare(),
            domain_separator,
        );
        assert_eq!(response, unblinded_response2);
    }

    #[test]
    fn test_oprf_with_proof() {
        let mut rng = rand::thread_rng();
        let key = OprfKey::random(&mut rng);
        let service = OprfServer::new(key);
        let public_key = service.public_key();
        let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF");
        let blinding_factor = BlindingFactor::rand(&mut rng);
        let blinding_factor2 = BlindingFactor::rand(&mut rng);

        let query = BaseField::from(42);
        let blinded_request = oprf::client::blind_query(query, blinding_factor.clone());
        let blinded_request2 = oprf::client::blind_query(query, blinding_factor2.clone());
        assert_ne!(blinded_request, blinded_request2);
        let (response, proof) = service.answer_query_with_proof(blinded_request);

        let unblinded_response = oprf::client::finalize_query_and_verify_proof(
            public_key,
            query,
            response.clone(),
            proof,
            blinding_factor.clone().prepare(),
            domain_separator,
        )
        .unwrap();

        let expected_response = &service.key * mappings::encode_to_curve(query);
        let out = poseidon2::bn254::t4::permutation(&[
            domain_separator,
            query,
            expected_response.x,
            expected_response.y,
        ]);
        let expected_output = out[1];

        assert_eq!(unblinded_response, expected_output);

        let (response2, proof2) = service.answer_query_with_proof(blinded_request2);
        let unblinded_response2 = oprf::client::finalize_query_and_verify_proof(
            public_key,
            query,
            response2,
            proof2.clone(),
            blinding_factor2.prepare(),
            domain_separator,
        )
        .unwrap();
        assert_eq!(unblinded_response, unblinded_response2);

        oprf::client::finalize_query_and_verify_proof(
            public_key,
            query,
            response,
            proof2,
            blinding_factor.prepare(),
            domain_separator,
        )
        .unwrap_err();
    }
}
