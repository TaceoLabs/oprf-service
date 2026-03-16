//! This module provides the server-side components for handling OPRF queries.
//! It is only available with the `server` feature and is intended **only** for non-threshold (single-key) OPRF scenarios.
//! In threshold OPRF protocols, these methods are replaced by secure multiparty computation (MPC) implementations.
//!
//! The server manages an OPRF secret key, responds to client queries (blinded requests), and can optionally produce a zero-knowledge
//! proof of correct evaluation.

use std::ops;

use ark_ec::{CurveGroup, PrimeGroup};
use rand::{CryptoRng, Rng};
use zeroize::ZeroizeOnDrop;

use crate::{
    dlog_equality::DLogEqualityProof,
    oprf::{Affine, BlindedOprfRequest, BlindedOprfResponse, Curve, ScalarField},
};

/// OPRF server secret key (scalar).
///
/// This should be handled as a secret and is zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct OprfKey(ScalarField);

impl ops::Mul<Affine> for &OprfKey {
    type Output = Affine;

    fn mul(self, rhs: Affine) -> Self::Output {
        (rhs * self.0).into_affine()
    }
}

impl OprfKey {
    /// Generate a random OPRF key.
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        OprfKey(rng.r#gen())
    }

    /// Returns the public key corresponding to this OPRF secret key.
    #[must_use]
    pub fn public_key(&self) -> Affine {
        (Curve::generator() * self.0).into_affine()
    }
}

/// OPRF server, holding the OPRF key and handling blinded queries.
///
/// Only enabled for the non-threshold variant of the protocol.
pub struct OprfServer {
    /// The OPRF key used for this service instance.
    pub(crate) key: OprfKey,
}

impl OprfServer {
    /// Create a new OPRF server instance using the given key.
    #[must_use]
    pub fn new(key: OprfKey) -> Self {
        OprfServer { key }
    }

    /// Returns a reference to the OPRF server's key.
    #[must_use]
    pub fn key(&self) -> &OprfKey {
        &self.key
    }

    /// Returns the public key corresponding to the server's secret key.
    #[must_use]
    pub fn public_key(&self) -> Affine {
        self.key.public_key()
    }

    /// Computes the blinded OPRF response for a given blinded query.
    #[must_use]
    pub fn answer_query(&self, query: &BlindedOprfRequest) -> BlindedOprfResponse {
        // Compute the blinded response
        let blinded_response = (query.0 * self.key.0).into_affine();
        BlindedOprfResponse(blinded_response)
    }

    /// Computes the blinded OPRF response and produces a zero-knowledge proof that the response was computed correctly.
    ///
    /// # Arguments
    /// * `query` - The blinded OPRF client request.
    ///
    /// # Returns
    /// Tuple of blinded response and zero-knowledge (discrete log equality) proof of correctness.
    #[must_use]
    pub fn answer_query_with_proof(
        &self,
        query: &BlindedOprfRequest,
    ) -> (BlindedOprfResponse, DLogEqualityProof) {
        // Compute the blinded response
        let blinded_response = (query.0 * self.key.0).into_affine();

        let proof = DLogEqualityProof::proof(query.0, self.key.0, &mut rand::thread_rng());
        (BlindedOprfResponse(blinded_response), proof)
    }
}
