//! This module implements the client side of the OPRF protocol, including query construction, blinding and unblinding,
//! as well as proof verification. It provides methods to generate domain-separated queries, blind them using random factors,
//! finalize (unblind and hash) server responses, and verify server proofs of correctness.

use ark_ec::CurveGroup;
use ark_ff::Zero;

use crate::dlog_equality::{DLogEqualityProof, InvalidProof};

use crate::oprf::{
    Affine, BaseField, BlindedOprfRequest, BlindedOprfResponse, BlindingFactor, Curve,
    PreparedBlindingFactor, mappings,
};

/// Blinds a query for the OPRF server using a randomly generated blinding factor.
///
/// The query is mapped to a curve point, then blinded via scalar multiplication.
/// Returns the blinded request and the blinding factor.
///
/// # Arguments
///
/// * `query` - Query field element to be blinded.
/// * `blinding_factor` - Blinding factor to use for blinding.
///
/// # Returns
///
/// A [`BlindedOprfRequest`].
pub fn blind_query(query: BaseField, blinding_factor: BlindingFactor) -> BlindedOprfRequest {
    // The blinding factor shall not be zero. As the chance of getting a zero is negligible we just panic here.
    if blinding_factor.beta().is_zero() {
        panic!("blinding_factor cannot be zero");
    }
    let encoded_input = mappings::encode_to_curve(query);
    let blinded_query = (encoded_input * blinding_factor.beta()).into_affine();
    BlindedOprfRequest(blinded_query)
}

/// Unblinds an OPRF server response and hashes it to produce the final output for the query. This method is for the non-threshold variant of the OPRF protocol.
///
/// Performs 2Hash-DH: H(query, unblinded_point).
///
/// # Arguments
///
/// * `query` - Query field element.
/// * `response` - Blinded OPRF server response.
/// * `blinding_factor` - Prepared blinding factor for unblinding.
/// * `domain_separator` - Domain separator for hashing.
///
/// # Returns
///
/// OPRF output as a `BaseField` element.
pub fn finalize_query(
    query: BaseField,
    response: BlindedOprfResponse,
    blinding_factor: PreparedBlindingFactor,
    domain_separator: BaseField,
) -> BaseField {
    // Unblind the response using the blinding factor
    let unblinded_point = response.unblind_response(&blinding_factor);

    // compute the second hash in the 2Hash-DH construction
    // out = H(query, unblinded_point)
    let hash_input = [
        domain_separator,
        query,
        unblinded_point.x,
        unblinded_point.y,
    ];

    let output = poseidon2::bn254::t4::permutation(&hash_input);
    output[1] // Return the first element of the state as the field element,
}

/// Unblinds a response, verifies the discrete log equality proof, and produces the final OPRF output. This method is for the non-threshold variant of the OPRF protocol.
///
/// Calls [`finalize_query`] after verifying the proof.
///
/// # Arguments
///
/// * `a` - Prover's public parameter.
/// * `query` - Query field element.
/// * `response` - Blinded OPRF server response.
/// * `proof` - Discrete log equality proof.
/// * `blinding_factor` - Prepared blinding factor for unblinding.
///
/// # Returns
///
/// Returns the OPRF output if the proof is valid, else returns `InvalidProof`.
pub fn finalize_query_and_verify_proof(
    a: Affine,
    query: BaseField,
    response: BlindedOprfResponse,
    proof: DLogEqualityProof,
    blinding_factor: PreparedBlindingFactor,
    domain_separator: BaseField,
) -> Result<BaseField, InvalidProof> {
    // Verify the proof
    use ark_ec::PrimeGroup as _;
    use ark_ff::Field as _;
    let d = Curve::generator().into_affine();
    let b = (mappings::encode_to_curve(query) * blinding_factor.beta_inv().inverse().unwrap())
        .into_affine();
    let c = response.0;

    proof.verify(a, b, c, d)?;

    // Call finalize_query to unblind the response
    Ok(finalize_query(
        query,
        response,
        blinding_factor,
        domain_separator,
    ))
}
