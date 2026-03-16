//! Tests for Distributed Secret Generation
//!
//! This module contains integration tests for the [`DLogSecretGenService`],
//! verifying the correctness of the multi-round secret generation protocol
//! including proof generation and verification.

use std::path::PathBuf;

use ark_ec::{CurveGroup as _, PrimeGroup};
use groth16_material::circom::{CircomGroth16MaterialBuilder, Validate};
use itertools::Itertools;
use oprf_types::crypto::{EphemeralEncryptionPublicKey, SecretGenCiphertexts};
use rand::Rng;

use super::*;

fn build_public_inputs(
    degree: u16,
    pk: EphemeralEncryptionPublicKey,
    contribution: &SecretGenCiphertexts,
    flattened_pks: &[ark_bn254::Fr],
    commitments: &SecretGenCommitment,
) -> Vec<ark_babyjubjub::Fq> {
    // public input is:
    // 1) PublicKey from sender (Affine Point Babyjubjub)
    // 2) Commitment to share (Affine Point Babyjubjub)
    // 3) Commitment to coeffs (Basefield Babyjubjub)
    // 4) Ciphertexts for nodes (in this case 3 Basefield BabyJubJub)
    // 5) Commitments to plaintexts (in this case 3 Affine Points BabyJubJub)
    // 6) Degree (Basefield BabyJubJub)
    // 7) Public Keys from nodes (in this case 3 Affine Points BabyJubJub)
    // 8) Nonces (in this case 3 Basefield BabyJubJub)
    let mut ciphers = Vec::with_capacity(3);
    let mut comm_ciphers = Vec::with_capacity(3);
    let mut nonces = Vec::with_capacity(3);
    for cipher in &contribution.ciphers {
        ciphers.push(cipher.cipher);
        comm_ciphers.push(cipher.commitment.x);
        comm_ciphers.push(cipher.commitment.y);
        nonces.push(cipher.nonce);
    }
    let mut public_inputs = Vec::with_capacity(24);
    public_inputs.push(pk.inner().x);
    public_inputs.push(pk.inner().y);
    public_inputs.push(commitments.comm_share.x);
    public_inputs.push(commitments.comm_share.y);
    public_inputs.push(commitments.comm_coeffs);
    public_inputs.extend(ciphers);
    public_inputs.extend(comm_ciphers);
    public_inputs.push(ark_babyjubjub::Fq::from(degree));
    public_inputs.extend(flattened_pks.iter());
    public_inputs.extend(nonces);
    public_inputs
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "is ok for test")]
async fn test_secret_gen() -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let oprf_key_id = OprfKeyId::new(rng.r#gen());
    let threshold = 2;
    let graph = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"))
        .join("../circom/main/key-gen/OPRFKeyGenGraph.13.bin");
    let graph = std::fs::read(graph)?;
    let key_gen_zkey = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"))
        .join("../circom/main/key-gen/OPRFKeyGen.13.arks.zkey");
    let key_gen_zkey = std::fs::read(key_gen_zkey)?;
    let key_gen_material = CircomGroth16MaterialBuilder::new()
        .validate(Validate::No)
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .build_from_bytes(&key_gen_zkey, &graph)?;

    let mut dlog_secret_gen0 = DLogSecretGenService::init(key_gen_material.clone());
    let mut dlog_secret_gen1 = DLogSecretGenService::init(key_gen_material.clone());
    let mut dlog_secret_gen2 = DLogSecretGenService::init(key_gen_material.clone());

    let dlog_secret_gen0_round1 = dlog_secret_gen0.key_gen_round1(oprf_key_id, threshold);
    let dlog_secret_gen1_round1 = dlog_secret_gen1.key_gen_round1(oprf_key_id, threshold);
    let dlog_secret_gen2_round1 = dlog_secret_gen2.key_gen_round1(oprf_key_id, threshold);

    let commitments0 = dlog_secret_gen0_round1.contribution.clone();
    let commitments1 = dlog_secret_gen1_round1.contribution.clone();
    let commitments2 = dlog_secret_gen2_round1.contribution.clone();

    let round1_contributions = [
        dlog_secret_gen0_round1.contribution.clone(),
        dlog_secret_gen1_round1.contribution.clone(),
        dlog_secret_gen2_round1.contribution.clone(),
    ];
    let should_public_key = round1_contributions.iter().fold(
        ark_babyjubjub::EdwardsAffine::zero(),
        |acc, contribution| (acc + contribution.comm_share).into_affine(),
    );

    let pks = [
        dlog_secret_gen0_round1.contribution.eph_pub_key,
        dlog_secret_gen1_round1.contribution.eph_pub_key,
        dlog_secret_gen2_round1.contribution.eph_pub_key,
    ];
    let flattened_pks = pks
        .into_iter()
        .flat_map(|p| [p.inner().x, p.inner().y])
        .collect_vec();

    let (dlog_secret_gen0_round2, dlog_secret_gen1_round2, dlog_secret_gen2_round2) = tokio::join!(
        dlog_secret_gen0.producer_round2(oprf_key_id, pks.to_vec()),
        dlog_secret_gen1.producer_round2(oprf_key_id, pks.to_vec()),
        dlog_secret_gen2.producer_round2(oprf_key_id, pks.to_vec())
    );
    let dlog_secret_gen0_round2 = dlog_secret_gen0_round2.context("while doing round2")?;
    let dlog_secret_gen1_round2 = dlog_secret_gen1_round2.context("while doing round2")?;
    let dlog_secret_gen2_round2 = dlog_secret_gen2_round2.context("while doing round2")?;

    assert_eq!(dlog_secret_gen0_round2.oprf_key_id, oprf_key_id);
    assert_eq!(dlog_secret_gen1_round2.oprf_key_id, oprf_key_id);
    assert_eq!(dlog_secret_gen2_round2.oprf_key_id, oprf_key_id);
    let [pk0, pk1, pk2] = pks;
    // verify the proofs
    // build public inputs for proof0
    let public_inputs0 = build_public_inputs(
        threshold - 1,
        pk0,
        &dlog_secret_gen0_round2.contribution,
        &flattened_pks,
        &commitments0,
    );
    let public_inputs1 = build_public_inputs(
        threshold - 1,
        pk1,
        &dlog_secret_gen1_round2.contribution,
        &flattened_pks,
        &commitments1,
    );
    let public_inputs2 = build_public_inputs(
        threshold - 1,
        pk2,
        &dlog_secret_gen2_round2.contribution,
        &flattened_pks,
        &commitments2,
    );
    let proof0 = dlog_secret_gen0_round2.contribution.proof;
    let proof1 = dlog_secret_gen1_round2.contribution.proof;
    let proof2 = dlog_secret_gen2_round2.contribution.proof;
    key_gen_material.verify_proof(&proof0.into(), &public_inputs0)?;
    key_gen_material.verify_proof(&proof1.into(), &public_inputs1)?;
    key_gen_material.verify_proof(&proof2.into(), &public_inputs2)?;

    let ciphers = (0..3)
        .map(|i| {
            vec![
                dlog_secret_gen0_round2.contribution.ciphers[i].clone(),
                dlog_secret_gen1_round2.contribution.ciphers[i].clone(),
                dlog_secret_gen2_round2.contribution.ciphers[i].clone(),
            ]
        })
        .collect_vec();
    let [ciphers0, ciphers1, ciphers2] = ciphers.try_into().expect("len is 3");
    let dlog_secret_gen0_round3 =
        dlog_secret_gen0.round3(oprf_key_id, ciphers0, Contributions::Full, &pks)?;
    let dlog_secret_gen1_round3 =
        dlog_secret_gen1.round3(oprf_key_id, ciphers1, Contributions::Full, &pks)?;
    let dlog_secret_gen2_round3 =
        dlog_secret_gen2.round3(oprf_key_id, ciphers2, Contributions::Full, &pks)?;
    assert_eq!(dlog_secret_gen0_round3.oprf_key_id, oprf_key_id);
    assert_eq!(dlog_secret_gen1_round3.oprf_key_id, oprf_key_id);
    assert_eq!(dlog_secret_gen2_round3.oprf_key_id, oprf_key_id);

    let share0 = dlog_secret_gen0
        .finished_shares
        .get(&oprf_key_id)
        .expect("gen0 has no share")
        .clone();
    let share1 = dlog_secret_gen1
        .finished_shares
        .get(&oprf_key_id)
        .expect("gen0 has no share")
        .clone();
    let share2 = dlog_secret_gen2
        .finished_shares
        .get(&oprf_key_id)
        .expect("gen0 has no share")
        .clone();

    let lagrange = oprf_core::shamir::lagrange_from_coeff(&[1, 2, 3]);
    let secret_key = oprf_core::shamir::reconstruct::<ark_babyjubjub::Fr>(
        &[share0.into(), share1.into(), share2.into()],
        &lagrange,
    );

    let is_public_key = (ark_babyjubjub::EdwardsProjective::generator() * secret_key).into_affine();

    assert_eq!(is_public_key, should_public_key);

    // finalize round
    let finalize0 = dlog_secret_gen0.finalize(oprf_key_id)?;
    let finalize1 = dlog_secret_gen1.finalize(oprf_key_id)?;
    let finalize2 = dlog_secret_gen2.finalize(oprf_key_id)?;

    let lagrange = oprf_core::shamir::lagrange_from_coeff(&[1, 2, 3]);
    let secret_key = oprf_core::shamir::reconstruct::<ark_babyjubjub::Fr>(
        &[finalize0.into(), finalize1.into(), finalize2.into()],
        &lagrange,
    );

    let is_public_key = (ark_babyjubjub::EdwardsProjective::generator() * secret_key).into_affine();

    assert_eq!(is_public_key, should_public_key);
    // check that shares are removed correctly
    assert!(!dlog_secret_gen0.finished_shares.contains_key(&oprf_key_id));
    assert!(!dlog_secret_gen1.finished_shares.contains_key(&oprf_key_id));
    assert!(!dlog_secret_gen2.finished_shares.contains_key(&oprf_key_id));

    Ok(())
}
