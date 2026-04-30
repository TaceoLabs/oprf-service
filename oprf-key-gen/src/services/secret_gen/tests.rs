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

use crate::{postgres, secret_manager::SecretManager};

use super::*;

fn build_public_inputs(
    degree: u16,
    pk: EphemeralEncryptionPublicKey,
    contribution: &SecretGenCiphertexts,
    flattened_pks: &[ark_bn254::Fr],
    commitments: &Round1Contribution,
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
    let comm_share = ark_babyjubjub::EdwardsAffine::try_from(commitments.commShare.clone())
        .expect("Should work");
    let comm_coeffs = ark_babyjubjub::Fq::try_from(commitments.commCoeffs).expect("Should work");
    let mut public_inputs = Vec::with_capacity(24);
    public_inputs.push(pk.inner().x);
    public_inputs.push(pk.inner().y);
    public_inputs.push(comm_share.x);
    public_inputs.push(comm_share.y);
    public_inputs.push(comm_coeffs);
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
    let graph =
        PathBuf::from(std::env!("CARGO_MANIFEST_DIR")).join("../artifacts/OPRFKeyGenGraph.13.bin");
    let graph = std::fs::read(graph)?;
    let key_gen_zkey =
        PathBuf::from(std::env!("CARGO_MANIFEST_DIR")).join("../artifacts/OPRFKeyGen.13.arks.zkey");
    let key_gen_zkey = std::fs::read(key_gen_zkey)?;
    let key_gen_material = CircomGroth16MaterialBuilder::new()
        .validate(Validate::No)
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .build_from_bytes(&key_gen_zkey, &graph)?;

    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    let secret_manager0 = Arc::new(
        postgres::tests::postgres_secret_manager_with_schema(
            &connection_string,
            "node0".parse().expect("should be valid schema"),
        )
        .await?,
    );
    let secret_manager1 = Arc::new(
        postgres::tests::postgres_secret_manager_with_schema(
            &connection_string,
            "node1".parse().expect("should be valid schema"),
        )
        .await?,
    );
    let secret_manager2 = Arc::new(
        postgres::tests::postgres_secret_manager_with_schema(
            &connection_string,
            "node2".parse().expect("should be valid schema"),
        )
        .await?,
    );

    let dlog_secret_gen0 =
        DLogSecretGenService::init(key_gen_material.clone(), secret_manager0.clone());
    let dlog_secret_gen1 =
        DLogSecretGenService::init(key_gen_material.clone(), secret_manager1.clone());
    let dlog_secret_gen2 =
        DLogSecretGenService::init(key_gen_material.clone(), secret_manager2.clone());

    let epoch = ShareEpoch::default();

    let dlog_secret_gen0_round1 = dlog_secret_gen0
        .key_gen_round1(oprf_key_id, epoch, threshold)
        .await?;
    let dlog_secret_gen1_round1 = dlog_secret_gen1
        .key_gen_round1(oprf_key_id, epoch, threshold)
        .await?;
    let dlog_secret_gen2_round1 = dlog_secret_gen2
        .key_gen_round1(oprf_key_id, epoch, threshold)
        .await?;

    let commitments0 = dlog_secret_gen0_round1.clone();
    let commitments1 = dlog_secret_gen1_round1.clone();
    let commitments2 = dlog_secret_gen2_round1.clone();

    let round1_contributions = [
        dlog_secret_gen0_round1.commShare,
        dlog_secret_gen1_round1.commShare,
        dlog_secret_gen2_round1.commShare,
    ]
    .into_iter()
    .map(ark_babyjubjub::EdwardsAffine::try_from)
    .collect::<eyre::Result<Vec<_>>>()?;
    let should_public_key = round1_contributions.iter().fold(
        ark_babyjubjub::EdwardsAffine::zero(),
        |acc, contribution| (acc + contribution).into_affine(),
    );

    let pks = [
        dlog_secret_gen0_round1.ephPubKey,
        dlog_secret_gen1_round1.ephPubKey,
        dlog_secret_gen2_round1.ephPubKey,
    ]
    .into_iter()
    .map(EphemeralEncryptionPublicKey::try_from)
    .collect::<eyre::Result<Vec<_>>>()?;
    let flattened_pks = pks
        .clone()
        .into_iter()
        .flat_map(|p| [p.inner().x, p.inner().y])
        .collect_vec();

    let (dlog_secret_gen0_round2, dlog_secret_gen1_round2, dlog_secret_gen2_round2) = tokio::join!(
        dlog_secret_gen0.producer_round2(oprf_key_id, epoch, pks.clone()),
        dlog_secret_gen1.producer_round2(oprf_key_id, epoch, pks.clone()),
        dlog_secret_gen2.producer_round2(oprf_key_id, epoch, pks.clone())
    );
    let dlog_secret_gen0_round2 = dlog_secret_gen0_round2
        .context("while doing round2")?
        .expect("Should be Some");
    let dlog_secret_gen1_round2 = dlog_secret_gen1_round2
        .context("while doing round2")?
        .expect("Should be Some");
    let dlog_secret_gen2_round2 = dlog_secret_gen2_round2
        .context("while doing round2")?
        .expect("Should be Some");

    let [pk0, pk1, pk2] = pks.clone().try_into().expect("Should be three keys");
    // verify the proofs
    // build public inputs for proof0
    let public_inputs0 = build_public_inputs(
        threshold - 1,
        pk0,
        &dlog_secret_gen0_round2,
        &flattened_pks,
        &commitments0,
    );
    let public_inputs1 = build_public_inputs(
        threshold - 1,
        pk1,
        &dlog_secret_gen1_round2,
        &flattened_pks,
        &commitments1,
    );
    let public_inputs2 = build_public_inputs(
        threshold - 1,
        pk2,
        &dlog_secret_gen2_round2,
        &flattened_pks,
        &commitments2,
    );
    let proof0 = dlog_secret_gen0_round2.proof;
    let proof1 = dlog_secret_gen1_round2.proof;
    let proof2 = dlog_secret_gen2_round2.proof;
    key_gen_material.verify_proof(&proof0.into(), &public_inputs0)?;
    key_gen_material.verify_proof(&proof1.into(), &public_inputs1)?;
    key_gen_material.verify_proof(&proof2.into(), &public_inputs2)?;

    let ciphers = (0..3)
        .map(|i| {
            vec![
                dlog_secret_gen0_round2.ciphers[i].clone(),
                dlog_secret_gen1_round2.ciphers[i].clone(),
                dlog_secret_gen2_round2.ciphers[i].clone(),
            ]
        })
        .collect_vec();
    let [ciphers0, ciphers1, ciphers2] = ciphers.try_into().expect("len is 3");
    dlog_secret_gen0
        .round3(oprf_key_id, epoch, ciphers0, Contributions::Full, &pks)
        .await?
        .expect("Should be Some");
    dlog_secret_gen1
        .round3(oprf_key_id, epoch, ciphers1, Contributions::Full, &pks)
        .await?
        .expect("Should be Some");
    dlog_secret_gen2
        .round3(oprf_key_id, epoch, ciphers2, Contributions::Full, &pks)
        .await?
        .expect("Should be Some");

    // finalize round
    dlog_secret_gen0
        .finalize(oprf_key_id, epoch, should_public_key.into())
        .await?;
    dlog_secret_gen1
        .finalize(oprf_key_id, epoch, should_public_key.into())
        .await?;
    dlog_secret_gen2
        .finalize(oprf_key_id, epoch, should_public_key.into())
        .await?;

    let share0 = secret_manager0
        .get_share_by_epoch(oprf_key_id, epoch)
        .await?
        .expect("Should be Some");

    let share1 = secret_manager1
        .get_share_by_epoch(oprf_key_id, epoch)
        .await?
        .expect("Should be Some");

    let share2 = secret_manager2
        .get_share_by_epoch(oprf_key_id, epoch)
        .await?
        .expect("Should be Some");

    let lagrange = oprf_core::shamir::lagrange_from_coeff(&[1, 2, 3]);
    let secret_key = oprf_core::shamir::reconstruct::<ark_babyjubjub::Fr>(
        &[share0.into(), share1.into(), share2.into()],
        &lagrange,
    );

    let is_public_key = (ark_babyjubjub::EdwardsProjective::generator() * secret_key).into_affine();

    assert_eq!(is_public_key, should_public_key);
    // check that shares are removed correctly
    assert!(
        secret_manager0
            .fetch_keygen_intermediates(oprf_key_id, epoch)
            .await?
            .is_none(),
        "Intermediates must be gone now"
    );
    assert!(
        secret_manager1
            .fetch_keygen_intermediates(oprf_key_id, epoch)
            .await?
            .is_none(),
        "Intermediates must be gone now"
    );
    assert!(
        secret_manager2
            .fetch_keygen_intermediates(oprf_key_id, epoch)
            .await?
            .is_none(),
        "Intermediates must be gone now"
    );

    Ok(())
}
