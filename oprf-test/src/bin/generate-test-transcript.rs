use ark_ff::{AdditiveGroup, PrimeField};
use std::{collections::HashMap, path::PathBuf, process::ExitCode};

use alloy::primitives::U256;
use ark_bn254::Bn254;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use askama::Template;
use clap::Parser;
use eyre::Context;
use groth16_material::circom::{CircomGroth16Material, CircomGroth16MaterialBuilder, Proof};
use itertools::Itertools as _;
use oprf_core::{
    keygen::{self, KeyGenPoly},
    shamir::{self},
};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const DEGREE: usize = 1;

#[derive(Debug, Clone, Template)]
#[template(path = "../templates/contributions.sol.template", escape = "none")]
pub struct ContributionsLib {
    oprf_key_x: ark_bn254::Fr,
    oprf_key_y: ark_bn254::Fr,
    keygen: KeyGenContributions,
    reshare1: Reshare1Contributions,
    reshare2: Reshare2Contributions,
}

#[derive(Debug, Clone, Template)]
#[template(path = "../templates/round1-call.sol.template", escape = "none")]
pub struct SolidityRound1Call {
    pub function_name: &'static str,
    pub comm_share_x: ark_bn254::Fr,
    pub comm_share_y: ark_bn254::Fr,
    pub comm_coeffs: ark_bn254::Fr,
    pub eph_pub_key_x: ark_bn254::Fr,
    pub eph_pub_key_y: ark_bn254::Fr,
}

#[derive(Debug, Clone, Template)]
#[template(path = "../templates/round2-call.sol.template", escape = "none")]
pub struct SolidityRound2Call {
    pub function_name: &'static str,
    pub cipher0: ark_bn254::Fr,
    pub cipher1: ark_bn254::Fr,
    pub cipher2: ark_bn254::Fr,

    pub nonce0: ark_babyjubjub::Fq,
    pub nonce1: ark_babyjubjub::Fq,
    pub nonce2: ark_babyjubjub::Fq,

    pub commitment0x: ark_bn254::Fr,
    pub commitment1x: ark_bn254::Fr,
    pub commitment2x: ark_bn254::Fr,

    pub commitment0y: ark_bn254::Fr,
    pub commitment1y: ark_bn254::Fr,
    pub commitment2y: ark_bn254::Fr,

    pub proof: String,
}

#[derive(Debug, Clone)]
struct ProducerContributions {
    round1: SolidityRound1Call,
    round2: SolidityRound2Call,
}

#[derive(Debug, Clone)]
struct ConsumerContributions {
    round1: SolidityRound1Call,
}

#[derive(Debug, Clone)]
struct KeyGenContributions {
    alice: ProducerContributions,
    bob: ProducerContributions,
    carol: ProducerContributions,
}

#[derive(Debug, Clone)]
struct Reshare1Contributions {
    alice: ProducerContributions,
    bob: ProducerContributions,
    carol: ConsumerContributions,
    lagrange: Vec<ark_babyjubjub::Fr>,
}

#[derive(Debug, Clone)]
struct Reshare2Contributions {
    alice: ConsumerContributions,
    bob: ProducerContributions,
    carol: ProducerContributions,
    lagrange: Vec<ark_babyjubjub::Fr>,
}

impl SolidityRound1Call {
    fn new(
        function_name: &'static str,
        comm_share: ark_babyjubjub::EdwardsAffine,
        comm_coeffs: ark_bn254::Fr,
        eph_pub_key: ark_babyjubjub::EdwardsAffine,
    ) -> Self {
        SolidityRound1Call {
            function_name,
            comm_share_x: comm_share.x,
            comm_share_y: comm_share.y,
            comm_coeffs,
            eph_pub_key_x: eph_pub_key.x,
            eph_pub_key_y: eph_pub_key.y,
        }
    }
}

impl SolidityRound2Call {
    fn new(
        function_name: &'static str,
        proof: Proof<Bn254>,
        nonces: Vec<ark_babyjubjub::Fq>,
        public_inputs: Vec<ark_bn254::Fr>,
    ) -> Self {
        SolidityRound2Call {
            function_name,
            cipher0: public_inputs[5],
            cipher1: public_inputs[6],
            cipher2: public_inputs[7],
            nonce0: nonces[0],
            nonce1: nonces[1],
            nonce2: nonces[2],
            commitment0x: public_inputs[8],
            commitment0y: public_inputs[9],
            commitment1x: public_inputs[10],
            commitment1y: public_inputs[11],
            commitment2x: public_inputs[12],
            commitment2y: public_inputs[13],
            proof: sol_call_proof(&proof),
        }
    }
}

#[derive(Parser, Debug)]
pub struct TestTranscriptConfig {
    /// The seed to generate the kats
    #[clap(long, env = "TEST_TRANSCRIPT_SEED", default_value = "42")]
    pub seed: u64,

    /// The bind addr of the AXUM server
    #[clap(long, env = "TEST_TRANSCRIPT_ZKEY")]
    pub key_gen_zkey_path: PathBuf,
    /// The location of the zkey for the key-gen proof in round 2 of KeyGen
    #[clap(long, env = "TEST_TRANSCRIPT_GRAPH")]
    pub key_gen_witness_graph_path: PathBuf,

    /// Where to write the created contract
    #[clap(long, env = "TEST_TRANSCRIPT_OUT")]
    pub output: PathBuf,
}

fn compute_key_gen_proof<R: Rng + CryptoRng>(
    inputs: HashMap<&'static str, Vec<U256>>,
    key_gen_material: &CircomGroth16Material,
    rng: &mut R,
) -> eyre::Result<(Proof<Bn254>, Vec<ark_bn254::Fr>)> {
    let inputs = &inputs
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect::<HashMap<String, Vec<U256>>>();
    let (proof, public_inputs) = key_gen_material
        .generate_proof(inputs, rng)
        .context("while computing key-gen proof")?;

    key_gen_material
        .verify_proof(&proof, &public_inputs)
        .context("while verifying key gen proof")?;
    Ok((proof, public_inputs))
}

fn sol_call_proof(proof: &Proof<Bn254>) -> String {
    groth16_sol::prepare_compressed_proof(proof)
        .into_iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join(",")
}

pub(crate) fn evaluate_poly<F: PrimeField>(poly: &[F], x: F) -> F {
    debug_assert!(!poly.is_empty());
    let mut iter = poly.iter().rev();
    let mut eval = iter.next().unwrap().to_owned();
    for coeff in iter {
        eval *= x;
        eval += coeff;
    }
    eval
}

fn producer_contributions<R: Rng + CryptoRng>(
    function_name: &'static str,
    sk: ark_babyjubjub::Fr,
    poly: &KeyGenPoly,
    flattened_pks: &[U256],
    key_gen_material: &CircomGroth16Material,
    rng: &mut R,
) -> eyre::Result<ProducerContributions> {
    let nonces = (0..3).map(|_| ark_babyjubjub::Fq::rand(rng)).collect_vec();
    let mut input = HashMap::new();
    input.insert("degree", vec![U256::from(DEGREE)]);
    input.insert("my_sk", vec![sk.into()]);
    input.insert("pks", flattened_pks.to_vec());
    input.insert(
        "poly",
        poly.coeffs().to_vec().iter().map(|x| x.into()).collect(),
    );
    input.insert("nonces", nonces.iter().map(|n| n.into()).collect_vec());
    tracing::info!("computing proof for {function_name}");
    let (proof, public) = compute_key_gen_proof(input, key_gen_material, rng)?;

    let round1 = SolidityRound1Call::new(
        function_name,
        poly.get_pk_share(),
        poly.get_coeff_commitment(),
        (ark_babyjubjub::EdwardsAffine::generator() * sk).into_affine(),
    );

    let round2 = SolidityRound2Call::new(function_name, proof, nonces, public);

    Ok(ProducerContributions { round1, round2 })
}

fn consumer_contributions(
    function_name: &'static str,
    sk: ark_babyjubjub::Fr,
) -> eyre::Result<ConsumerContributions> {
    let round1 = SolidityRound1Call::new(
        function_name,
        // this must be (0,0) AND NOT THE IDENTITY.
        // solidity expect both values as zero because that's how an empty struct is represented
        ark_babyjubjub::EdwardsAffine::new_unchecked(
            ark_babyjubjub::Fq::ZERO,
            ark_babyjubjub::Fq::ZERO,
        ),
        ark_babyjubjub::Fq::ZERO,
        (ark_babyjubjub::EdwardsAffine::generator() * sk).into_affine(),
    );

    Ok(ConsumerContributions { round1 })
}

fn key_gen_contributions<R: Rng + CryptoRng>(
    alice_poly: &KeyGenPoly,
    bob_poly: &KeyGenPoly,
    carol_poly: &KeyGenPoly,
    key_gen_material: &CircomGroth16Material,
    rng: &mut R,
) -> eyre::Result<KeyGenContributions> {
    // we need three private keys
    let alice_sk = ark_babyjubjub::Fr::rand(rng);
    let bob_sk = ark_babyjubjub::Fr::rand(rng);
    let carol_sk = ark_babyjubjub::Fr::rand(rng);

    let generator = ark_babyjubjub::EdwardsAffine::generator();
    let public_key0 = ((generator) * alice_sk).into_affine();
    let public_key1 = ((generator) * bob_sk).into_affine();
    let public_key2 = ((generator) * carol_sk).into_affine();
    let flattened_pks = [public_key0, public_key1, public_key2]
        .into_iter()
        .flat_map(|p| [p.x.into(), p.y.into()])
        .collect_vec();

    let alice = producer_contributions(
        "aliceKeyGen",
        alice_sk,
        alice_poly,
        &flattened_pks,
        key_gen_material,
        rng,
    )
    .context("while doing alice contributions")?;

    let bob = producer_contributions(
        "bobKeyGen",
        bob_sk,
        bob_poly,
        &flattened_pks,
        key_gen_material,
        rng,
    )
    .context("while doing bob contributions")?;

    let carol = producer_contributions(
        "carolKeyGen",
        carol_sk,
        carol_poly,
        &flattened_pks,
        key_gen_material,
        rng,
    )
    .context("while doing carol contributions")?;

    Ok(KeyGenContributions { alice, bob, carol })
}

fn reshare1_contributions<R: Rng + CryptoRng>(
    alice_poly: &KeyGenPoly,
    bob_poly: &KeyGenPoly,
    lagrange: &[ark_babyjubjub::Fr],
    key_gen_material: &CircomGroth16Material,
    rng: &mut R,
) -> eyre::Result<Reshare1Contributions> {
    // we need three private keys
    let alice_sk = ark_babyjubjub::Fr::rand(rng);
    let bob_sk = ark_babyjubjub::Fr::rand(rng);
    let carol_sk = ark_babyjubjub::Fr::rand(rng);

    let generator = ark_babyjubjub::EdwardsAffine::generator();
    let public_key0 = ((generator) * alice_sk).into_affine();
    let public_key1 = ((generator) * bob_sk).into_affine();
    let public_key2 = ((generator) * carol_sk).into_affine();
    let flattened_pks = [public_key0, public_key1, public_key2]
        .into_iter()
        .flat_map(|p| [p.x.into(), p.y.into()])
        .collect_vec();

    let alice = producer_contributions(
        "aliceReshare1",
        alice_sk,
        alice_poly,
        &flattened_pks,
        key_gen_material,
        rng,
    )
    .context("while doing alice contributions")?;

    let bob = producer_contributions(
        "bobReshare1",
        bob_sk,
        bob_poly,
        &flattened_pks,
        key_gen_material,
        rng,
    )
    .context("while doing bob contributions")?;

    let carol = consumer_contributions("carolReshare1", carol_sk)
        .context("while doing carol contributions")?;

    Ok(Reshare1Contributions {
        alice,
        bob,
        carol,
        lagrange: lagrange.to_vec(),
    })
}

fn reshare2_contributions<R: Rng + CryptoRng>(
    bob_poly: &KeyGenPoly,
    carol_poly: &KeyGenPoly,
    lagrange: &[ark_babyjubjub::Fr],
    key_gen_material: &CircomGroth16Material,
    rng: &mut R,
) -> eyre::Result<Reshare2Contributions> {
    // we need three private keys
    let alice_sk = ark_babyjubjub::Fr::rand(rng);
    let bob_sk = ark_babyjubjub::Fr::rand(rng);
    let carol_sk = ark_babyjubjub::Fr::rand(rng);

    let generator = ark_babyjubjub::EdwardsAffine::generator();
    let public_key0 = ((generator) * alice_sk).into_affine();
    let public_key1 = ((generator) * bob_sk).into_affine();
    let public_key2 = ((generator) * carol_sk).into_affine();
    let flattened_pks = [public_key0, public_key1, public_key2]
        .into_iter()
        .flat_map(|p| [p.x.into(), p.y.into()])
        .collect_vec();

    let alice = consumer_contributions("aliceReshare2", alice_sk)
        .context("while doing alice contributions")?;

    let bob = producer_contributions(
        "bobReshare2",
        bob_sk,
        bob_poly,
        &flattened_pks,
        key_gen_material,
        rng,
    )
    .context("while doing bob contributions")?;

    let carol = producer_contributions(
        "carolReshare2",
        carol_sk,
        carol_poly,
        &flattened_pks,
        key_gen_material,
        rng,
    )
    .context("while doing carol contributions")?;

    Ok(Reshare2Contributions {
        alice,
        bob,
        carol,
        lagrange: lagrange.to_vec(),
    })
}
fn check_keygen(
    alice_poly: &KeyGenPoly,
    bob_poly: &KeyGenPoly,
    carol_poly: &KeyGenPoly,
    lagrange12: &[ark_babyjubjub::Fr],
    lagrange23: &[ark_babyjubjub::Fr],
) -> [ark_babyjubjub::Fr; 3] {
    let alice_alice_share = evaluate_poly(alice_poly.coeffs(), 1.into());
    let alice_bob_share = evaluate_poly(alice_poly.coeffs(), 2.into());
    let alice_carol_share = evaluate_poly(alice_poly.coeffs(), 3.into());

    let bob_alice_share = evaluate_poly(bob_poly.coeffs(), 1.into());
    let bob_bob_share = evaluate_poly(bob_poly.coeffs(), 2.into());
    let bob_carol_share = evaluate_poly(bob_poly.coeffs(), 3.into());

    let carol_alice_share = evaluate_poly(carol_poly.coeffs(), 1.into());
    let carol_bob_share = evaluate_poly(carol_poly.coeffs(), 2.into());
    let carol_carol_share = evaluate_poly(carol_poly.coeffs(), 3.into());

    let should_public_key =
        alice_poly.get_pk_share() + bob_poly.get_pk_share() + carol_poly.get_pk_share();

    let alice_share = alice_alice_share + bob_alice_share + carol_alice_share;
    let bob_share = alice_bob_share + bob_bob_share + carol_bob_share;
    let carol_share = alice_carol_share + bob_carol_share + carol_carol_share;

    let alice_bob_reconstructed =
        keygen::accumulate_lagrange_shares(&[alice_share, bob_share], lagrange12);

    let bob_carol_reconstructed =
        keygen::accumulate_lagrange_shares(&[bob_share, carol_share], lagrange23);

    assert_eq!(
        should_public_key,
        ark_babyjubjub::EdwardsAffine::generator() * alice_bob_reconstructed
    );
    assert_eq!(
        should_public_key,
        ark_babyjubjub::EdwardsAffine::generator() * bob_carol_reconstructed
    );
    [alice_share, bob_share, carol_share]
}

fn check_reshare(
    poly1: &KeyGenPoly,
    poly2: &KeyGenPoly,
    lagrange: &[ark_babyjubjub::Fr],
    lagrange12: &[ark_babyjubjub::Fr],
    lagrange23: &[ark_babyjubjub::Fr],
    should_public_key: ark_babyjubjub::EdwardsAffine,
) -> [ark_babyjubjub::Fr; 3] {
    let bob_alice_share = evaluate_poly(poly1.coeffs(), 1.into());
    let bob_bob_share = evaluate_poly(poly1.coeffs(), 2.into());
    let bob_carol_share = evaluate_poly(poly1.coeffs(), 3.into());

    let carol_alice_share = evaluate_poly(poly2.coeffs(), 1.into());
    let carol_bob_share = evaluate_poly(poly2.coeffs(), 2.into());
    let carol_carol_share = evaluate_poly(poly2.coeffs(), 3.into());

    // reconstruct shares
    let alice_share =
        keygen::accumulate_lagrange_shares(&[bob_alice_share, carol_alice_share], lagrange);
    let bob_share = keygen::accumulate_lagrange_shares(&[bob_bob_share, carol_bob_share], lagrange);
    let carol_share =
        keygen::accumulate_lagrange_shares(&[bob_carol_share, carol_carol_share], lagrange);

    let alice_bob_reconstructed =
        keygen::accumulate_lagrange_shares(&[alice_share, bob_share], lagrange12);

    let bob_carol_reconstructed =
        keygen::accumulate_lagrange_shares(&[bob_share, carol_share], lagrange23);

    assert_eq!(
        should_public_key,
        ark_babyjubjub::EdwardsAffine::generator() * alice_bob_reconstructed
    );
    assert_eq!(
        should_public_key,
        ark_babyjubjub::EdwardsAffine::generator() * bob_carol_reconstructed
    );
    [alice_share, bob_share, carol_share]
}

fn main() -> eyre::Result<ExitCode> {
    nodes_observability::install_tracing("debug");
    let config = TestTranscriptConfig::parse();
    tracing::info!("starting with config: {config:#?}");

    let mut rng = ChaCha20Rng::seed_from_u64(config.seed);
    let key_gen_material = CircomGroth16MaterialBuilder::new()
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .build_from_paths(config.key_gen_zkey_path, config.key_gen_witness_graph_path)
        .context("while building key_gen_material")?;

    let lagrange12: Vec<ark_babyjubjub::Fr> =
        shamir::lagrange_from_coeff(&[ark_babyjubjub::Fr::from(1), ark_babyjubjub::Fr::from(2)]);

    let lagrange23: Vec<ark_babyjubjub::Fr> =
        shamir::lagrange_from_coeff(&[ark_babyjubjub::Fr::from(2), ark_babyjubjub::Fr::from(3)]);

    let alice_poly = KeyGenPoly::new(&mut rng, DEGREE);
    let bob_poly = KeyGenPoly::new(&mut rng, DEGREE);
    let carol_poly = KeyGenPoly::new(&mut rng, DEGREE);

    let should_public_key =
        alice_poly.get_pk_share() + bob_poly.get_pk_share() + carol_poly.get_pk_share();

    let [alice_keygen_share, bob_keygen_share, _] = check_keygen(
        &alice_poly,
        &bob_poly,
        &carol_poly,
        &lagrange12,
        &lagrange23,
    );

    let key_gen_contributions = key_gen_contributions(
        &alice_poly,
        &bob_poly,
        &carol_poly,
        &key_gen_material,
        &mut rng,
    )
    .context("while doing key-gen contributions")?;

    tracing::info!("doing first reshare proofs");

    let alice_reshare_poly = KeyGenPoly::reshare(&mut rng, alice_keygen_share, DEGREE);
    let bob_reshare_poly = KeyGenPoly::reshare(&mut rng, bob_keygen_share, DEGREE);
    // carol is consumer in first run

    let [_, bob_reshare1_share, carol_reshare1_share] = check_reshare(
        &alice_reshare_poly,
        &bob_reshare_poly,
        &lagrange12,
        &lagrange12,
        &lagrange23,
        should_public_key.into_affine(),
    );

    let reshare1_contributions = reshare1_contributions(
        &alice_reshare_poly,
        &bob_reshare_poly,
        &lagrange12,
        &key_gen_material,
        &mut rng,
    )
    .context("while doing reshare 1 contributions")?;

    tracing::info!("doing second reshare proofs");

    let bob_reshare_poly = KeyGenPoly::reshare(&mut rng, bob_reshare1_share, DEGREE);
    let carol_reshare_poly = KeyGenPoly::reshare(&mut rng, carol_reshare1_share, DEGREE);
    // carol is consumer in first run

    let _ = check_reshare(
        &bob_reshare_poly,
        &carol_reshare_poly,
        &lagrange23,
        &lagrange12,
        &lagrange23,
        should_public_key.into_affine(),
    );

    let reshare2_contributions = reshare2_contributions(
        &bob_reshare_poly,
        &carol_reshare_poly,
        &lagrange23,
        &key_gen_material,
        &mut rng,
    )
    .context("while doing reshare 2 contributions")?;

    let affine_key = should_public_key.into_affine();

    std::fs::write(
        config.output,
        ContributionsLib {
            oprf_key_x: affine_key.x,
            oprf_key_y: affine_key.y,
            keygen: key_gen_contributions,
            reshare1: reshare1_contributions,
            reshare2: reshare2_contributions,
        }
        .render()
        .expect("Works"),
    )
    .context("while writing sol-library")?;

    Ok(ExitCode::SUCCESS)
}
