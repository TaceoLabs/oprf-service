use ark_ff::UniformRand;
use rand::Rng;

use super::*;
use crate::{
    legendre::{commit_key, legendre_prf},
    shamir::{evaluate_poly, lagrange_from_coeff},
};

/// Degree-`degree` Shamir shares of `secret` for parties `1..=n`.
fn share<R: Rng>(secret: ScalarField, degree: usize, n: usize, rng: &mut R) -> Vec<ScalarField> {
    let mut poly = vec![secret];
    poly.extend((0..degree).map(|_| ScalarField::rand(rng)));
    (1..=n as u64)
        .map(|i| evaluate_poly(&poly, ScalarField::from(i)))
        .collect()
}

/// `len` additive shares of zero.
fn zero_shares<R: Rng>(len: usize, rng: &mut R) -> Vec<ScalarField> {
    let mut shares = (1..len).map(|_| ScalarField::rand(rng)).collect::<Vec<_>>();
    shares.push(-shares.iter().sum::<ScalarField>());
    shares
}

struct Setup {
    params: LegendreParams,
    degree: usize,
    k: ScalarField,
    c_k: Affine,
    keys: Vec<KeyShare>,
}

fn setup(n_bits: usize, n_parties: usize, degree: usize) -> Setup {
    let mut rng = rand::thread_rng();
    let params = LegendreParams::new(n_bits);
    let (k, rho) = (ScalarField::rand(&mut rng), ScalarField::rand(&mut rng));
    let keys = share(k, degree, n_parties, &mut rng)
        .into_iter()
        .zip(share(rho, degree, n_parties, &mut rng))
        .map(|(k, rho)| KeyShare { k, rho })
        .collect();
    Setup {
        c_k: commit_key(&params, k, rho),
        params,
        degree,
        k,
        keys,
    }
}

/// Trusted-dealer correlated randomness for the parties in `ids` (1-based).
fn deal_randomness(setup: &Setup, ids: &[u64]) -> Vec<SessionRandomness> {
    let mut rng = rand::thread_rng();
    let n = setup.params.n_bits();
    let parties = setup.keys.len();
    let shared = |rng: &mut rand::rngs::ThreadRng| {
        (0..n)
            .map(|_| share(ScalarField::rand(rng), setup.degree, parties, rng))
            .collect::<Vec<_>>()
    };
    let (masks, nonces) = (shared(&mut rng), shared(&mut rng));
    let key_nonce = share(ScalarField::rand(&mut rng), setup.degree, parties, &mut rng);
    let zero_u = (0..n)
        .map(|_| zero_shares(ids.len(), &mut rng))
        .collect::<Vec<_>>();
    let zero_t0 = (0..n)
        .map(|_| zero_shares(ids.len(), &mut rng))
        .collect::<Vec<_>>();
    ids.iter()
        .enumerate()
        .map(|(pos, id)| {
            let i = usize::try_from(*id).expect("fits") - 1;
            SessionRandomness {
                masks: masks.iter().map(|s| s[i]).collect(),
                nonces: nonces.iter().map(|s| s[i]).collect(),
                key_nonce: key_nonce[i],
                zero_u: zero_u.iter().map(|z| z[pos]).collect(),
                zero_t0: zero_t0.iter().map(|z| z[pos]).collect(),
            }
        })
        .collect()
}

fn evaluate(
    setup: &Setup,
    h: ScalarField,
    ids: &[u64],
    tamper: impl Fn(&mut [Round1Message]),
) -> Result<(Vec<bool>, LegendreProof), ThresholdError> {
    let mut rng = rand::thread_rng();
    let h_shares = share(h, setup.degree, setup.keys.len(), &mut rng);
    let lagrange = lagrange_from_coeff::<ScalarField, u64>(ids);
    let randomness = deal_randomness(setup, ids);
    let (sessions, mut msgs): (Vec<_>, Vec<_>) = ids
        .iter()
        .enumerate()
        .map(|(pos, id)| {
            let i = usize::try_from(*id).expect("fits") - 1;
            NodeSession::round1(
                &setup.params,
                lagrange[pos],
                setup.keys[i].clone(),
                h_shares[i],
                &randomness[pos],
                &mut rng,
            )
        })
        .unzip();
    tamper(&mut msgs);
    let (client, request) = ClientSession::round1(&setup.params, setup.c_k, h, &msgs)?;
    let responses = sessions
        .into_iter()
        .map(|s| s.round2(&request))
        .collect::<Vec<_>>();
    client.round2(&setup.params, &responses)
}

#[test]
fn threshold_evaluation_matches_plain_prf() {
    let mut rng = rand::thread_rng();
    // 7 parties, degree 2: any 3t + 1 = 7 answer
    let setup = setup(32, 10, 2);
    let h = ScalarField::rand(&mut rng);
    let expected = legendre_prf(setup.k, h, 32).expect("non-zero");
    for ids in [vec![1, 2, 3, 4, 5, 6, 7], vec![2, 3, 5, 6, 8, 9, 10]] {
        let (bits, proof) = evaluate(&setup, h, &ids, |_| {}).expect("evaluation succeeds");
        assert_eq!(bits, expected);
        proof
            .verify(&setup.params, setup.c_k, h, &bits)
            .expect("proof verifies");
    }
}

#[test]
fn too_few_nodes_fail() {
    let setup = setup(8, 7, 2);
    let h = ScalarField::rand(&mut rand::thread_rng());
    // 3t = 6 nodes cannot interpolate the degree-3t products
    assert_eq!(
        evaluate(&setup, h, &[1, 2, 3, 4, 5, 6], |_| {}).unwrap_err(),
        ThresholdError::InvalidProof
    );
}

#[test]
fn cheating_node_is_detected() {
    let setup = setup(8, 7, 2);
    let h = ScalarField::rand(&mut rand::thread_rng());
    let ids = [1, 2, 3, 4, 5, 6, 7];
    // a wrong share of a masked value changes u_j, and with it possibly the bit: the proof must fail either way
    let wrong_u = evaluate(&setup, h, &ids, |msgs| {
        msgs[3].u[5] += ScalarField::from(1u64)
    });
    assert_eq!(wrong_u.unwrap_err(), ThresholdError::InvalidProof);
    // a wrong commitment share
    let wrong_commitment = evaluate(&setup, h, &ids, |msgs| msgs[0].t[1][2] = msgs[0].t[1][3]);
    assert_eq!(wrong_commitment.unwrap_err(), ThresholdError::InvalidProof);
}
