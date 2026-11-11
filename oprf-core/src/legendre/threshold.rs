//! Threshold evaluation of the Legendre PRF with a jointly produced evaluation proof.
//!
//! The key `k` and its commitment randomness `rho` are Shamir-shared with degree `t`. The client Shamir-shares its input `h` with degree `t` as well. Nodes never talk to each other; the client aggregates, as for the distributed DLEQ proof. Because nodes multiply three degree-`t` sharings locally, `3t + 1` nodes have to answer.
//!
//! Round 1: every node masks its share of `k + h + j` with the square of a shared random mask `s_j` and returns an additive share of `u_j = s_j^2 * (k + h + j)`, together with perfectly hiding commitments to the masks and to the first message of the sigma protocol. The client learns `u_j`, whose quadratic character is the output bit, and nothing else.
//!
//! Round 2: the client rescales the masks by `1 / sqrt(u_j / N^{b_j})`, which turns them into the witnesses `sigma_j` of [`LegendreProof`], derives the Fiat-Shamir challenges and sends them to the nodes. Their responses add up to the proof.
//!
//! All node messages are additive shares over the session's node set: the Lagrange coefficient of the node is already folded in.

use ark_ec::{CurveGroup, VariableBaseMSM as _};
use ark_ff::{Field, UniformRand, Zero};
use rand::{CryptoRng, Rng};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    Affine, Projective, ScalarField,
    params::{LegendreParams, is_square},
    proof::{InvalidLegendreProof, LegendreProof, index, relation_coefficients, target},
    transcript::{batch_challenges, sigma_challenge},
};

/// A node's share of the PRF key and of the randomness of the key commitment.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[allow(clippy::exhaustive_structs, reason = "Plain share data")]
pub struct KeyShare {
    /// Degree-`t` Shamir share of the key `k`.
    pub k: ScalarField,
    /// Degree-`t` Shamir share of the commitment randomness `rho`.
    pub rho: ScalarField,
}

/// Correlated randomness a node consumes in one session. It must never be used for two sessions: reusing a mask reveals the key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[allow(clippy::exhaustive_structs, reason = "Plain share data")]
pub struct SessionRandomness {
    /// Degree-`t` Shamir shares of the random masks `s_j`.
    pub masks: Vec<ScalarField>,
    /// Degree-`t` Shamir shares of the sigma-protocol nonces `a_j`.
    pub nonces: Vec<ScalarField>,
    /// Degree-`t` Shamir share of the sigma-protocol nonce for the key.
    pub key_nonce: ScalarField,
    /// Additive shares of zero over the session's node set, blinding the shares of `u_j`.
    pub zero_u: Vec<ScalarField>,
    /// Additive shares of zero over the session's node set, blinding the shares of the constant relation coefficient.
    pub zero_t0: Vec<ScalarField>,
}

/// A node's first message.
#[derive(Debug, Clone)]
#[allow(clippy::exhaustive_structs, reason = "Plain message data")]
pub struct Round1Message {
    /// Additive shares of `u_j = s_j^2 * (k + h + j)`.
    pub u: Vec<ScalarField>,
    /// Shares of the per-bit mask commitments `s_j*G_j + nu_j*H`.
    pub s: Vec<Affine>,
    /// Shares of the per-bit nonce commitments `a_j*G_j + alpha_j*H`.
    pub a: Vec<Affine>,
    /// Share of the key nonce commitment `a_k*G + alpha_k*H`.
    pub a_k: Affine,
    /// Shares of the commitments to the three relation coefficients, per bit.
    pub t: [Vec<Affine>; 3],
}

/// The challenges the client sends in the second round.
#[derive(Debug, Clone)]
#[allow(clippy::exhaustive_structs, reason = "Plain message data")]
pub struct Round2Request {
    /// The sigma-protocol challenge.
    pub e: ScalarField,
    /// Per-bit weights `gamma_j / t_j^2` with which the coefficient commitments are combined.
    pub weights: Vec<ScalarField>,
}

/// A node's second message.
#[derive(Debug, Clone)]
#[allow(clippy::exhaustive_structs, reason = "Plain message data")]
pub struct Round2Message {
    /// Shares of the responses `a_j + e*s_j`.
    pub z: Vec<ScalarField>,
    /// Responses for the blinding of the per-bit commitments.
    pub z_nu: Vec<ScalarField>,
    /// Share of `a_k + e*k`.
    pub z_k: ScalarField,
    /// Response for the blinding of the key commitment.
    pub z_rho: ScalarField,
    /// Response for the blinding of the coefficient commitments.
    pub z_tau: ScalarField,
}

/// Secret state a node keeps between the two rounds. Consumed by [`NodeSession::round2`], so a session can be answered only once.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NodeSession {
    lagrange: ScalarField,
    key: KeyShare,
    masks: Vec<ScalarField>,
    nonces: Vec<ScalarField>,
    key_nonce: ScalarField,
    nu: Vec<ScalarField>,
    alpha: Vec<ScalarField>,
    alpha_k: ScalarField,
    tau: [Vec<ScalarField>; 3],
}

fn rand_vec<R: Rng + CryptoRng>(n: usize, rng: &mut R) -> Vec<ScalarField> {
    (0..n).map(|_| ScalarField::rand(rng)).collect()
}

fn commit(g: Affine, x: ScalarField, h: Affine, r: ScalarField) -> Projective {
    g * x + h * r
}

impl NodeSession {
    /// Computes the node's first message.
    ///
    /// `lagrange` is the node's Lagrange coefficient for interpolation at zero over the session's node set, `h_share` its Shamir share of the client input.
    ///
    /// # Panics
    /// If the randomness does not match the number of output bits.
    pub fn round1<R: Rng + CryptoRng>(
        params: &LegendreParams,
        lagrange: ScalarField,
        key: KeyShare,
        h_share: ScalarField,
        randomness: &SessionRandomness,
        rng: &mut R,
    ) -> (Self, Round1Message) {
        let n = params.n_bits();
        assert!(
            [
                randomness.masks.len(),
                randomness.nonces.len(),
                randomness.zero_u.len(),
                randomness.zero_t0.len()
            ]
            .iter()
            .all(|len| *len == n),
            "session randomness must match the number of output bits"
        );
        let g = LegendreParams::g();
        let session = Self {
            lagrange,
            key,
            masks: randomness.masks.clone(),
            nonces: randomness.nonces.clone(),
            key_nonce: randomness.key_nonce,
            nu: rand_vec(n, rng),
            alpha: rand_vec(n, rng),
            alpha_k: ScalarField::rand(rng),
            tau: [rand_vec(n, rng), rand_vec(n, rng), rand_vec(n, rng)],
        };

        let mut u = Vec::with_capacity(n);
        let mut points = Vec::with_capacity(5 * n + 1);
        for j in 0..n {
            let (s, a) = (session.masks[j], session.nonces[j]);
            let kappa = session.key.k + h_share + index(j);
            u.push(lagrange * s.square() * kappa + randomness.zero_u[j]);
            let coeffs = relation_coefficients(a, s, session.key_nonce, kappa);
            points.push(commit(
                params.gens[j],
                lagrange * s,
                params.h,
                session.nu[j],
            ));
            points.push(commit(
                params.gens[j],
                lagrange * a,
                params.h,
                session.alpha[j],
            ));
            for (c, coeff) in coeffs.into_iter().enumerate() {
                let zero = if c == 0 {
                    randomness.zero_t0[j]
                } else {
                    ScalarField::zero()
                };
                points.push(commit(
                    g,
                    lagrange * coeff + zero,
                    params.h,
                    session.tau[c][j],
                ));
            }
        }
        points.push(commit(
            g,
            lagrange * session.key_nonce,
            params.h,
            session.alpha_k,
        ));
        let points = Projective::normalize_batch(&points);

        let column = |c: usize| (0..n).map(|j| points[5 * j + c]).collect::<Vec<_>>();
        let msg = Round1Message {
            u,
            s: column(0),
            a: column(1),
            a_k: points[5 * n],
            t: [column(2), column(3), column(4)],
        };
        (session, msg)
    }

    /// Computes the node's second message and consumes the session.
    ///
    /// # Panics
    /// If the request does not match the number of output bits.
    #[must_use]
    pub fn round2(self, request: &Round2Request) -> Round2Message {
        let n = self.masks.len();
        assert_eq!(request.weights.len(), n, "one weight per output bit");
        let e = request.e;
        let e2 = e.square();
        let z_tau = (0..n)
            .map(|j| {
                request.weights[j] * (self.tau[0][j] + e * self.tau[1][j] + e2 * self.tau[2][j])
            })
            .sum();
        Round2Message {
            z: (0..n)
                .map(|j| self.lagrange * (self.nonces[j] + e * self.masks[j]))
                .collect(),
            z_nu: (0..n).map(|j| self.alpha[j] + e * self.nu[j]).collect(),
            z_k: self.lagrange * (self.key_nonce + e * self.key.k),
            z_rho: self.alpha_k + e * self.lagrange * self.key.rho,
            z_tau,
        }
    }
}

/// Errors of the client side of the threshold evaluation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ThresholdError {
    /// A node message has the wrong number of entries, or no messages were given.
    MalformedMessage,
    /// A masked value is zero. Happens with negligible probability for honest nodes.
    ZeroOutput,
    /// The aggregated proof does not verify: at least one node deviated or too few nodes answered.
    InvalidProof,
}

impl std::error::Error for ThresholdError {}

impl std::fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MalformedMessage => "malformed node message",
            Self::ZeroOutput => "masked PRF value is zero",
            Self::InvalidProof => "aggregated Legendre proof is invalid",
        })
    }
}

impl From<InvalidLegendreProof> for ThresholdError {
    fn from(_: InvalidLegendreProof) -> Self {
        Self::InvalidProof
    }
}

/// Client state between the two rounds.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientSession {
    #[zeroize(skip)]
    c_k: Affine,
    h: ScalarField,
    bits: Vec<bool>,
    /// `1 / sqrt(u_j / N^{b_j})`
    scale: Vec<ScalarField>,
    #[zeroize(skip)]
    c_sigma: Affine,
    #[zeroize(skip)]
    t1: Affine,
    #[zeroize(skip)]
    t2: Affine,
    e: ScalarField,
}

fn sum_points<'a>(columns: impl Iterator<Item = &'a Vec<Affine>>, n: usize) -> Vec<Affine> {
    let mut acc = vec![Projective::zero(); n];
    for column in columns {
        for (acc, p) in acc.iter_mut().zip(column) {
            *acc += p;
        }
    }
    Projective::normalize_batch(&acc)
}

fn sum_scalars<'a>(
    columns: impl Iterator<Item = &'a Vec<ScalarField>>,
    n: usize,
) -> Vec<ScalarField> {
    let mut acc = vec![ScalarField::zero(); n];
    for column in columns {
        for (acc, x) in acc.iter_mut().zip(column) {
            *acc += x;
        }
    }
    acc
}

impl ClientSession {
    /// Aggregates the first messages of all nodes of the session, derives the output bits and the challenges for the second round.
    ///
    /// # Errors
    /// See [`ThresholdError`].
    pub fn round1(
        params: &LegendreParams,
        c_k: Affine,
        h: ScalarField,
        msgs: &[Round1Message],
    ) -> Result<(Self, Round2Request), ThresholdError> {
        let n = params.n_bits();
        let well_formed = |m: &Round1Message| {
            [
                m.u.len(),
                m.s.len(),
                m.a.len(),
                m.t[0].len(),
                m.t[1].len(),
                m.t[2].len(),
            ]
            .iter()
            .all(|len| *len == n)
        };
        if msgs.is_empty() || !msgs.iter().all(well_formed) {
            return Err(ThresholdError::MalformedMessage);
        }
        let u = sum_scalars(msgs.iter().map(|m| &m.u), n);
        let mut bits = Vec::with_capacity(n);
        let mut scale = Vec::with_capacity(n);
        for u_j in u {
            if u_j.is_zero() {
                return Err(ThresholdError::ZeroOutput);
            }
            let bit = !is_square(u_j);
            // u_j / N^{b_j} is a square by the choice of b_j
            let root = (u_j * target(bit).inverse().ok_or(ThresholdError::ZeroOutput)?)
                .sqrt()
                .ok_or(ThresholdError::ZeroOutput)?;
            bits.push(bit);
            scale.push(root.inverse().ok_or(ThresholdError::ZeroOutput)?);
        }

        let c_sigma = Projective::msm_unchecked(&sum_points(msgs.iter().map(|m| &m.s), n), &scale)
            .into_affine();
        let a = Projective::msm_unchecked(&sum_points(msgs.iter().map(|m| &m.a), n), &scale)
            .into_affine();
        let a_k = msgs.iter().map(|m| m.a_k).sum::<Projective>().into_affine();

        let batch = batch_challenges(c_k, c_sigma, h, &bits);
        let weights = (0..n)
            .map(|j| batch.gamma(j) * scale[j].square())
            .collect::<Vec<_>>();
        let [t0, t1, t2] = [0, 1, 2].map(|c| {
            Projective::msm_unchecked(&sum_points(msgs.iter().map(|m| &m.t[c]), n), &weights)
                .into_affine()
        });
        let e = sigma_challenge(&batch, a, a_k, t0, t1, t2);
        let session = Self {
            c_k,
            h,
            bits,
            scale,
            c_sigma,
            t1,
            t2,
            e,
        };
        Ok((session, Round2Request { e, weights }))
    }

    /// Aggregates the second messages into the output bits and their proof, and verifies the proof.
    ///
    /// # Errors
    /// See [`ThresholdError`].
    pub fn round2(
        self,
        params: &LegendreParams,
        msgs: &[Round2Message],
    ) -> Result<(Vec<bool>, LegendreProof), ThresholdError> {
        let n = params.n_bits();
        if msgs.is_empty() || !msgs.iter().all(|m| m.z.len() == n && m.z_nu.len() == n) {
            return Err(ThresholdError::MalformedMessage);
        }
        let z = sum_scalars(msgs.iter().map(|m| &m.z), n);
        let z_nu = sum_scalars(msgs.iter().map(|m| &m.z_nu), n);
        let proof = LegendreProof {
            c_sigma: self.c_sigma,
            t1: self.t1,
            t2: self.t2,
            e: self.e,
            z: z.iter()
                .zip(&self.scale)
                .map(|(z, scale)| *z * scale)
                .collect(),
            z_nu: z_nu
                .iter()
                .zip(&self.scale)
                .map(|(z, scale)| *z * scale)
                .sum(),
            z_k: msgs.iter().map(|m| m.z_k).sum(),
            z_rho: msgs.iter().map(|m| m.z_rho).sum(),
            z_tau: msgs.iter().map(|m| m.z_tau).sum(),
        };
        proof.verify(params, self.c_k, self.h, &self.bits)?;
        Ok((self.bits.clone(), proof))
    }
}

#[cfg(test)]
mod tests;
