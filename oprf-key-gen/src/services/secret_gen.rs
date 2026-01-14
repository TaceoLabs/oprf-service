//! This service handles the distributed key-gen/reshare protocol.
//!
//! It maintains toxic waste for ongoing rounds. The service handles the destruction of this toxic waste during the lifecycle of protocol.
//!
//! Currently, there is no timeout for a protocol run. Therefore, the toxic waste will not be cleaned up and will remain in memory.
//!
//! On the other hand, the toxic waste is not persisted anywhere other than RAM. This means that if an OPRF node shuts down during the protocol, the key-gen/reshare cannot be completed, as the data is lost.
//!
//! **Important:** This service is **not thread-safe**. It is intended to be used
//! only in contexts where a single dedicated task owns the struct. No internal
//! locking (`Mutex`) or reference counting (`Arc`) is performed, so multiple tasks
//! must not concurrently access it.
//!
//! We refer to [Appendix B.2 of our design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf) for more information about the OPRF-nullifier
//! generation protocol.

use std::collections::HashMap;

use alloy::primitives::U256;
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_ff::UniformRand as _;
use eyre::{Context, ContextCompat};
use groth16_material::circom::CircomGroth16Material;
use itertools::{Itertools as _, izip};
use oprf_core::{
    ddlog_equality::shamir::DLogShareShamir,
    keygen::{self, KeyGenPoly},
};
use oprf_types::{
    OprfKeyId,
    chain::{
        SecretGenRound1Contribution, SecretGenRound2Contribution, SecretGenRound3Contribution,
    },
    crypto::{
        EphemeralEncryptionPublicKey, SecretGenCiphertext, SecretGenCiphertexts,
        SecretGenCommitment,
    },
};
use rand::{CryptoRng, Rng};
use tracing::instrument;
use zeroize::ZeroizeOnDrop;

#[cfg(test)]
mod tests;

/// Defines how many contributions we need to reconstruct the received [`DLogShareShamir`].
///
/// We need contributions from everyone during key-gen and only some (along with the lagrange coefficients) during reshare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Contributions {
    /// Need contributions from everyone (key-gen).
    Full,
    /// Shamir sharing - wraps the lagrange coefficients.
    Shamir(Vec<ark_babyjubjub::Fr>),
}

/// Service for managing the distributed key-gen/reshare protocol.
///
/// **Note:** Must only be used in a single-owner context. Do not share across tasks.
pub(crate) struct DLogSecretGenService {
    toxic_waste_round1: HashMap<OprfKeyId, ToxicWasteRound1>,
    toxic_waste_round2: HashMap<OprfKeyId, ToxicWasteRound2>,
    finished_shares: HashMap<OprfKeyId, DLogShareShamir>,
    key_gen_material: CircomGroth16Material,
}

/// The ephemeral private key of an OPRF node.
///
/// Used internally to compute Diffie-Hellman for key-generation operations.
/// Not `Debug`/`Display` to avoid accidental leaks.
///
/// **Note**: Don't reuse a key. One key per keygen/reshare.
#[derive(ZeroizeOnDrop)]
struct EphemeralEncryptionPrivateKey(ark_babyjubjub::Fr);

/// The toxic waste generated in round 1 of the key-gen/reshare protocol.
///
/// Contains the full polynomial and the ephemeral private key for a single protocol run.
struct ToxicWasteRound1 {
    poly: KeyGenPoly,
    sk: EphemeralEncryptionPrivateKey,
}

/// The toxic waste generated in round 2 of the key-gen/reshare protocol.
///
/// Contains the ephemeral private key for a single key generation.
struct ToxicWasteRound2 {
    sk: EphemeralEncryptionPrivateKey,
}

impl From<EphemeralEncryptionPrivateKey> for ToxicWasteRound2 {
    fn from(sk: EphemeralEncryptionPrivateKey) -> Self {
        Self { sk }
    }
}

impl EphemeralEncryptionPrivateKey {
    /// Generates a fresh private-key to be used in a single DLog generation.
    /// **Note**: do not reuse this key.
    fn generate<R: Rng + CryptoRng>(r: &mut R) -> Self {
        Self(ark_babyjubjub::Fr::rand(r))
    }
    /// Computes the associated [`EphemeralEncryptionPublicKey`] by multiplying the private key with the generator.
    pub fn get_public_key(&self) -> EphemeralEncryptionPublicKey {
        EphemeralEncryptionPublicKey::new_unchecked(
            (ark_babyjubjub::EdwardsAffine::generator() * self.0).into_affine(),
        )
    }

    /// Returns the inner scalar value of the private key.
    pub fn inner(&self) -> &ark_babyjubjub::Fr {
        &self.0
    }
}

impl ToxicWasteRound1 {
    /// Creates a new instance of `ToxicWasteRound1` intended to be used for key-gen (not reshare).
    ///
    /// Generates a secret-sharing polynomial with some randomly sampled secret and an ephemeral private key for the first round of the key generation protocol. For toxic-waste for resharing, see [`Self::reshare`].
    ///
    /// **Note:** do not reuse the toxic waste.
    ///
    /// # Arguments
    ///
    /// * `degree` - The degree of the polynomial to be generated (relates to threshold settings).
    /// * `rng` - A mutable reference to a cryptographically secure random number generator.
    fn new<R: Rng + CryptoRng>(degree: usize, rng: &mut R) -> Self {
        let poly = KeyGenPoly::new(rng, degree);
        let sk = EphemeralEncryptionPrivateKey::generate(rng);
        Self { poly, sk }
    }

    /// Creates a new instance of `ToxicWasteRound1` intended to be used for reshare (not key-gen).
    ///
    /// Generates a secret-sharing polynomial using the old share as the secret and an ephemeral private key for the first round of the reshare protocol. For toxic-waste for key-gen, see [`Self::new`].
    ///
    /// **Note:** do not reuse the toxic waste.
    ///
    /// # Arguments
    ///
    /// * `old_share` - The share of the previous epoch.
    /// * `rng` - A mutable reference to a cryptographically secure random number generator.
    fn reshare<R: Rng + CryptoRng>(old_share: DLogShareShamir, degree: usize, rng: &mut R) -> Self {
        let poly = KeyGenPoly::reshare(rng, old_share.into(), degree);
        let sk = EphemeralEncryptionPrivateKey::generate(rng);
        Self { poly, sk }
    }

    /// Advances to the second round of key-gen/reshare protocol.
    ///
    /// Consumes `self` and combines the secret material from round one with the public keys of all nodes.
    ///
    /// **Note:** do not reuse the toxic waste.
    ///
    /// # Returns
    ///
    /// A `ToxicWasteRound2` instance containing the ephemeral private key.
    fn next(self) -> ToxicWasteRound2 {
        ToxicWasteRound2 { sk: self.sk }
    }
}

impl DLogSecretGenService {
    /// Initializes a new DLog secret generation service.
    pub(crate) fn init(key_gen_material: CircomGroth16Material) -> Self {
        Self {
            toxic_waste_round1: HashMap::new(),
            toxic_waste_round2: HashMap::new(),
            finished_shares: HashMap::new(),
            key_gen_material,
        }
    }

    /// Deletes all material associated with the [`OprfKeyId`].
    /// This includes:
    /// * [`ToxicWasteRound1`]
    /// * [`ToxicWasteRound2`]
    /// * Any finished shares that wait for finalize from all nodes
    pub(crate) fn delete_oprf_key_material(&mut self, oprf_key_id: OprfKeyId) {
        if self.toxic_waste_round1.remove(&oprf_key_id).is_some() {
            tracing::debug!("removed {oprf_key_id:?} toxic waste round 1");
        };
        if self.toxic_waste_round2.remove(&oprf_key_id).is_some() {
            tracing::debug!("removed {oprf_key_id:?} toxic waste round 2");
        };
        if self.finished_shares.remove(&oprf_key_id).is_some() {
            tracing::debug!("removed {oprf_key_id:?} finished share");
        };
    }

    /// Executes round 1 of the key-gen protocol.
    ///
    /// Generates a random polynomial of the specified degree and stores it internally.
    /// Returns a [`SecretGenRound1Contribution`] containing the commitment to share with other parties.
    ///
    /// # Arguments
    /// * `oprf_key_id` - Identifier of the OPRF key that we generate.
    /// * `threshold` - The threshold of the MPC-protocol.
    #[instrument(level = "info", skip(self))]
    pub(crate) fn key_gen_round1(
        &mut self,
        oprf_key_id: OprfKeyId,
        threshold: u16,
    ) -> SecretGenRound1Contribution {
        tracing::info!("secret gen round1..");
        let mut rng = rand::thread_rng();
        let degree = usize::from(threshold - 1);
        let toxic_waste = ToxicWasteRound1::new(degree, &mut rng);
        self.round1_inner(oprf_key_id, toxic_waste)
    }

    /// Executes the producer round 2 of the key-gen/reshare protocol.
    ///
    /// Producers generate secret shares for all nodes based on the polynomial generated in round 1 and a proof of the encryptions. Consumers (receiving parties should call [`Self::consumer_round2`]).
    ///
    /// Returns a [`SecretGenRound2Contribution`] containing ciphertexts for all parties + the proof.
    ///
    /// # Arguments
    /// * `oprf_key_id` - Identifier of the OPRF key that we generate.
    /// * `pks` - List of public keys for nodes participating in the protocol.
    pub(crate) fn producer_round2(
        &mut self,
        oprf_key_id: OprfKeyId,
        pks: Vec<EphemeralEncryptionPublicKey>,
    ) -> eyre::Result<SecretGenRound2Contribution> {
        let toxic_waste_r1 = self
            .toxic_waste_round1
            .remove(&oprf_key_id)
            .context("Did not have round 1 toxic waste stored")?;
        let (contribution, toxix_waste_r2) =
            compute_keygen_proof(&self.key_gen_material, toxic_waste_r1, pks)
                .context("while computing proof for round2")?;
        self.toxic_waste_round2.insert(oprf_key_id, toxix_waste_r2);
        Ok(SecretGenRound2Contribution {
            oprf_key_id,
            contribution,
        })
    }

    /// Finalizes the key-gen/reshare protocol by decrypting received ciphertexts and computing the final secret share for this party.
    ///
    /// # Arguments
    /// * `oprf_key_id` - Identifier of the OPRF key that we generate.
    /// * `ciphers` - Ciphertexts received from other parties in round 2.
    /// * `sharing_type` - Defines how the resulting share is secret-shared. `Linear` for key-gen, `Shamir` for reshare.
    /// * `pks` - The ephemeral public-keys of the producers needed for DHE.
    #[instrument(level = "info", skip_all, fields(oprf_key_id=%oprf_key_id))]
    pub(crate) fn round3(
        &mut self,
        oprf_key_id: OprfKeyId,
        ciphers: Vec<SecretGenCiphertext>,
        sharing_type: Contributions,
        pks: Vec<EphemeralEncryptionPublicKey>,
    ) -> eyre::Result<SecretGenRound3Contribution> {
        tracing::info!("calling round3 with {}", ciphers.len());
        let toxic_waste_r2 = self
            .toxic_waste_round2
            .remove(&oprf_key_id)
            .context("Did not have round 2 toxic waste stored")?;
        let share = decrypt_key_gen_ciphertexts(ciphers, toxic_waste_r2, sharing_type, pks)
            .context("while computing DLogShare")?;
        // We need to store the computed share - as soon as we get ready
        // event, we will store the share inside the crypto-device.
        self.finished_shares.insert(oprf_key_id, share);
        Ok(SecretGenRound3Contribution { oprf_key_id })
    }

    /// Marks the generated secret as finished.
    ///
    /// # Arguments
    /// * `oprf_key_id` - Identifier of the RP for which the secret is being finalized.
    pub(crate) fn finalize(&mut self, oprf_key_id: OprfKeyId) -> eyre::Result<DLogShareShamir> {
        tracing::info!("finalize..");
        self.finished_shares
            .remove(&oprf_key_id)
            .context("cannot find computed DLogShare")
    }

    /// Executes round 1 of the reshare protocol.
    ///
    /// Generates a secret-sharing polynomial where the secret-value is the old dlog-share of the specified degree and stores it internally.
    /// Returns a [`SecretGenRound1Contribution`] containing the commitment to share with other parties.
    ///
    /// # Arguments
    /// * `oprf_key_id` - Identifier of the OPRF key that we generate.
    /// * `threshold` - The threshold of the MPC-protocol.
    /// * `old_share` - The old share used as input for the resharing
    pub(crate) fn reshare_round1(
        &mut self,
        oprf_key_id: OprfKeyId,
        threshold: u16,
        old_share: DLogShareShamir,
    ) -> SecretGenRound1Contribution {
        tracing::info!("reshare round1..");
        let mut rng = rand::thread_rng();
        let degree = usize::from(threshold - 1);
        let toxic_waste = ToxicWasteRound1::reshare(old_share, degree, &mut rng);
        self.round1_inner(oprf_key_id, toxic_waste)
    }

    /// internal helper function for round1. Called by key-gen and reshare.
    fn round1_inner(
        &mut self,
        oprf_key_id: OprfKeyId,
        toxic_waste: ToxicWasteRound1,
    ) -> SecretGenRound1Contribution {
        let contribution = SecretGenCommitment {
            comm_share: toxic_waste.poly.get_pk_share(),
            comm_coeffs: toxic_waste.poly.get_coeff_commitment(),
            eph_pub_key: toxic_waste.sk.get_public_key(),
        };
        let old_value = self.toxic_waste_round1.insert(oprf_key_id, toxic_waste);
        // TODO handle this more gracefully
        assert!(
            old_value.is_none(),
            "already had this round1 - this is a bug"
        );
        SecretGenRound1Contribution {
            oprf_key_id,
            contribution,
        }
    }

    /// Executes the consumer round 1 of the reshare protocol.
    ///
    /// If a party does not have the share for an [`OprfKeyId`] it needs to participate as a consumer in the reshare protocol. In that case the node will only produce an encryption key-pair and sends this on-chain so that the producers generate the share for the node.
    pub(crate) fn consumer_round1<R: Rng + CryptoRng>(
        &mut self,
        oprf_key_id: OprfKeyId,
        rng: &mut R,
    ) -> EphemeralEncryptionPublicKey {
        tracing::debug!("computing ephemeral encryption key");
        let sk = EphemeralEncryptionPrivateKey::generate(rng);
        let pk = sk.get_public_key();
        if self
            .toxic_waste_round2
            .insert(oprf_key_id, ToxicWasteRound2::from(sk))
            .is_some()
        {
            tracing::warn!("overwriting toxic waste for {oprf_key_id}");
        }
        pk
    }

    /// Executes the consumer round 2 of the reshare protocol.
    ///
    /// Only relevant for reshare as everyone is a producer in key-gen. A consuming node simply drops the polynomial it created in round1 if it created one in round 1.
    pub(crate) fn consumer_round2(&mut self, oprf_key_id: OprfKeyId) {
        tracing::debug!("reverting reshare...");
        if let Some(toxic_waste_round1) = self.toxic_waste_round1.remove(&oprf_key_id) {
            self.toxic_waste_round2
                .insert(oprf_key_id, toxic_waste_round1.next());
            tracing::debug!("tried to be a producer in round 2 - dropping polynomial");
        } else {
            tracing::debug!("nothing to do as registered as consumer in round1");
        }
    }
}

/// Decrypts a key-generation ciphertext using the private key.
///
/// Returns the share of the node's polynomial or an error if decryption fails.
fn decrypt_key_gen_ciphertexts(
    ciphers: Vec<SecretGenCiphertext>,
    toxic_waste: ToxicWasteRound2,
    sharing_type: Contributions,
    pks: Vec<EphemeralEncryptionPublicKey>,
) -> eyre::Result<DLogShareShamir> {
    let ToxicWasteRound2 { sk } = toxic_waste;
    // In some later version, we maybe need some meaningful way
    // to tell which party produced a wrong ciphertext. Currently,
    // we trust the smart-contract to verify the proof, therefore
    // it should never happen that this here fails. If yes, there is
    // a bug.
    //
    // In some future version, we might have an optimistic approach
    // where we don't verify the proof and need to pinpoint the
    // scoundrel.
    let shares = ciphers
        .into_iter()
        .enumerate()
        .map(|(idx, cipher)| {
            let SecretGenCiphertext {
                nonce,
                cipher,
                commitment,
            } = cipher;
            let their_pk = pks[idx].inner();
            let share = keygen::decrypt_share(sk.inner(), their_pk, cipher, nonce)
                .context("cannot decrypt share ciphertext from node")?;
            // check commitment
            let is_commitment = (ark_babyjubjub::EdwardsAffine::generator() * share).into_affine();
            // This is actually not possible if Smart Contract verified proof
            if is_commitment == commitment {
                eyre::Ok(share)
            } else {
                eyre::bail!("Commitment for {idx} wrong");
            }
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    match sharing_type {
        Contributions::Full => Ok(DLogShareShamir::from(keygen::accumulate_shares(&shares))),
        Contributions::Shamir(lagrange) => Ok(DLogShareShamir::from(
            keygen::accumulate_lagrange_shares(&shares, &lagrange),
        )),
    }
}

/// Executes the `KeyGen` circom circuit
///
/// ## Security Considerations
/// This method expects that the parameter `pks` contains exactly three [`EphemeralEncryptionPublicKey`]s that encapsulate valid BabyJubJub points on the correct subgroup.
///
/// If `pks` were constructed without [`EphemeralEncryptionPublicKey::new_unchecked`], the points are on curve and the correct subgroup.
///
/// This method consumes an instance of [`ToxicWasteRound1`] and, on success, produces an instance of [`ToxicWasteRound2`]. This enforces that the toxic waste from round 1 is in fact dropped when continuing with the KeyGen protocol.
fn compute_keygen_proof(
    key_gen_material: &CircomGroth16Material,
    toxic_waste: ToxicWasteRound1,
    pks: Vec<EphemeralEncryptionPublicKey>,
) -> eyre::Result<(SecretGenCiphertexts, ToxicWasteRound2)> {
    // compute the nonces for every party
    let num_parties = pks.len();
    let mut rng = rand::thread_rng();
    let nonces = (0..pks.len())
        .map(|_| ark_babyjubjub::Fq::rand(&mut rng))
        .collect_vec();

    let flattened_pks = pks
        .iter()
        .flat_map(|pk| {
            let p = pk.inner();
            [p.x.into(), p.y.into()]
        })
        .collect::<Vec<U256>>();

    let coeffs = toxic_waste
        .poly
        .coeffs()
        .iter()
        .map(|coeff| coeff.into())
        .collect::<Vec<U256>>();

    // build the input for the graph
    let mut inputs = HashMap::new();
    inputs.insert(
        String::from("degree"),
        vec![U256::from(toxic_waste.poly.degree())],
    );
    inputs.insert(String::from("my_sk"), vec![toxic_waste.sk.inner().into()]);
    inputs.insert(String::from("pks"), flattened_pks);
    inputs.insert(String::from("poly"), coeffs);
    inputs.insert(
        String::from("nonces"),
        nonces.iter().map(|n| n.into()).collect_vec(),
    );
    let (proof, public_inputs) = key_gen_material
        .generate_proof(&inputs, &mut rand::thread_rng())
        .context("while computing key-gen proof")?;

    key_gen_material
        .verify_proof(&proof, &public_inputs)
        .context("while verifying key gen proof")?;

    // parse the outputs from the public_input
    let pk_computed = ark_babyjubjub::EdwardsAffine::new(public_inputs[0], public_inputs[1]);
    // parse commitment to share
    let comm_share_computed =
        ark_babyjubjub::EdwardsAffine::new(public_inputs[2], public_inputs[3]);

    // parse commitment to coefficients
    let comm_coeffs_computed = public_inputs[4];

    // parse one ciphertext per party
    let ciphertexts = public_inputs[5..5 + num_parties].iter();
    // parse one affine point (2 elements in inputs) per party
    let comm_plains = public_inputs[5 + num_parties..5 + num_parties * 3]
        .chunks_exact(2)
        .map(|coords| ark_babyjubjub::EdwardsAffine::new(coords[0], coords[1]));

    let rp_ciphertexts = izip!(ciphertexts, comm_plains, nonces)
        .map(|(cipher, comm, nonce)| SecretGenCiphertext::new(*cipher, comm, nonce))
        .collect_vec();

    if pk_computed != toxic_waste.sk.get_public_key().inner() {
        eyre::bail!("computed public key does not match with my own!");
    }

    if comm_share_computed != toxic_waste.poly.get_pk_share() {
        eyre::bail!("computed commitment to share does not match with my own!");
    }

    if comm_coeffs_computed != toxic_waste.poly.get_coeff_commitment() {
        eyre::bail!("computed commitment to coeffs does not match with my own!");
    }

    let ciphers = SecretGenCiphertexts::new(proof.into(), rp_ciphertexts);
    Ok((ciphers, toxic_waste.next()))
}
