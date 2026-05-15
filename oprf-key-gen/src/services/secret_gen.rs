//! This service handles the distributed key-gen/reshare protocol.
//!
//! It creates and consumes intermediate state for ongoing key-gen and reshare rounds.
//!
//! This intermediate state is persisted via the [`SecretManager`](crate::secret_manager::SecretManager)
//! between protocol rounds and removed again when a run is finalized, aborted, or deleted.
//!
//! Currently, there is no timeout for a protocol run. Therefore, stale in-progress state is not
//! cleaned up automatically if a run never finishes.
//!
//! **Important:** This service is **not thread-safe**. It is intended to be used
//! only in contexts where a single dedicated task owns the struct. No internal
//! locking (`Mutex`) or reference counting (`Arc`) is performed, so multiple tasks
//! must not concurrently access it.
//!
//! We refer to [Appendix B.2 of our design document](https://github.com/TaceoLabs/oprf-service/blob/main/docs/oprf.pdf) for more information about the OPRF-nullifier
//! generation protocol.

use core::fmt;
use std::{collections::HashMap, num::NonZeroU16, sync::Arc};

use alloy::primitives::U256;
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_ff::UniformRand as _;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use eyre::{Context, ContextCompat};
use groth16_material::circom::CircomGroth16Material;
use itertools::{Itertools as _, izip};
use oprf_core::{
    ddlog_equality::shamir::DLogShareShamir,
    keygen::{self, KeyGenPoly},
};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    chain::OprfKeyGen::Round1Contribution,
    crypto::{
        EphemeralEncryptionPublicKey, OprfPublicKey, SecretGenCiphertext, SecretGenCiphertexts,
        SecretGenCommitment,
    },
};
use rand::{CryptoRng, Rng};
use zeroize::ZeroizeOnDrop;

use crate::secret_manager::{SecretManagerError, SecretManagerService};

#[cfg(test)]
mod tests;

/// Error type returned by [`DLogSecretGenService`] methods.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SecretGenError {
    #[error(transparent)]
    SecretManagerError(#[from] SecretManagerError),
    #[error("internal error: {0:?}")]
    Internal(#[from] eyre::Report),
}

// Cannot use type alias Result because CanonicalSerialize/CanonicalDeserialize yield compiler errors in that case
type SecretGenResult<T> = std::result::Result<T, SecretGenError>;

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
#[derive(Clone)]
pub(crate) struct DLogSecretGenService {
    secret_manager: SecretManagerService,
    key_gen_material: Arc<CircomGroth16Material>,
}

/// Intermediate values generated during the key-generation (or reshare) protocol.
///
/// These are persisted between protocol rounds via the [`SecretManager`](crate::services::secret_manager::SecretManager) and consumed once the round completes.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct KeyGenIntermediateValues {
    /// Ephemeral secret key for this key-gen, used for encryption and decryption when communicating with peers over the chain.
    ///
    /// Must only be used for a single key-generation.
    sk: EphemeralEncryptionPrivateKey,
    /// The party's polynomial during key-generation, representing its randomness contribution.
    ///
    /// May be `None` during a reshare if the node registers as a consumer — this occurs
    /// when the node does not hold a share from the previous epoch.
    poly: Option<KeyGenPoly>,
}

impl fmt::Debug for KeyGenIntermediateValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyGenIntermediates[REDACTED]")
    }
}

/// The ephemeral private key of an OPRF node.
///
/// Used internally to compute Diffie-Hellman for key-generation operations.
/// Not `Debug`/`Display` to avoid accidental leaks.
///
/// **Note**: Don't reuse a key. One key per keygen/reshare.
#[derive(ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize)]
struct EphemeralEncryptionPrivateKey(ark_babyjubjub::Fr);

impl EphemeralEncryptionPrivateKey {
    /// Generates a fresh private-key to be used in a single `DLog` generation.
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

impl KeyGenIntermediateValues {
    /// Creates a new instance of `KeyGenIntermediateValues` for key generation.
    ///
    /// Generates a secret-sharing polynomial with a freshly sampled secret and an ephemeral private key for the first round of the key-generation protocol. For resharing, see [`Self::reshare`].
    ///
    /// **Note:** do not reuse these intermediate values.
    ///
    /// # Arguments
    ///
    /// * `degree` - The degree of the polynomial to be generated (relates to threshold settings).
    /// * `rng` - A mutable reference to a cryptographically secure random number generator.
    fn new<R: Rng + CryptoRng>(degree: usize, rng: &mut R) -> Self {
        let poly = KeyGenPoly::new(rng, degree);
        let sk = EphemeralEncryptionPrivateKey::generate(rng);
        Self {
            poly: Some(poly),
            sk,
        }
    }

    /// Creates a new instance of `KeyGenIntermediateValues` for resharing.
    ///
    /// Generates a secret-sharing polynomial using the old share as the secret and an ephemeral private key for the first round of the reshare protocol. For key generation, see [`Self::new`].
    ///
    /// **Note:** do not reuse these intermediate values.
    ///
    /// # Arguments
    ///
    /// * `old_share` - The share of the previous epoch.
    /// * `rng` - A mutable reference to a cryptographically secure random number generator.
    fn reshare<R: Rng + CryptoRng>(old_share: DLogShareShamir, degree: usize, rng: &mut R) -> Self {
        let poly = KeyGenPoly::reshare(rng, old_share.into(), degree);
        let sk = EphemeralEncryptionPrivateKey::generate(rng);
        Self {
            poly: Some(poly),
            sk,
        }
    }

    fn consumer<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self {
            sk: EphemeralEncryptionPrivateKey::generate(rng),
            poly: None,
        }
    }

    fn build_round1_contribution(&self) -> Round1Contribution {
        let Self { sk, poly } = self;
        if let Some(poly) = poly {
            Round1Contribution::from(SecretGenCommitment {
                comm_share: poly.get_pk_share(),
                comm_coeffs: poly.get_coeff_commitment(),
                eph_pub_key: sk.get_public_key(),
            })
        } else {
            Round1Contribution::from(sk.get_public_key())
        }
    }
}

impl DLogSecretGenService {
    /// Initializes a new `DLog` secret generation service.
    pub(crate) fn init(
        key_gen_material: CircomGroth16Material,
        secret_manager: SecretManagerService,
    ) -> Self {
        Self {
            key_gen_material: Arc::new(key_gen_material),
            secret_manager,
        }
    }

    /// Deletes all material associated with the [`OprfKeyId`].
    pub(crate) async fn delete_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> SecretGenResult<()> {
        self.secret_manager
            .delete_oprf_key_material(oprf_key_id)
            .await?;
        Ok(())
    }

    /// Aborts an in-process keygen.
    pub(crate) async fn abort_keygen(&self, oprf_key_id: OprfKeyId) -> SecretGenResult<()> {
        self.secret_manager.abort_keygen(oprf_key_id).await?;
        Ok(())
    }

    /// Executes round 1 of the key-gen protocol.
    ///
    /// Generates a random polynomial of the specified degree and persists the resulting intermediate values via the secret manager.
    /// Returns an [`OprfKeyGen::Round1Contribution`](oprf_types::chain::OprfKeyGen::Round1Contribution)
    /// containing the commitment to share with other parties.
    ///
    /// # Arguments
    /// * `oprf_key_id` - Identifier of the OPRF key that we generate.
    /// * `threshold` - The threshold of the MPC-protocol.
    pub(crate) async fn key_gen_round1(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        threshold: NonZeroU16,
    ) -> SecretGenResult<Round1Contribution> {
        tracing::trace!("secret gen round1 - creating new intermediates");
        let degree = usize::from(threshold.get() - 1);
        let intermediates = KeyGenIntermediateValues::new(degree, &mut rand::thread_rng());
        let intermediates = self
            .secret_manager
            .try_store_keygen_intermediates(oprf_key_id, pending_epoch, intermediates)
            .await?;
        Ok(intermediates.build_round1_contribution())
    }

    /// Executes the producer round 2 of the key-gen/reshare protocol.
    ///
    /// Producers generate secret shares for all nodes based on the polynomial generated in round 1 and a proof of the encryptions.
    ///
    /// Returns [`SecretGenCiphertexts`] containing ciphertexts for all parties plus the proof.
    ///
    /// # Arguments
    /// * `oprf_key_id` - Identifier of the OPRF key that we generate.
    /// * `pks` - List of public keys for nodes participating in the protocol.
    pub(crate) async fn producer_round2(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        pks: Vec<EphemeralEncryptionPublicKey>,
    ) -> SecretGenResult<SecretGenCiphertexts> {
        let intermediate_values = self
            .secret_manager
            .fetch_keygen_intermediates(oprf_key_id, pending_epoch)
            .await?;
        let key_gen_material = Arc::clone(&self.key_gen_material);
        let contribution = tokio::task::spawn_blocking(move || {
            compute_keygen_proof(&key_gen_material, intermediate_values, &pks)
        })
        .await
        .context("while joining compute key-gen")?
        .context("while computing proof for round2")?;
        Ok(contribution)
    }

    /// Decrypts received ciphertexts and stores the resulting pending share for this party.
    ///
    /// # Arguments
    /// * `oprf_key_id` - Identifier of the OPRF key that we generate.
    /// * `ciphers` - Ciphertexts received from other parties in round 2.
    /// * `sharing_type` - Defines how the resulting share is combined. `Full` for key-gen, `Shamir` for reshare.
    /// * `pks` - The ephemeral public-keys of the producers needed for DHE.
    pub(crate) async fn round3(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        ciphers: Vec<SecretGenCiphertext>,
        sharing_type: Contributions,
        pks: &[EphemeralEncryptionPublicKey],
    ) -> SecretGenResult<()> {
        tracing::trace!("calling round3 with {}", ciphers.len());
        let intermediate_values = self
            .secret_manager
            .fetch_keygen_intermediates(oprf_key_id, pending_epoch)
            .await?;
        let share = decrypt_key_gen_ciphertexts(ciphers, intermediate_values, sharing_type, pks)
            .context("while computing DLogShare")?;
        // Store the computed share as pending until the finalize event confirms it.
        self.secret_manager
            .store_pending_dlog_share(oprf_key_id, pending_epoch, share)
            .await?;
        Ok(())
    }

    /// Marks the generated secret as finished.
    ///
    /// # Arguments
    /// * `oprf_key_id` - Identifier of the OPRF key being finalized.
    /// * `epoch` - The generated epoch.
    /// * `public_key` - The generated [`OprfPublicKey`].
    pub(crate) async fn finalize(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        public_key: OprfPublicKey,
    ) -> SecretGenResult<()> {
        self.secret_manager
            .confirm_dlog_share(oprf_key_id, epoch, public_key)
            .await?;
        Ok(())
    }

    /// Executes round 1 of the reshare protocol.
    ///
    /// Generates a secret-sharing polynomial where the secret value is the previously confirmed share and persists the resulting intermediate values.
    /// Returns an [`OprfKeyGen::Round1Contribution`](oprf_types::chain::OprfKeyGen::Round1Contribution)
    /// containing the commitment to share with other parties.
    ///
    /// # Arguments
    /// * `oprf_key_id` - Identifier of the OPRF key that we generate.
    /// * `pending_epoch` - The epoch being generated by the reshare flow.
    /// * `threshold` - The threshold of the MPC protocol.
    pub(crate) async fn reshare_round1(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        threshold: NonZeroU16,
    ) -> SecretGenResult<Round1Contribution> {
        tracing::trace!("creating new intermediates");
        let old_share = self
            .secret_manager
            .get_share_by_epoch(oprf_key_id, pending_epoch.prev())
            .await?;
        let intermediates = if let Some(old_share) = old_share {
            tracing::trace!("found share - we want to be PRODUCER");
            let mut rng = rand::thread_rng();
            let degree = usize::from(threshold.get() - 1);
            KeyGenIntermediateValues::reshare(old_share, degree, &mut rng)
        } else {
            tracing::trace!("did not find share - we want to be CONSUMER");
            // Consumers still need an ephemeral key for the round-1 contribution.
            KeyGenIntermediateValues::consumer(&mut rand::thread_rng())
        };

        let intermediates = self
            .secret_manager
            .try_store_keygen_intermediates(oprf_key_id, pending_epoch, intermediates)
            .await?;
        Ok(intermediates.build_round1_contribution())
    }
}

/// Decrypts a key-generation ciphertext using the private key.
///
/// Returns the share of the node's polynomial or an error if decryption fails.
fn decrypt_key_gen_ciphertexts(
    ciphers: Vec<SecretGenCiphertext>,
    intermediates: KeyGenIntermediateValues,
    sharing_type: Contributions,
    pks: &[EphemeralEncryptionPublicKey],
) -> eyre::Result<DLogShareShamir> {
    let KeyGenIntermediateValues { sk, poly: _ } = intermediates;
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

/// Executes the key-generation Circom circuit.
///
/// ## Security Considerations
/// This method expects that the parameter `pks` contains exactly three [`EphemeralEncryptionPublicKey`]s that encapsulate valid `BabyJubJub` points on the correct subgroup.
///
/// If `pks` were constructed without [`EphemeralEncryptionPublicKey::new_unchecked`], the points are on curve and the correct subgroup.
///
/// This method consumes [`KeyGenIntermediateValues`] from round 1 so they cannot be reused when continuing with the protocol.
fn compute_keygen_proof(
    key_gen_material: &CircomGroth16Material,
    intermediates: KeyGenIntermediateValues,
    pks: &[EphemeralEncryptionPublicKey],
) -> eyre::Result<SecretGenCiphertexts> {
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

    let KeyGenIntermediateValues { sk, poly } = intermediates;
    let poly = poly.ok_or_else(|| eyre::eyre!("cannot compute keygen proof as consumer"))?;

    let coeffs = poly.coeffs().iter().map(Into::into).collect::<Vec<U256>>();

    // build the input for the graph
    let mut inputs = HashMap::new();
    inputs.insert(String::from("degree"), vec![U256::from(poly.degree())]);
    inputs.insert(String::from("my_sk"), vec![sk.inner().into()]);
    inputs.insert(String::from("pks"), flattened_pks);
    inputs.insert(String::from("poly"), coeffs);
    inputs.insert(
        String::from("nonces"),
        nonces.iter().map(Into::into).collect_vec(),
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

    if pk_computed != sk.get_public_key().inner() {
        eyre::bail!("computed public key does not match with my own!");
    }

    if comm_share_computed != poly.get_pk_share() {
        eyre::bail!("computed commitment to share does not match with my own!");
    }

    if comm_coeffs_computed != poly.get_coeff_commitment() {
        eyre::bail!("computed commitment to coeffs does not match with my own!");
    }

    Ok(SecretGenCiphertexts::new(proof.into(), rp_ciphertexts))
}
