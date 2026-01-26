use ark_ec::AffineRepr as _;
use ark_ff::PrimeField as _;
use eyre::Context;
use oprf_client::{Connector, VerifiableOprfOutput};
use oprf_core::oprf::BlindingFactor;
use oprf_types::{OprfKeyId, ShareEpoch};
use rand::{CryptoRng, Rng};
use tracing::instrument;

#[instrument(level = "debug", skip_all)]
#[expect(clippy::too_many_arguments)]
pub async fn distributed_oprf<R: Rng + CryptoRng>(
    services: &[String],
    module: &str,
    threshold: usize,
    oprf_key_id: OprfKeyId,
    share_epoch: ShareEpoch,
    action: ark_babyjubjub::Fq,
    connector: Connector,
    rng: &mut R,
) -> eyre::Result<ark_babyjubjub::Fq> {
    let query = action;
    let blinding_factor = BlindingFactor::rand(rng);
    let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF");
    let auth = ();

    let VerifiableOprfOutput {
        output,
        dlog_proof,
        blinded_response,
        unblinded_response: _,
        blinded_request,
        oprf_public_key,
    } = oprf_client::distributed_oprf(
        services,
        module,
        threshold,
        oprf_key_id,
        share_epoch,
        query,
        blinding_factor,
        domain_separator,
        auth,
        connector,
    )
    .await?;
    dlog_proof
        .verify(
            oprf_public_key.inner(),
            blinded_request,
            blinded_response,
            ark_babyjubjub::EdwardsAffine::generator(),
        )
        .context("cannot verify dlog proof")?;

    Ok(output)
}
