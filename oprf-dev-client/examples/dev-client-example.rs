use std::{collections::HashMap, str::FromStr as _, sync::Arc, time::Duration};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U160},
    providers::{DynProvider, Provider as _, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use ark_ec::AffineRepr as _;
use ark_ff::{PrimeField as _, UniformRand as _};
use clap::Parser;
use eyre::Context as _;
use oprf_client::{Connector, VerifiableOprfOutput};
use oprf_core::oprf::{BlindedOprfRequest, BlindingFactor};
use oprf_test_utils::health_checks;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    api::{OprfRequest, ShareIdentifier},
    crypto::OprfPublicKey,
};
use rand::{CryptoRng, Rng, SeedableRng as _};
use rustls::{ClientConfig, RootCertStore};
use secrecy::{ExposeSecret as _, SecretString};
use taceo_oprf_dev_client::{Command, StressTestCommand};
use tracing::instrument;
use uuid::Uuid;

/// The configuration for the OPRF client.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct OprfDevClientConfig {
    /// The URLs to all OPRF nodes
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_NODES",
        value_delimiter = ',',
        default_value = "http://127.0.0.1:10000,http://127.0.0.1:10001,http://127.0.0.1:10002"
    )]
    pub nodes: Vec<String>,

    /// The threshold of services that need to respond
    #[clap(long, env = "OPRF_DEV_CLIENT_THRESHOLD", default_value = "2")]
    pub threshold: usize,

    /// The OPRF module of the OPRF service to use
    #[clap(long, env = "OPRF_DEV_CLIENT_MODULE", default_value = "example")]
    pub module: String,

    /// The Address of the OprfKeyRegistry contract.
    #[clap(long, env = "OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT")]
    pub oprf_key_registry_contract: Address,

    /// The RPC for chain communication
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_CHAIN_RPC_URL",
        default_value = "http://localhost:8545"
    )]
    pub chain_rpc_url: SecretString,

    /// The PRIVATE_KEY of the TACEO admin wallet - used to register the OPRF nodes
    ///
    /// Default is anvil wallet 0
    #[clap(
        long,
        env = "TACEO_ADMIN_PRIVATE_KEY",
        default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )]
    pub taceo_private_key: SecretString,

    /// rp id of already registered rp
    #[clap(long, env = "OPRF_DEV_CLIENT_OPRF_KEY_ID")]
    pub oprf_key_id: Option<U160>,

    /// The share epoch. Will be ignored if `oprf_key_id` is `None`.
    #[clap(long, env = "OPRF_DEV_CLIENT_SHARE_EPOCH", default_value = "0")]
    pub share_epoch: u32,

    /// max wait time for init key-gen/reshare to succeed.
    #[clap(long, env = "OPRF_DEV_CLIENT_WAIT_TIME", default_value="2min", value_parser=humantime::parse_duration)]
    pub max_wait_time: Duration,

    /// Command
    #[command(subcommand)]
    pub command: Command,
}

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

async fn run_oprf(
    nodes: &[String],
    module: &str,
    threshold: usize,
    oprf_key_id: OprfKeyId,
    share_epoch: ShareEpoch,
    connector: Connector,
) -> eyre::Result<()> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let action = ark_babyjubjub::Fq::rand(&mut rng);

    // the client example internally checks the DLog equality
    distributed_oprf(
        nodes,
        module,
        threshold,
        oprf_key_id,
        share_epoch,
        action,
        connector,
        &mut rng,
    )
    .await?;

    Ok(())
}

fn prepare_oprf_stress_test_oprf_request(
    oprf_key_id: OprfKeyId,
) -> eyre::Result<(Uuid, BlindedOprfRequest, OprfRequest<()>)> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let request_id = Uuid::new_v4();
    let action = ark_babyjubjub::Fq::rand(&mut rng);
    let blinding_factor = BlindingFactor::rand(&mut rng);
    let query = action;
    let blinded_request = oprf_core::oprf::client::blind_query(query, blinding_factor);
    let oprf_req = OprfRequest {
        request_id,
        blinded_query: blinded_request.blinded_query(),
        share_identifier: ShareIdentifier {
            oprf_key_id,
            share_epoch: ShareEpoch::default(),
        },
        auth: (),
    };

    Ok((request_id, blinded_request, oprf_req))
}

async fn stress_test(
    cmd: StressTestCommand,
    nodes: &[String],
    module: &str,
    threshold: usize,
    oprf_key_id: OprfKeyId,
    oprf_public_key: OprfPublicKey,
    connector: Connector,
) -> eyre::Result<()> {
    let mut blinded_requests = HashMap::with_capacity(cmd.runs);
    let mut init_requests = HashMap::with_capacity(cmd.runs);

    tracing::info!("preparing requests..");
    for _ in 0..cmd.runs {
        let (request_id, blinded_req, req) = prepare_oprf_stress_test_oprf_request(oprf_key_id)?;
        blinded_requests.insert(request_id, blinded_req);
        init_requests.insert(request_id, req);
    }

    tracing::info!("sending init requests..");
    let (sessions, finish_requests) = taceo_oprf_dev_client::send_init_requests(
        nodes,
        module,
        threshold,
        connector,
        cmd.sequential,
        init_requests,
    )
    .await?;

    tracing::info!("sending finish requests..");
    let responses = taceo_oprf_dev_client::send_finish_requests(
        sessions,
        cmd.sequential,
        finish_requests.clone(),
    )
    .await?;

    if !cmd.skip_checks {
        tracing::info!("checking OPRF + proofs");
        for (id, res) in responses {
            let blinded_req = blinded_requests.get(&id).expect("is there").to_owned();
            let finish_req = finish_requests.get(&id).expect("is there").to_owned();
            let _dlog_proof = oprf_client::verify_dlog_equality(
                id,
                oprf_public_key,
                &blinded_req,
                res,
                finish_req,
            )?;
        }
    }

    Ok(())
}

#[expect(clippy::too_many_arguments)]
async fn reshare_test(
    nodes: &[String],
    module: &str,
    threshold: usize,
    oprf_key_registry: Address,
    oprf_key_id: OprfKeyId,
    share_epoch: ShareEpoch,
    oprf_public_key: OprfPublicKey,
    connector: Connector,
    provider: DynProvider,
    max_wait_time: Duration,
) -> eyre::Result<()> {
    tracing::info!("running single OPRF");
    run_oprf(
        nodes,
        module,
        threshold,
        oprf_key_id,
        share_epoch,
        connector.clone(),
    )
    .await?;
    tracing::info!("OPRF successful");

    let (share_epoch_1, oprf_public_key_1) = taceo_oprf_dev_client::reshare(
        nodes,
        oprf_key_registry,
        provider.clone(),
        max_wait_time,
        oprf_key_id,
        share_epoch,
    )
    .await?;
    assert_eq!(oprf_public_key, oprf_public_key_1);

    tracing::info!("running OPRF with epoch 0 after 1st reshare");
    run_oprf(
        nodes,
        module,
        threshold,
        oprf_key_id,
        share_epoch,
        connector.clone(),
    )
    .await?;
    tracing::info!("OPRF successful");

    tracing::info!("running OPRF with epoch 1 after 1st reshare");
    run_oprf(
        nodes,
        module,
        threshold,
        oprf_key_id,
        share_epoch_1,
        connector.clone(),
    )
    .await?;
    tracing::info!("OPRF successful");

    let (share_epoch_2, oprf_public_key_2) = taceo_oprf_dev_client::reshare(
        nodes,
        oprf_key_registry,
        provider,
        max_wait_time,
        oprf_key_id,
        share_epoch_1,
    )
    .await?;
    assert_eq!(oprf_public_key, oprf_public_key_2);

    tracing::info!("running OPRF with epoch 1 after 2nd reshare");
    run_oprf(
        nodes,
        module,
        threshold,
        oprf_key_id,
        share_epoch_1,
        connector.clone(),
    )
    .await?;
    tracing::info!("OPRF successful");

    tracing::info!("running OPRF with epoch 2 after 2nd reshare");
    run_oprf(
        nodes,
        module,
        threshold,
        oprf_key_id,
        share_epoch_2,
        connector.clone(),
    )
    .await?;
    tracing::info!("OPRF successful");

    tracing::info!("running OPRF with epoch 0 after 2nd reshare - should fail");
    let _ = run_oprf(
        nodes,
        module,
        threshold,
        oprf_key_id,
        share_epoch,
        connector.clone(),
    )
    .await
    .expect_err("should fail");
    tracing::info!("OPRF failed as expected");

    Ok(())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    nodes_observability::install_tracing(
        "taceo_oprf_dev_client=trace,dev_client_example=trace,warn",
    );
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let config = OprfDevClientConfig::parse();
    tracing::info!("starting oprf-dev-client with config: {config:#?}");

    tracing::info!("health check for all nodes...");
    health_checks::services_health_check(&config.nodes, Duration::from_secs(5))
        .await
        .context("while doing health checks")?;
    tracing::info!("everyone online..");

    let private_key = PrivateKeySigner::from_str(config.taceo_private_key.expose_secret())?;
    let wallet = EthereumWallet::from(private_key.clone());

    tracing::info!("init rpc provider..");
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(config.chain_rpc_url.expose_secret())
        .await
        .context("while connecting to RPC")?
        .erased();

    let (oprf_key_id, share_epoch, oprf_public_key) = if let Some(oprf_key_id) = config.oprf_key_id
    {
        let oprf_key_id = OprfKeyId::new(oprf_key_id);
        let share_epoch = ShareEpoch::from(config.share_epoch);
        let oprf_public_key = health_checks::oprf_public_key_from_services(
            oprf_key_id,
            share_epoch,
            &config.nodes,
            config.max_wait_time,
        )
        .await?;
        (oprf_key_id, share_epoch, oprf_public_key)
    } else {
        let (oprf_key_id, oprf_public_key) = taceo_oprf_dev_client::init_key_gen(
            &config.nodes,
            config.oprf_key_registry_contract,
            provider.clone(),
            config.max_wait_time,
        )
        .await?;
        (oprf_key_id, ShareEpoch::default(), oprf_public_key)
    };

    // setup TLS config - even if we are http
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let rustls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = Connector::Rustls(Arc::new(rustls_config));

    match config.command.clone() {
        Command::Test => {
            tracing::info!("running oprf-test");
            run_oprf(
                &config.nodes,
                &config.module,
                config.threshold,
                oprf_key_id,
                share_epoch,
                connector,
            )
            .await?;
            tracing::info!("oprf-test successful");
        }
        Command::StressTest(cmd) => {
            tracing::info!("running stress-test");
            stress_test(
                cmd,
                &config.nodes,
                &config.module,
                config.threshold,
                oprf_key_id,
                oprf_public_key,
                connector,
            )
            .await?;
            tracing::info!("stress-test successful");
        }
        Command::ReshareTest => {
            tracing::info!("running reshare-test");
            reshare_test(
                &config.nodes,
                &config.module,
                config.threshold,
                config.oprf_key_registry_contract,
                oprf_key_id,
                share_epoch,
                oprf_public_key,
                connector,
                provider,
                config.max_wait_time,
            )
            .await?;
            tracing::info!("reshare-test successful");
        }
    }

    Ok(())
}
