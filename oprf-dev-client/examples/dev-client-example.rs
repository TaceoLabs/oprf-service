use alloy::{primitives::U160, providers::DynProvider};
use ark_ff::{PrimeField as _, UniformRand as _};
use clap::Parser;
use oprf_client::Connector;
use oprf_core::oprf::BlindingFactor;
use oprf_test_utils::health_checks;
use oprf_types::{
    OprfKeyId, ShareEpoch, api::OprfRequest, async_trait::async_trait, crypto::OprfPublicKey,
};
use rand::{CryptoRng, Rng, SeedableRng as _};
use serde::{Deserialize, Serialize};
use taceo_oprf_dev_client::{DevClient, DevClientConfig, StressTestItem};
use uuid::Uuid;

#[derive(Clone, Parser, Debug)]
struct ExampleDevClientConfig {
    #[clap(long, env = "OPRF_DEV_CLIENT_OPRF_KEY_ID")]
    pub oprf_key_id: Option<U160>,
    #[clap(flatten)]
    pub inner: DevClientConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ExampleOprfRequestAuth(OprfKeyId);

struct ExampleDevClient {
    oprf_key_id: Option<U160>,
}

#[derive(Clone)]
struct ExampleDevClientSetup {
    oprf_key_id: OprfKeyId,
    oprf_public_key: OprfPublicKey,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    nodes_observability::install_tracing(
        "taceo_oprf_dev_client=trace,dev_client_example=trace,warn",
    );
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let example_config = ExampleDevClientConfig::parse();
    tracing::info!("starting oprf-dev-client with config: {example_config:#?}");
    let example_dev_client = ExampleDevClient {
        oprf_key_id: example_config.oprf_key_id,
    };
    taceo_oprf_dev_client::run(example_config.inner, example_dev_client).await?;
    Ok(())
}

#[async_trait]
impl DevClient for ExampleDevClient {
    type Setup = ExampleDevClientSetup;
    type RequestAuth = ExampleOprfRequestAuth;

    async fn setup_oprf_test(
        &self,
        config: &DevClientConfig,
        provider: DynProvider,
    ) -> eyre::Result<Self::Setup> {
        let (oprf_key_id, oprf_public_key) = if let Some(oprf_key_id) = self.oprf_key_id {
            let oprf_key_id = OprfKeyId::new(oprf_key_id);
            let share_epoch = ShareEpoch::from(config.share_epoch);
            let oprf_public_key = health_checks::oprf_public_key_from_services(
                oprf_key_id,
                share_epoch,
                &config.nodes,
                config.max_wait_time,
            )
            .await?;
            (oprf_key_id, oprf_public_key)
        } else {
            let (oprf_key_id, oprf_public_key) = taceo_oprf_dev_client::init_key_gen(
                &config.nodes,
                config.oprf_key_registry_contract,
                provider,
                config.max_wait_time,
            )
            .await?;
            (oprf_key_id, oprf_public_key)
        };
        Ok(ExampleDevClientSetup {
            oprf_key_id,
            oprf_public_key,
        })
    }

    async fn run_oprf(
        &self,
        config: &DevClientConfig,
        setup: Self::Setup,
        connector: Connector,
    ) -> eyre::Result<ShareEpoch> {
        let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

        let query = ark_babyjubjub::Fq::rand(&mut rng);
        let blinding_factor = BlindingFactor::rand(&mut rng);
        let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF");
        let auth = ExampleOprfRequestAuth(setup.oprf_key_id);

        let verifiable_oprf_output = oprf_client::distributed_oprf(
            &config.nodes,
            &self.auth_module(),
            config.threshold,
            query,
            blinding_factor,
            domain_separator,
            auth,
            connector,
        )
        .await?;

        Ok(verifiable_oprf_output.epoch)
    }

    async fn prepare_stress_test_item<R: Rng + CryptoRng + Send>(
        &self,
        setup: &Self::Setup,
        rng: &mut R,
    ) -> eyre::Result<StressTestItem<Self::RequestAuth>> {
        let request_id = Uuid::new_v4();
        let action = ark_babyjubjub::Fq::rand(rng);
        let blinding_factor = BlindingFactor::rand(rng);
        let query = action;
        let blinded_query = oprf_core::oprf::client::blind_query(query, blinding_factor.clone());
        let init_request = OprfRequest {
            request_id,
            blinded_query: blinded_query.blinded_query(),
            auth: ExampleOprfRequestAuth(setup.oprf_key_id),
        };
        Ok(StressTestItem {
            request_id,
            blinded_query,
            init_request,
        })
    }

    fn get_oprf_key(&self, setup: &Self::Setup) -> OprfPublicKey {
        setup.oprf_public_key
    }

    fn get_oprf_key_id(&self, setup: &Self::Setup) -> OprfKeyId {
        setup.oprf_key_id
    }

    fn auth_module(&self) -> String {
        "example".to_owned()
    }
}
