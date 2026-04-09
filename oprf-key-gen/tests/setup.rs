use std::{fmt, sync::Arc};

use axum_test::TestServer;
use eyre::Context as _;
use nodes_common::web3::RpcProviderConfig;
use nodes_common::{Environment, StartedServices};
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_test_utils::test_secret_manager::TestSecretManager;
use oprf_test_utils::{DeploySetup, PEER_PRIVATE_KEYS, TestSetup};
use oprf_types::crypto::OprfPublicKey;
use oprf_types::{OprfKeyId, ShareEpoch};
use taceo_oprf_key_gen::KeyGenTasks;
use taceo_oprf_key_gen::config::{OprfKeyGenServiceConfig, OprfKeyGenServiceConfigMandatoryValues};
use taceo_oprf_key_gen::secret_manager::SecretManager;
use tokio_util::sync::CancellationToken;

pub struct TestKeyGen {
    pub party_id: usize,
    pub secret_manager: Arc<TestSecretManager>,
    pub server: TestServer,
    pub key_gen_task: KeyGenTasks,
    pub started_services: StartedServices,
    pub cancellation_token: CancellationToken,
}

pub struct KeyGenTestSecretManager(Arc<TestSecretManager>);

#[async_trait::async_trait]
impl SecretManager for KeyGenTestSecretManager {
    async fn store_wallet_address(&self, address: String) -> eyre::Result<()> {
        self.0.store_wallet_address(address).await
    }
    async fn ping(&self) -> eyre::Result<()> {
        // noop
        Ok(())
    }

    async fn get_share_by_epoch(
        &self,
        oprf_key_id: OprfKeyId,
        generated_epoch: ShareEpoch,
    ) -> eyre::Result<Option<DLogShareShamir>> {
        self.0
            .get_share_by_epoch(oprf_key_id, generated_epoch)
            .await
    }

    async fn remove_oprf_key_material(&self, rp_id: OprfKeyId) -> eyre::Result<()> {
        self.0
            .remove_oprf_key_material(rp_id)
            .await
            .context("while remove oprf key material")?;
        Ok(())
    }

    async fn store_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        public_key: OprfPublicKey,
        epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> eyre::Result<()> {
        self.0
            .store_dlog_share(oprf_key_id, public_key, epoch, share)
            .await
            .context("while store DlogShare")?;
        Ok(())
    }
}

impl fmt::Debug for TestKeyGen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestKeyGen")
            .field("party_id", &self.party_id)
            .finish()
    }
}

impl TestKeyGen {
    pub async fn start(party_id: usize, test_setup: &TestSetup) -> eyre::Result<Self> {
        let TestSetup {
            anvil,
            provider: _,
            oprf_key_registry,
            cancellation_token,
            setup,
        } = test_setup;

        assert!(party_id < 5, "can only spawn 5 key-gens");
        let private_key = PEER_PRIVATE_KEYS[party_id];
        let child_token = cancellation_token.child_token();
        let secret_manager = Arc::new(TestSecretManager::new(private_key));
        let keygen_secret_manager = Arc::new(KeyGenTestSecretManager(Arc::clone(&secret_manager)));
        let (expected_threshold, expected_num_peers) = match test_setup.setup {
            DeploySetup::TwoThree => (2, 3),
            DeploySetup::ThreeFive => (3, 5),
        };

        let mut config =
            OprfKeyGenServiceConfig::with_default_values(OprfKeyGenServiceConfigMandatoryValues {
                environment: Environment::Dev,
                oprf_key_registry_contract: *oprf_key_registry,
                wallet_private_key: private_key.into(),
                zkey_path: setup.key_gen_path(),
                witness_graph_path: setup.witness_path(),
                expected_threshold: expected_threshold.try_into().expect("Is non-zero"),
                expected_num_peers: expected_num_peers.try_into().expect("Is non-zero"),
                rpc_provider_config: RpcProviderConfig::with_default_values(
                    vec![anvil.endpoint_url()],
                    anvil.ws_endpoint_url(),
                ),
            });

        // anvil doesn't work with confirmations
        config.confirmations_for_transaction = 0;
        config.rpc_provider_config.chain_id = Some(31_337);

        let started_services = StartedServices::new();

        let (router, key_gen_task) = taceo_oprf_key_gen::start(
            config,
            keygen_secret_manager,
            started_services.clone(),
            child_token.clone(),
        )
        .await?;
        let server = TestServer::builder()
            .http_transport()
            .build(router)
            .expect("can build test-server");
        Ok(TestKeyGen {
            secret_manager,
            party_id,
            server,
            key_gen_task,
            started_services,
            cancellation_token: child_token,
        })
    }

    pub async fn start_three(test_setup: &TestSetup) -> eyre::Result<[Self; 3]> {
        let (keygen0, keygen1, keygen2) = tokio::join!(
            Self::start(0, test_setup),
            Self::start(1, test_setup),
            Self::start(2, test_setup)
        );
        Ok([keygen0?, keygen1?, keygen2?])
    }

    pub async fn start_five(test_setup: &TestSetup) -> eyre::Result<[Self; 5]> {
        let (keygen0, keygen1, keygen2, keygen3, keygen4) = tokio::join!(
            Self::start(0, test_setup),
            Self::start(1, test_setup),
            Self::start(2, test_setup),
            Self::start(3, test_setup),
            Self::start(4, test_setup)
        );
        Ok([keygen0?, keygen1?, keygen2?, keygen3?, keygen4?])
    }
}

pub mod keygen_asserts {
    use std::sync::Arc;

    use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
    use tokio::task::JoinSet;

    use crate::TestKeyGen;

    pub async fn all_have_key(
        instances: &[TestKeyGen],
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> eyre::Result<OprfPublicKey> {
        let mut keys = instances
            .iter()
            .map(|instance| {
                let secret_manager = Arc::clone(&instance.secret_manager);
                async move { secret_manager.is_key_id_stored(oprf_key_id, epoch).await }
            })
            .collect::<JoinSet<_>>()
            .join_all()
            .await
            .into_iter()
            .collect::<eyre::Result<Vec<_>>>()?;
        assert_eq!(keys.len(), instances.len());
        let oprf_public_key = keys.pop().expect("is there");
        assert!(keys.into_iter().all(|hay| hay == oprf_public_key));
        Ok(oprf_public_key)
    }
}
