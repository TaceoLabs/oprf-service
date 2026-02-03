use std::{fmt, sync::Arc, time::Duration};

use alloy::signers::local::PrivateKeySigner;
use async_trait::async_trait;
use axum_test::TestServer;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_test_utils::test_secret_manager::TestSecretManager;
use oprf_test_utils::{PEER_PRIVATE_KEYS, TestSetup};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    crypto::{OprfKeyMaterial, OprfPublicKey},
};
use taceo_oprf_key_gen::config::{Environment, OprfKeyGenConfig};

pub struct TestKeyGen {
    pub party_id: usize,
    pub secret_manager: Arc<TestSecretManager>,
    pub server: TestServer,
}

// need a new type to implement the trait
pub struct KeyGenTestSecretManager(pub Arc<TestSecretManager>);

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

        let config = OprfKeyGenConfig {
            environment: Environment::Dev,
            // not used
            bind_addr: "0.0.0.0:10000".parse().unwrap(),
            oprf_key_registry_contract: *oprf_key_registry,
            chain_ws_rpc_url: anvil.ws_endpoint().into(),
            wallet_private_key_secret_id: "wallet/privatekey".to_owned(),
            key_gen_zkey_path: setup.key_gen_path(),
            key_gen_witness_graph_path: setup.witness_path(),
            max_wait_time_shutdown: Duration::from_secs(10),
            start_block: None,
            max_wait_time_transaction_confirmation: Duration::from_secs(30),
            max_transaction_attempts: 3,
            max_gas_per_transaction: 10_000_000,
            confirmations_for_transaction: 1,
            db_connection_string: "not used".into(),
            db_schema: "test".to_owned(),
        };

        let (router, _key_gen_tasks) =
            taceo_oprf_key_gen::start(config, keygen_secret_manager, child_token).await?;
        let server = TestServer::builder()
            .http_transport()
            .build(router)
            .expect("can build test-server");
        Ok(TestKeyGen {
            secret_manager,
            party_id,
            server,
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

#[async_trait]
impl taceo_oprf_key_gen::secret_manager::SecretManager for KeyGenTestSecretManager {
    async fn load_or_insert_wallet_private_key(&self) -> eyre::Result<PrivateKeySigner> {
        Ok(self.0.wallet_private_key.clone())
    }

    async fn get_share_by_epoch(
        &self,
        oprf_key_id: OprfKeyId,
        generated_epoch: ShareEpoch,
    ) -> eyre::Result<Option<DLogShareShamir>> {
        let store = self.0.store.lock();
        if let Some(oprf_key_material) = store.get(&oprf_key_id)
            && oprf_key_material.is_epoch(generated_epoch)
        {
            Ok(Some(oprf_key_material.share()))
        } else {
            Ok(None)
        }
    }

    async fn remove_oprf_key_material(&self, rp_id: OprfKeyId) -> eyre::Result<()> {
        if self.0.store.lock().remove(&rp_id).is_none() {
            panic!("trying to remove oprf_key_id that does not exist");
        }
        Ok(())
    }

    async fn store_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        public_key: OprfPublicKey,
        epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> eyre::Result<()> {
        let mut store = self.0.store.lock();
        if epoch.is_initial_epoch() || !store.contains_key(&oprf_key_id) {
            assert!(
                store
                    .insert(oprf_key_id, OprfKeyMaterial::new(share, public_key, epoch))
                    .is_none(),
                "On initial epoch, secret-manager must be empty"
            )
        } else {
            store.insert(oprf_key_id, OprfKeyMaterial::new(share, public_key, epoch));
        }
        Ok(())
    }
}
