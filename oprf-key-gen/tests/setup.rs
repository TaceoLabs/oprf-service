use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use axum_test::TestServer;
use nodes_common::web3::RpcProviderConfig;
use nodes_common::{Environment, StartedServices};
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_test_utils::{
    DeploySetup, PEER_PRIVATE_KEYS, TestSetup, test_secret_manager::TestSecretManager,
};
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use taceo_oprf_key_gen::KeyGenTasks;
use taceo_oprf_key_gen::config::{OprfKeyGenServiceConfig, OprfKeyGenServiceConfigMandatoryValues};
use taceo_oprf_key_gen::secret_manager::{
    KeyGenIntermediateValues, SecretManager, SecretManagerError, SecretManagerService,
};
use tokio_util::sync::CancellationToken;

pub struct TestKeyGen {
    pub party_id: usize,
    pub secret_manager: Arc<TestSecretManager>,
    pub server: TestServer,
    pub key_gen_task: KeyGenTasks,
    pub started_services: StartedServices,
    pub cancellation_token: CancellationToken,
}

pub struct TestKeyGenSecretManager {
    base: Arc<TestSecretManager>,
    keygen_intermediates: Mutex<HashMap<(OprfKeyId, ShareEpoch), Vec<u8>>>,
    pending_shares: Mutex<HashMap<(OprfKeyId, ShareEpoch), DLogShareShamir>>,
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
            oprf_key_registry,
            cancellation_token,
            setup,
            ..
        } = test_setup;

        assert!(party_id < 5, "can only spawn 5 key-gens");
        let private_key = PEER_PRIVATE_KEYS[party_id];
        let child_token = cancellation_token.child_token();
        let secret_manager = Arc::new(TestSecretManager::new(private_key));
        let keygen_secret_manager: SecretManagerService =
            Arc::new(TestKeyGenSecretManager::new(Arc::clone(&secret_manager)));
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

impl TestKeyGenSecretManager {
    fn new(base: Arc<TestSecretManager>) -> Self {
        Self {
            base,
            keygen_intermediates: Mutex::new(HashMap::new()),
            pending_shares: Mutex::new(HashMap::new()),
        }
    }

    fn serialize_intermediates(
        intermediate: &KeyGenIntermediateValues,
    ) -> Result<Vec<u8>, SecretManagerError> {
        let mut bytes = Vec::with_capacity(intermediate.uncompressed_size());
        intermediate
            .serialize_uncompressed(&mut bytes)
            .map_err(|error| SecretManagerError::Internal(eyre::eyre!(error)))?;
        Ok(bytes)
    }

    fn deserialize_intermediates(
        bytes: &[u8],
    ) -> Result<KeyGenIntermediateValues, SecretManagerError> {
        KeyGenIntermediateValues::deserialize_uncompressed(bytes)
            .map_err(|error| SecretManagerError::Internal(eyre::eyre!(error)))
    }
}

#[async_trait]
impl SecretManager for TestKeyGenSecretManager {
    async fn store_wallet_address(&self, address: String) -> Result<(), SecretManagerError> {
        self.base
            .store_wallet_address(address)
            .await
            .map_err(Into::into)
    }

    async fn get_share_by_epoch(
        &self,
        oprf_key_id: OprfKeyId,
        generated_epoch: ShareEpoch,
    ) -> Result<Option<DLogShareShamir>, SecretManagerError> {
        self.base
            .get_share_by_epoch(oprf_key_id, generated_epoch)
            .await
            .map_err(Into::into)
    }

    async fn delete_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> Result<(), SecretManagerError> {
        self.base.remove_key_material(oprf_key_id);
        self.keygen_intermediates
            .lock()
            .expect("lock not poisoned")
            .retain(|(key_id, _), _| *key_id != oprf_key_id);
        self.pending_shares
            .lock()
            .expect("lock not poisoned")
            .retain(|(key_id, _), _| *key_id != oprf_key_id);
        Ok(())
    }

    async fn abort_keygen(&self, oprf_key_id: OprfKeyId) -> Result<(), SecretManagerError> {
        self.keygen_intermediates
            .lock()
            .expect("lock not poisoned")
            .retain(|(key_id, _), _| *key_id != oprf_key_id);
        self.pending_shares
            .lock()
            .expect("lock not poisoned")
            .retain(|(key_id, _), _| *key_id != oprf_key_id);
        Ok(())
    }

    async fn try_store_keygen_intermediates(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        intermediate: KeyGenIntermediateValues,
    ) -> Result<KeyGenIntermediateValues, SecretManagerError> {
        let mut intermediates = self.keygen_intermediates.lock().expect("lock not poisoned");
        let serialized = Self::serialize_intermediates(&intermediate)?;
        Self::deserialize_intermediates(
            intermediates
                .entry((oprf_key_id, pending_epoch))
                .or_insert(serialized),
        )
    }

    async fn fetch_keygen_intermediates(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
    ) -> Result<Option<KeyGenIntermediateValues>, SecretManagerError> {
        self.keygen_intermediates
            .lock()
            .expect("lock not poisoned")
            .get(&(oprf_key_id, pending_epoch))
            .map(|bytes| Self::deserialize_intermediates(bytes))
            .transpose()
    }

    async fn store_pending_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        pending_epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> Result<(), SecretManagerError> {
        let has_intermediates = self
            .keygen_intermediates
            .lock()
            .expect("lock not poisoned")
            .contains_key(&(oprf_key_id, pending_epoch));
        if !has_intermediates {
            return Err(SecretManagerError::MissingIntermediates(
                oprf_key_id,
                pending_epoch,
            ));
        }
        self.pending_shares
            .lock()
            .expect("lock not poisoned")
            .insert((oprf_key_id, pending_epoch), share);
        Ok(())
    }

    async fn confirm_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        public_key: OprfPublicKey,
    ) -> Result<(), SecretManagerError> {
        let share = self
            .pending_shares
            .lock()
            .expect("lock not poisoned")
            .remove(&(oprf_key_id, epoch))
            .ok_or(SecretManagerError::MissingIntermediates(oprf_key_id, epoch))?;

        if let Some(existing) = self.base.get_key_material(oprf_key_id)
            && existing.public_key_with_epoch().epoch >= epoch
        {
            return Err(SecretManagerError::RefusingToRollbackEpoch);
        }

        self.base.insert_key_material(
            oprf_key_id,
            oprf_types::crypto::OprfKeyMaterial::new(share, public_key, epoch),
        );
        self.keygen_intermediates
            .lock()
            .expect("lock not poisoned")
            .retain(|(key_id, _), _| *key_id != oprf_key_id);
        self.pending_shares
            .lock()
            .expect("lock not poisoned")
            .retain(|(key_id, _), _| *key_id != oprf_key_id);
        Ok(())
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
        assert!(keys.into_iter().all(|key| key == oprf_public_key));
        Ok(oprf_public_key)
    }
}
