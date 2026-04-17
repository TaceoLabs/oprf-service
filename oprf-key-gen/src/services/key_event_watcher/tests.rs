use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{
    secret_manager::{
        KeyGenIntermediateValues, SecretManager, SecretManagerError, SecretManagerService,
    },
    services::{
        key_event_watcher::{
            TransactionError, handle_abort, handle_delete, handle_not_enough_producers,
        },
        secret_gen::DLogSecretGenService,
        transaction_handler::{TransactionHandler, TransactionHandlerArgs},
    },
};
use alloy::{network::EthereumWallet, primitives::U160, signers::local::PrivateKeySigner};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use groth16_material::circom::{CircomGroth16Material, CircomGroth16MaterialBuilder};
use nodes_common::{Environment, web3::RpcProviderBuilder};
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_test_utils::{
    DeploySetup, OPRF_PEER_PRIVATE_KEY_0, PEER_ADDRESSES, TestSetup,
    test_secret_manager::TestSecretManager,
};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    chain::{OprfKeyRegistry, RevertError, Verifier::VerifierErrors},
    crypto::OprfPublicKey,
};

const INVALID_PROOF_KEY: usize = 43;
const WRONG_ROUND_LOAD_PEER_PUBLIC_KEYS: usize = 44;

struct TestKeyGenSecretManager {
    base: Arc<TestSecretManager>,
    keygen_intermediates: Mutex<HashMap<(OprfKeyId, ShareEpoch), Vec<u8>>>,
    pending_shares: Mutex<HashMap<(OprfKeyId, ShareEpoch), DLogShareShamir>>,
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
        if !self
            .keygen_intermediates
            .lock()
            .expect("lock not poisoned")
            .contains_key(&(oprf_key_id, pending_epoch))
        {
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
            && existing.epoch() >= epoch
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

fn key_gen_material(deploy_setup: DeploySetup) -> CircomGroth16Material {
    CircomGroth16MaterialBuilder::new()
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .build_from_paths(deploy_setup.key_gen_path(), deploy_setup.witness_path())
        .expect("Can build key_gen_material")
}

fn test_secret_manager() -> (Arc<TestSecretManager>, Arc<TestKeyGenSecretManager>) {
    let base = Arc::new(TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_0));
    let secret_manager = Arc::new(TestKeyGenSecretManager::new(Arc::clone(&base)));
    (base, secret_manager)
}

fn random_share() -> DLogShareShamir {
    DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>())
}

fn random_public_key() -> OprfPublicKey {
    OprfPublicKey::new(rand::random())
}

async fn test_config(setup: &TestSetup) -> (CircomGroth16Material, TransactionHandler) {
    let rpc_provider = RpcProviderBuilder::with_default_values(
        vec![setup.anvil.endpoint_url()],
        setup.anvil.ws_endpoint_url(),
    )
    .environment(Environment::Dev)
    .chain_id(31_337)
    .wallet(EthereumWallet::new(
        PrivateKeySigner::from_str(OPRF_PEER_PRIVATE_KEY_0).expect("works"),
    ))
    .build()
    .await
    .expect("can build RPC providers");

    let transaction_handler = TransactionHandler::new(TransactionHandlerArgs {
        max_wait_time_watch_transaction: Duration::from_secs(10),
        confirmations_for_transaction: 1,
        sleep_between_get_receipt: Duration::from_millis(500),
        max_tries_fetching_receipt: 5,
        max_gas_per_transaction: 10_000_000,
        rpc_provider,
        wallet_address: PEER_ADDRESSES[0],
    });

    (key_gen_material(setup.setup), transaction_handler)
}

#[tokio::test]
async fn test_send_invalid_proof() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let (key_gen_material, transaction_handler) = test_config(&setup).await;
    let (_, secret_manager) = test_secret_manager();
    let secret_manager: SecretManagerService = secret_manager;
    let secret_gen = DLogSecretGenService::init(key_gen_material, secret_manager);
    let key_id = U160::from(INVALID_PROOF_KEY);
    secret_gen
        .key_gen_round1(key_id.into(), ShareEpoch::default(), 2)
        .await?;
    let error = super::handle_round2(
        OprfKeyId::from(key_id),
        ShareEpoch::from(0u32),
        &OprfKeyRegistry::new(setup.oprf_key_registry, setup.provider.clone()),
        &secret_gen,
        &transaction_handler,
    )
    .await
    .expect_err("should fail");
    assert!(matches!(
        error,
        TransactionError::Revert(RevertError::Verifier(VerifierErrors::ProofInvalid(_)))
    ));
    Ok(())
}

#[tokio::test]
async fn test_delete() -> eyre::Result<()> {
    let (base, secret_manager) = test_secret_manager();
    let secret_manager_service: SecretManagerService = secret_manager.clone();
    let secret_gen = DLogSecretGenService::init(
        key_gen_material(DeploySetup::TwoThree),
        secret_manager_service,
    );

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let confirmed_epoch = ShareEpoch::default();
    let pending_epoch = confirmed_epoch.next();
    base.add_random_key_material_with_id_epoch(
        oprf_key_id,
        confirmed_epoch,
        &mut rand::thread_rng(),
    );
    secret_gen
        .reshare_round1(oprf_key_id, pending_epoch, 2)
        .await?;
    secret_manager
        .store_pending_dlog_share(oprf_key_id, pending_epoch, random_share())
        .await?;

    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, confirmed_epoch)
            .await?
            .is_some()
    );
    assert!(
        secret_manager
            .fetch_keygen_intermediates(oprf_key_id, pending_epoch)
            .await?
            .is_some()
    );

    handle_delete(oprf_key_id, &secret_gen)
        .await
        .expect("Works");

    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, confirmed_epoch)
            .await?
            .is_none()
    );
    assert!(
        secret_manager
            .fetch_keygen_intermediates(oprf_key_id, pending_epoch)
            .await?
            .is_none()
    );

    let error = secret_manager
        .confirm_dlog_share(oprf_key_id, pending_epoch, random_public_key())
        .await
        .expect_err("delete must clear pending shares");
    assert!(matches!(
        error,
        SecretManagerError::MissingIntermediates(id, epoch)
            if id == oprf_key_id && epoch == pending_epoch
    ));

    Ok(())
}

#[tokio::test]
async fn test_round2_in_wrong_round_during_load_public_keys() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let (key_gen_material, transaction_handler) = test_config(&setup).await;
    let (_, secret_manager) = test_secret_manager();
    let secret_manager_service: SecretManagerService = secret_manager.clone();
    let secret_gen = DLogSecretGenService::init(key_gen_material, secret_manager_service);
    let key_id = OprfKeyId::from(U160::from(WRONG_ROUND_LOAD_PEER_PUBLIC_KEYS));
    let epoch = ShareEpoch::default();

    secret_gen.key_gen_round1(key_id, epoch, 2).await?;
    assert!(
        secret_manager
            .fetch_keygen_intermediates(key_id, epoch)
            .await?
            .is_some()
    );

    super::handle_round2(
        key_id,
        epoch,
        &OprfKeyRegistry::new(setup.oprf_key_registry, setup.provider.clone()),
        &secret_gen,
        &transaction_handler,
    )
    .await
    .expect("Should still work");

    assert!(
        secret_manager
            .fetch_keygen_intermediates(key_id, epoch)
            .await?
            .is_some(),
        "consumer path must keep round-1 intermediates for round 3"
    );
    assert!(
        secret_manager
            .get_share_by_epoch(key_id, epoch)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn test_abort() -> eyre::Result<()> {
    let (base, secret_manager) = test_secret_manager();
    let secret_manager_service: SecretManagerService = secret_manager.clone();
    let secret_gen = DLogSecretGenService::init(
        key_gen_material(DeploySetup::TwoThree),
        secret_manager_service,
    );

    let oprf_key_id = OprfKeyId::new(U160::from(142));
    let confirmed_epoch = ShareEpoch::default();
    let pending_epoch = confirmed_epoch.next();
    base.add_random_key_material_with_id_epoch(
        oprf_key_id,
        confirmed_epoch,
        &mut rand::thread_rng(),
    );
    secret_gen
        .reshare_round1(oprf_key_id, pending_epoch, 2)
        .await?;
    secret_manager
        .store_pending_dlog_share(oprf_key_id, pending_epoch, random_share())
        .await?;

    assert!(
        secret_manager
            .fetch_keygen_intermediates(oprf_key_id, pending_epoch)
            .await?
            .is_some()
    );
    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, confirmed_epoch)
            .await?
            .is_some()
    );

    handle_abort(oprf_key_id, &secret_gen).await?;

    assert!(
        secret_manager
            .fetch_keygen_intermediates(oprf_key_id, pending_epoch)
            .await?
            .is_none()
    );
    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, confirmed_epoch)
            .await?
            .is_some()
    );

    let error = secret_manager
        .confirm_dlog_share(oprf_key_id, pending_epoch, random_public_key())
        .await
        .expect_err("abort must clear pending shares");
    assert!(matches!(
        error,
        SecretManagerError::MissingIntermediates(id, epoch)
            if id == oprf_key_id && epoch == pending_epoch
    ));

    Ok(())
}

#[tokio::test]
async fn test_not_enough_producers() -> eyre::Result<()> {
    let (base, secret_manager) = test_secret_manager();
    let secret_manager_service: SecretManagerService = secret_manager.clone();
    let secret_gen = DLogSecretGenService::init(
        key_gen_material(DeploySetup::TwoThree),
        secret_manager_service,
    );

    let oprf_key_id = OprfKeyId::new(U160::from(242));
    let confirmed_epoch = ShareEpoch::default();
    let pending_epoch = confirmed_epoch.next();
    base.add_random_key_material_with_id_epoch(
        oprf_key_id,
        confirmed_epoch,
        &mut rand::thread_rng(),
    );
    secret_gen
        .reshare_round1(oprf_key_id, pending_epoch, 2)
        .await?;
    secret_manager
        .store_pending_dlog_share(oprf_key_id, pending_epoch, random_share())
        .await?;

    assert!(
        secret_manager
            .fetch_keygen_intermediates(oprf_key_id, pending_epoch)
            .await?
            .is_some()
    );
    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, confirmed_epoch)
            .await?
            .is_some()
    );

    handle_not_enough_producers(oprf_key_id, &secret_gen).await?;

    assert!(
        secret_manager
            .fetch_keygen_intermediates(oprf_key_id, pending_epoch)
            .await?
            .is_none()
    );
    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, confirmed_epoch)
            .await?
            .is_some()
    );

    let error = secret_manager
        .confirm_dlog_share(oprf_key_id, pending_epoch, random_public_key())
        .await
        .expect_err("not-enough-producers must clear pending shares");
    assert!(matches!(
        error,
        SecretManagerError::MissingIntermediates(id, epoch)
            if id == oprf_key_id && epoch == pending_epoch
    ));

    Ok(())
}
