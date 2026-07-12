use std::{num::NonZeroU16, path::PathBuf, str::FromStr, sync::Arc, time::Duration};

use alloy::{
    primitives::{Address, Bytes, U160, U256},
    providers::mock::Asserter,
    sol_types::{SolCall as _, SolError},
};
use ark_ff::UniformRand as _;
use groth16_material::circom::{CircomGroth16Material, CircomGroth16MaterialBuilder};
use nodes_common::{postgres::PostgresConfig, web3::HttpRpcProvider};
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    chain::{BabyJubJub, OprfKeyRegistry, RevertError, Verifier, Verifier::VerifierErrors},
    crypto::OprfPublicKey,
};
use rand::{CryptoRng, Rng};
use sqlx::PgPool;

use crate::{
    postgres::{PostgresDb, to_db_ark_serialize_uncompressed},
    secret_manager::{SecretManager, SecretManagerError},
    services::{
        key_event_watcher::{KeyRegistryEventError, handler::KeyRegistryEventHandler},
        secret_gen::DLogSecretGenService,
        transaction_handler::{TransactionHandler, TransactionHandlerArgs},
    },
};

use super::events::KeyRegistryEvent;

const CONTRACT_ADDRESS: Address = Address::repeat_byte(0x42);
const WALLET_ADDRESS: Address = Address::repeat_byte(0x24);

struct HandlerFixture {
    handler: KeyRegistryEventHandler,
    secret_manager: Arc<PostgresDb>,
    secret_gen: DLogSecretGenService,
    pool: PgPool,
    asserter: Asserter,
}

fn key_gen_material() -> CircomGroth16Material {
    let artifacts = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../artifacts");
    CircomGroth16MaterialBuilder::new()
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .build_from_paths(
            artifacts.join("OPRFKeyGen.13.arks.zkey"),
            artifacts.join("OPRFKeyGenGraph.13.bin"),
        )
        .expect("Can build key_gen_material")
}

async fn fixture() -> eyre::Result<HandlerFixture> {
    let connection_string = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let schema = nodes_common::test_utils::next_test_schema();
    let postgres_config = PostgresConfig::with_default_values(
        secrecy::SecretString::from(connection_string.to_owned()),
        schema,
    );
    let pool = nodes_common::postgres::pg_pool_with_schema(
        &postgres_config,
        nodes_common::postgres::CreateSchema::Yes,
    )
    .await?;
    let postgres_db = PostgresDb::init(&postgres_config).await?;
    let secret_manager = Arc::new(postgres_db);

    let sm_service: crate::secret_manager::SecretManagerService = secret_manager.clone();
    let secret_gen = DLogSecretGenService::init(key_gen_material(), sm_service);

    let asserter = Asserter::new();
    let rpc_provider = HttpRpcProvider::with_mock_asserter(asserter.clone());

    let transaction_handler = TransactionHandler::new(TransactionHandlerArgs {
        max_wait_time_watch_transaction: Duration::from_secs(10),
        confirmations_for_transaction: 1,
        sleep_between_get_receipt: Duration::from_millis(500),
        max_tries_fetching_receipt: 5,
        max_gas_per_transaction: 10_000_000,
        rpc_provider: rpc_provider.clone(),
        wallet_address: WALLET_ADDRESS,
        contract_address: CONTRACT_ADDRESS,
    });

    // Handler view-call contract shares the same asserter-backed provider.
    let contract = OprfKeyRegistry::new(CONTRACT_ADDRESS, rpc_provider.inner());
    let threshold = NonZeroU16::new(2).expect("2 is non-zero");
    let handler =
        KeyRegistryEventHandler::new(contract, secret_gen.clone(), threshold, transaction_handler);

    Ok(HandlerFixture {
        handler,
        secret_manager,
        secret_gen,
        pool,
        asserter,
    })
}

impl HandlerFixture {
    async fn add_random_key_material_with_id_epoch<R: Rng + CryptoRng>(
        &self,
        key_id: OprfKeyId,
        epoch: ShareEpoch,
        rng: &mut R,
    ) -> eyre::Result<()> {
        let share = DLogShareShamir::from(ark_babyjubjub::Fr::rand(rng));
        let public_key = OprfPublicKey::new(rng.r#gen());
        sqlx::query("INSERT INTO shares (id, share, epoch, public_key) VALUES ($1, $2, $3, $4)")
            .bind(key_id.to_le_bytes())
            .bind(to_db_ark_serialize_uncompressed(&share).as_slice())
            .bind(i64::from(epoch))
            .bind(to_db_ark_serialize_uncompressed(&public_key).as_slice())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn random_share() -> DLogShareShamir {
    DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>())
}

/// Queue a successful `loadPeerPublicKeysForProducers` `eth_call` response containing
/// three valid `BabyJubJub` points (copied from the former TestOprfKeyRegistry.sol fixture).
fn push_producer_public_keys(asserter: &Asserter) {
    let point = |x: &str, y: &str| BabyJubJub::Affine {
        x: U256::from_str(x).expect("valid decimal"),
        y: U256::from_str(y).expect("valid decimal"),
    };
    let keys = vec![
        point(
            "12821603125475748520011037468870418930812538699668722876863355416717947078760",
            "17067928114558614218231702459319414114121381971449529647004646393893219524072",
        ),
        point(
            "1688152706970503579483116674764161908712002477111907598715160302455660303671",
            "20413269805955861205216587925478893435677791255572561712193586073128762510903",
        ),
        point(
            "181606117961119882406004099351368673462695832980672617028988734026223981902",
            "16711318399047418081809052707903382106816693867662676821566699591386252462603",
        ),
    ];
    let encoded = OprfKeyRegistry::loadPeerPublicKeysForProducersCall::abi_encode_returns(&keys);
    asserter.push_success(&Bytes::from(encoded));
}

/// Queue an `eth_call` revert whose data is the ABI-encoded custom error, so the
/// existing decoders (`as_decoded_error` in handler.rs, `From<alloy::contract::Error>`
/// in `key_event_watcher.rs`) can identify it.
fn push_revert<E: SolError>(asserter: &Asserter, error: &E) {
    let data = alloy::hex::encode_prefixed(error.abi_encode());
    let payload = alloy::rpc::json_rpc::ErrorPayload {
        code: 3,
        message: "execution reverted".into(),
        data: Some(serde_json::value::to_raw_value(&data).expect("valid json")),
    };
    asserter.push_failure(payload);
}

#[tokio::test]
async fn test_round2_invalid_proof() -> eyre::Result<()> {
    let fx = fixture().await?;
    let key_id = OprfKeyId::from(U160::from(43u32));
    let epoch = ShareEpoch::default();

    fx.secret_gen
        .key_gen_round1(key_id, epoch, NonZeroU16::new(2).expect("non-zero"))
        .await?;

    // eth_call #1: fetch_producer_public_keys returns 3 EPKs -> producer path.
    push_producer_public_keys(&fx.asserter);
    // eth_call #2: TransactionHandler::simulate_transaction pre-flight reverts ProofInvalid.
    push_revert(&fx.asserter, &Verifier::ProofInvalid {});

    let error = fx
        .handler
        .handle(
            KeyRegistryEvent::Round2 { key_id, epoch },
            &tracing::Span::none(),
        )
        .await
        .expect_err("should fail with ProofInvalid");

    assert!(matches!(
        error,
        KeyRegistryEventError::Revert(RevertError::Verifier(VerifierErrors::ProofInvalid(_)))
    ));
    Ok(())
}

#[tokio::test]
async fn test_round2_consumer_path_when_contract_in_wrong_round() -> eyre::Result<()> {
    let fx = fixture().await?;
    let key_id = OprfKeyId::from(U160::from(44u32));
    let epoch = ShareEpoch::default();

    fx.secret_gen
        .key_gen_round1(key_id, epoch, NonZeroU16::new(2).expect("non-zero"))
        .await?;

    // eth_call #1: fetch_producer_public_keys reverts WrongRound -> consumer path -> Ok(()).
    push_revert(&fx.asserter, &OprfKeyRegistry::WrongRound(3));

    fx.handler
        .handle(
            KeyRegistryEvent::Round2 { key_id, epoch },
            &tracing::Span::none(),
        )
        .await
        .expect("consumer path should succeed");

    // Intermediates survive; no share was confirmed.
    fx.secret_manager
        .fetch_keygen_intermediates(key_id, epoch)
        .await?;
    assert!(
        fx.secret_manager
            .get_share_by_epoch(key_id, epoch)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn test_delete() -> eyre::Result<()> {
    let fx = fixture().await?;
    let key_id = OprfKeyId::new(U160::from(42u32));
    let confirmed_epoch = ShareEpoch::default();
    let pending_epoch = confirmed_epoch.next();

    fx.add_random_key_material_with_id_epoch(key_id, confirmed_epoch, &mut rand::thread_rng())
        .await?;
    fx.secret_gen
        .reshare_round1(key_id, pending_epoch, NonZeroU16::new(2).expect("non-zero"))
        .await?;
    fx.secret_manager
        .store_pending_dlog_share(key_id, pending_epoch, random_share())
        .await?;

    assert!(
        fx.secret_manager
            .get_share_by_epoch(key_id, confirmed_epoch)
            .await?
            .is_some()
    );
    fx.secret_manager
        .fetch_keygen_intermediates(key_id, pending_epoch)
        .await?;

    fx.handler
        .handle(KeyRegistryEvent::Delete { key_id }, &tracing::Span::none())
        .await
        .expect("delete should succeed");

    // Confirmed share removed.
    assert!(
        fx.secret_manager
            .get_share_by_epoch(key_id, confirmed_epoch)
            .await?
            .is_none()
    );

    // Intermediates cleared.
    let err = fx
        .secret_manager
        .fetch_keygen_intermediates(key_id, pending_epoch)
        .await
        .expect_err("intermediates must be gone");
    assert!(
        matches!(err, SecretManagerError::MissingIntermediates(id, ep) if id == key_id && ep == pending_epoch),
        "unexpected error: {err}"
    );

    Ok(())
}

#[tokio::test]
async fn test_abort() -> eyre::Result<()> {
    let fx = fixture().await?;
    let key_id = OprfKeyId::new(U160::from(142u32));
    let confirmed_epoch = ShareEpoch::default();
    let pending_epoch = confirmed_epoch.next();

    fx.add_random_key_material_with_id_epoch(key_id, confirmed_epoch, &mut rand::thread_rng())
        .await?;
    fx.secret_gen
        .reshare_round1(key_id, pending_epoch, NonZeroU16::new(2).expect("non-zero"))
        .await?;
    fx.secret_manager
        .store_pending_dlog_share(key_id, pending_epoch, random_share())
        .await?;

    fx.handler
        .handle(KeyRegistryEvent::Abort { key_id }, &tracing::Span::none())
        .await?;

    // In-progress state cleared.
    let err = fx
        .secret_manager
        .fetch_keygen_intermediates(key_id, pending_epoch)
        .await
        .expect_err("intermediates must be gone");
    assert!(
        matches!(err, SecretManagerError::MissingIntermediates(id, ep) if id == key_id && ep == pending_epoch),
        "unexpected error: {err}"
    );

    // Confirmed share preserved.
    assert!(
        fx.secret_manager
            .get_share_by_epoch(key_id, confirmed_epoch)
            .await?
            .is_some()
    );
    Ok(())
}
