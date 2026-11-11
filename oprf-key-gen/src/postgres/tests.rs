#![allow(clippy::too_many_lines, reason = "doesn't matter for tests")]
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::sync::Arc;

use crate::event_cursor_store::ChainCursorStorage;
use crate::postgres::{PostgresDb, PostgresDbError, StorageSettings, upgrade};
use crate::secret_manager::{
    KeyGenIntermediateValues, SecretManager as _, SecretManagerError, StorageReport,
};
use crate::services::secret_gen::DLogSecretGenService;
use alloy::{
    primitives::{Address, U160},
    signers::local::PrivateKeySigner,
    sol_types::SolValue as _,
};
use ark_serialize::CanonicalDeserialize;
use eyre::Context;
use groth16_material::circom::{CircomGroth16Material, CircomGroth16MaterialBuilder, Validate};
use nodes_common::postgres::{PostgresConfig, SanitizedSchema};
use nodes_common::test_utils::SharedPostgres;
use nodes_common::web3::event_stream::ChainCursor;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_store::{
    DekWrapper, EnvelopeError, InMemoryWrapper, StorageCrypto,
    aad::{AadContext, Kind, RowId},
    format::StorageFormat,
};
use oprf_types::crypto::PartyId;
use oprf_types::service::NodeInformation;
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use secrecy::SecretString;
use sqlx::Row;
use sqlx::{PgConnection, postgres::PgRow};
use uuid::Uuid;

type Fixture = (PostgresDb, Arc<SharedPostgres>, SanitizedSchema);

/// Settings that read and write `direct` only.
pub(crate) fn direct_settings() -> StorageSettings {
    StorageSettings {
        allowed: vec![StorageFormat::Direct],
        write: StorageFormat::Direct,
    }
}

/// The AAD context the tests prepare storage with.
pub(crate) fn aad_context() -> AadContext {
    AadContext {
        chain_id: 31337,
        registry: Address::repeat_byte(0xAA),
        party_id: PartyId(1),
        threshold: NonZeroU16::new(2).expect("2 is non-zero"),
    }
}

fn wrapper() -> InMemoryWrapper {
    InMemoryWrapper::new("arn:aws:kms:eu-central-1:000000000000:key/test", [1; 32])
}

/// Settings that read `direct` and `envelopeV1` and write `envelopeV1`.
fn envelope_settings() -> StorageSettings {
    StorageSettings {
        allowed: vec![StorageFormat::Direct, StorageFormat::EnvelopeV1],
        write: StorageFormat::EnvelopeV1,
    }
}

async fn init_db(
    pg: &SharedPostgres,
    schema: SanitizedSchema,
    storage: StorageSettings,
    wrapper: Option<Arc<dyn DekWrapper>>,
) -> eyre::Result<PostgresDb> {
    PostgresDb::init(
        &PostgresConfig::with_default_values(
            SecretString::from(pg.connection_string.clone()),
            schema,
        ),
        storage,
        wrapper,
    )
    .await
}

/// A database with envelope settings and the test wrapper; storage is not prepared yet.
async fn unprepared_envelope_db(
    pg: &SharedPostgres,
    schema: SanitizedSchema,
) -> eyre::Result<PostgresDb> {
    init_db(pg, schema, envelope_settings(), Some(Arc::new(wrapper()))).await
}

/// A database writing in `format`; with `envelopeV1` it also reads `direct`.
async fn postgres_db_with(format: StorageFormat) -> eyre::Result<Fixture> {
    if format == StorageFormat::EnvelopeV1 {
        return envelope_db(&[StorageFormat::Direct, StorageFormat::EnvelopeV1]).await;
    }
    let pg = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let schema = nodes_common::test_utils::next_test_schema();
    let db = init_db(&pg, schema.clone(), direct_settings(), None).await?;
    db.prepare_storage(aad_context()).await?;
    Ok((db, pg, schema))
}

/// A database writing `envelopeV1` under a freshly created data key and reading `allowed`.
async fn envelope_db(allowed: &[StorageFormat]) -> eyre::Result<Fixture> {
    let pg = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let schema = nodes_common::test_utils::next_test_schema();
    let storage = StorageSettings {
        allowed: allowed.to_vec(),
        write: StorageFormat::EnvelopeV1,
    };
    let db = init_db(&pg, schema.clone(), storage, None).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    let dek = oprf_store::data_keys::create(&mut conn, &wrapper()).await?;
    let dek_id = dek.id();
    db.set_crypto_for_tests(
        StorageCrypto::new(allowed, aad_context(), vec![dek])
            .with_write(StorageFormat::EnvelopeV1, Some(dek_id))?,
    );
    Ok((db, pg, schema))
}

async fn postgres_db() -> eyre::Result<(PostgresDb, Arc<SharedPostgres>)> {
    let (db, pg, _) = postgres_db_with(StorageFormat::Direct).await?;
    Ok((db, pg))
}

/// A prepared, direct-only database on `schema`.
pub(crate) async fn postgres_secret_manager_with_schema(
    connection_string: &str,
    schema: SanitizedSchema,
) -> eyre::Result<PostgresDb> {
    let db = PostgresDb::init(
        &PostgresConfig::with_default_values(
            SecretString::from(connection_string.to_owned()),
            schema,
        ),
        direct_settings(),
        None,
    )
    .await?;
    db.prepare_storage(aad_context()).await?;
    Ok(db)
}

/// Runs each listed `async fn name(format: StorageFormat)` once per write format.
macro_rules! for_each_write_format {
    ($($name:ident),* $(,)?) => {
        mod direct {
            $(
                #[tokio::test]
                async fn $name() -> eyre::Result<()> {
                    super::$name(super::StorageFormat::Direct).await
                }
            )*
        }
        mod envelope {
            $(
                #[tokio::test]
                async fn $name() -> eyre::Result<()> {
                    super::$name(super::StorageFormat::EnvelopeV1).await
                }
            )*
        }
    };
}

for_each_write_format!(
    fetch_keygen_intermediates_missing_returns_none,
    key_gen_round1_is_idempotent,
    store_pending_share_without_intermediates_fails,
    confirm_without_pending_share_fails,
    abort_keygen_is_idempotent_and_preserves_confirmed_share,
    store_dlog_share_and_fetch_previous,
    store_dlog_share_as_consumer,
    try_retrieve_random_empty_epochs,
    confirm_after_abort_keygen_fails,
    confirm_same_epoch_without_restaging_is_idempotent,
    confirm_same_epoch_after_restaging_is_idempotent,
    delete_oprf_key_material_is_idempotent_and_soft_deletes_share,
    confirm_deleted_share_returns_store_on_deleted_share,
    test_delete,
);

#[tokio::test]
async fn load_node_information_success() -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_db_with(StorageFormat::Direct).await?;

    let key = PrivateKeySigner::random();
    let address = key.address();
    let should_party_id = PartyId(42);
    let should_threshold = NonZeroU16::new(2).expect("2 is non-zero");
    let should_node_information =
        NodeInformation::new(should_party_id, address.to_string(), should_threshold);
    secret_manager
        .store_node_information(should_node_information.clone())
        .await?;

    // check that the address is stored in the DB
    let mut pg_connection =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    let is_node_information: NodeInformation = sqlx::query_as(
        "SELECT eth_address,party_id,threshold FROM node_information WHERE id = TRUE",
    )
    .fetch_one(&mut pg_connection)
    .await?;

    assert_eq!(is_node_information, should_node_information);
    Ok(())
}

fn key_gen_material() -> eyre::Result<CircomGroth16Material> {
    let graph =
        PathBuf::from(std::env!("CARGO_MANIFEST_DIR")).join("../artifacts/OPRFKeyGenGraph.13.bin");
    let graph = std::fs::read(graph)?;
    let key_gen_zkey =
        PathBuf::from(std::env!("CARGO_MANIFEST_DIR")).join("../artifacts/OPRFKeyGen.13.arks.zkey");
    let key_gen_zkey = std::fs::read(key_gen_zkey)?;
    CircomGroth16MaterialBuilder::new()
        .validate(Validate::No)
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .build_from_bytes(&key_gen_zkey, &graph)
        .map_err(Into::into)
}

async fn all_rows(conn: &mut PgConnection) -> eyre::Result<Vec<PgRow>> {
    sqlx::query("SELECT * FROM shares")
        .fetch_all(conn)
        .await
        .context("while fetching all rows")
}

async fn intermediate_count(oprf_key_id: OprfKeyId, conn: &mut PgConnection) -> eyre::Result<i64> {
    sqlx::query_scalar(
        "
            SELECT COUNT(*)
            FROM in_progress_keygens
            WHERE id = $1
        ",
    )
    .bind(oprf_key_id.to_le_bytes())
    .fetch_one(conn)
    .await
    .context("while counting intermediate rows")
}

async fn insert_intermediate_row(
    oprf_key_id: OprfKeyId,
    pending_epoch: ShareEpoch,
    pending_share: Option<Vec<u8>>,
    intermediates: Vec<u8>,
    conn: &mut PgConnection,
) -> eyre::Result<()> {
    sqlx::query(
        "
            INSERT INTO in_progress_keygens (id, pending_epoch, pending_share, intermediates)
            VALUES ($1, $2, $3, $4)
        ",
    )
    .bind(oprf_key_id.to_le_bytes())
    .bind(i64::from(pending_epoch.into_inner()))
    .bind(pending_share)
    .bind(intermediates)
    .execute(conn)
    .await?;
    Ok(())
}

/// Test helper: directly inserts a pending-share row into `in_progress_keygens`, sealed in the
/// write format of `db`, ready to be confirmed.
async fn setup_pending_share(
    db: &PostgresDb,
    pg_connection: &mut PgConnection,
    oprf_key_id: OprfKeyId,
    pending_epoch: ShareEpoch,
    share: &DLogShareShamir,
) -> eyre::Result<()> {
    let row = RowId {
        kind: Kind::PendingShare,
        oprf_key_id,
        epoch: pending_epoch,
        public_key: None,
    };
    let sealed = db
        .crypto()?
        .seal(&row, &oprf_store::codec::to_bytes(share))?;
    sqlx::query(
        "INSERT INTO in_progress_keygens
             (id, pending_epoch, pending_share, intermediates, storage_format, data_key_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (id, pending_epoch) DO UPDATE SET
             pending_share = EXCLUDED.pending_share,
             intermediates = EXCLUDED.intermediates,
             storage_format = EXCLUDED.storage_format,
             data_key_id = EXCLUDED.data_key_id",
    )
    .bind(oprf_key_id.to_le_bytes())
    .bind(i64::from(pending_epoch.into_inner()))
    .bind(sealed.bytes.as_slice())
    // `confirm_dlog_share` only reads `pending_share`; these tests do not deserialize `intermediates`.
    .bind(vec![0_u8])
    .bind(sealed.format.as_str())
    .bind(sealed.data_key_id)
    .execute(&mut *pg_connection)
    .await?;
    Ok(())
}

fn assert_row_matches(
    db: &PostgresDb,
    row: &PgRow,
    should_format: StorageFormat,
    should_oprf_key_id: OprfKeyId,
    should_share: Option<DLogShareShamir>,
    should_epoch: ShareEpoch,
    should_public_key: OprfPublicKey,
) {
    let is_id: Vec<u8> = row.get("id");
    let is_share: Option<Vec<u8>> = row.get("share");
    let is_epoch: i64 = row.get("epoch");
    let is_public_key: Vec<u8> = row.get("public_key");
    let is_deleted: bool = row.get("deleted");
    let storage_format: String = row.get("storage_format");
    let data_key_id: Option<Uuid> = row.get("data_key_id");

    assert_eq!(should_oprf_key_id, OprfKeyId::from_le_slice(&is_id));
    assert_eq!(
        storage_format,
        should_format.as_str(),
        "the row must be stored in the write format"
    );
    assert_eq!(
        data_key_id.is_some(),
        should_format == StorageFormat::EnvelopeV1,
        "a data key id is set exactly for envelopeV1"
    );

    assert_eq!(should_share.is_none(), is_deleted);
    let row_id = RowId {
        kind: Kind::Share,
        oprf_key_id: should_oprf_key_id,
        epoch: should_epoch,
        public_key: Some(&should_public_key),
    };
    let is_share = is_share.map(|is_share| {
        let plaintext = db
            .crypto()
            .expect("crypto is set")
            .open(&storage_format, data_key_id, &row_id, &is_share)
            .expect("Can open");
        ark_babyjubjub::Fr::deserialize_uncompressed(plaintext.as_slice()).expect("Can deserialize")
    });
    let should_share = should_share.map(ark_babyjubjub::Fr::from);
    assert_eq!(should_share, is_share);
    assert_eq!(i64::from(should_epoch.into_inner()), is_epoch);
    assert_eq!(
        should_public_key,
        OprfPublicKey::deserialize_uncompressed_unchecked(is_public_key.as_slice())
            .expect("Can deserialize"),
    );
}

async fn fetch_keygen_intermediates_missing_returns_none(
    format: StorageFormat,
) -> eyre::Result<()> {
    let (secret_manager, _pg, _) = postgres_db_with(format).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let epoch = ShareEpoch::new(12);

    let should_err = secret_manager
        .fetch_keygen_intermediates(oprf_key_id, epoch)
        .await
        .expect_err("Should be an error");
    assert!(
        matches!(
            should_err,
            SecretManagerError::MissingIntermediates(is_oprf_key, is_epoch) if is_oprf_key == oprf_key_id && is_epoch == epoch
        ),
        "Should be MissingIntermediates but is {should_err}"
    );
    Ok(())
}

async fn key_gen_round1_is_idempotent(format: StorageFormat) -> eyre::Result<()> {
    let (secret_manager, _pg, _) = postgres_db_with(format).await?;
    let secret_manager = Arc::new(secret_manager);
    let dlog_secret_gen = DLogSecretGenService::init(key_gen_material()?, secret_manager.clone());
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let epoch = ShareEpoch::default();

    let first_contribution = dlog_secret_gen
        .key_gen_round1(
            oprf_key_id,
            epoch,
            NonZeroU16::new(2).expect("2 is non-zero"),
        )
        .await?;
    let intermediates = secret_manager
        .fetch_keygen_intermediates(oprf_key_id, epoch)
        .await?;

    let serialized_intermediates = oprf_store::codec::to_bytes(&intermediates);

    let retried_contribution = dlog_secret_gen
        .key_gen_round1(
            oprf_key_id,
            epoch,
            NonZeroU16::new(2).expect("2 is non-zero"),
        )
        .await
        .expect("retrying round 1 should reuse stored intermediates");

    let stored_after_retry = secret_manager
        .fetch_keygen_intermediates(oprf_key_id, epoch)
        .await?;

    assert_eq!(
        serialized_intermediates,
        oprf_store::codec::to_bytes(&stored_after_retry)
    );
    assert_eq!(
        first_contribution.abi_encode(),
        retried_contribution.abi_encode()
    );
    Ok(())
}

async fn store_pending_share_without_intermediates_fails(
    format: StorageFormat,
) -> eyre::Result<()> {
    let (secret_manager, _pg, _) = postgres_db_with(format).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let epoch = ShareEpoch::new(42);
    let share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    let err = secret_manager
        .store_pending_dlog_share(oprf_key_id, epoch, share)
        .await
        .expect_err("missing intermediates should fail");
    assert!(matches!(
        err,
        SecretManagerError::MissingIntermediates(id, pending_epoch)
            if id == oprf_key_id && pending_epoch == epoch
    ));
    Ok(())
}

async fn confirm_without_pending_share_fails(format: StorageFormat) -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_db_with(format).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch = ShareEpoch::new(42);
    insert_intermediate_row(oprf_key_id, epoch, None, vec![0_u8], &mut conn).await?;

    let err = secret_manager
        .confirm_dlog_share(oprf_key_id, epoch, public_key)
        .await
        .expect_err("confirm without pending share should fail");
    assert!(
        matches!(
            err,
            SecretManagerError::MissingIntermediates(id, pending_epoch)
                if id == oprf_key_id && pending_epoch == epoch
        ),
        "Should be missing intermediates but is {err}"
    );
    assert_eq!(intermediate_count(oprf_key_id, &mut conn).await?, 1);
    Ok(())
}

async fn abort_keygen_is_idempotent_and_preserves_confirmed_share(
    format: StorageFormat,
) -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_db_with(format).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let epoch = ShareEpoch::new(42);
    let next_epoch = epoch.next();
    let public_key = OprfPublicKey::new(rand::random());
    let share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    setup_pending_share(&secret_manager, &mut conn, oprf_key_id, epoch, &share).await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch, public_key)
        .await?;
    insert_intermediate_row(oprf_key_id, next_epoch, None, vec![0_u8], &mut conn).await?;

    secret_manager.abort_keygen(oprf_key_id).await?;
    secret_manager.abort_keygen(oprf_key_id).await?;

    assert_eq!(intermediate_count(oprf_key_id, &mut conn).await?, 0);
    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, epoch)
            .await?
            .is_some()
    );
    Ok(())
}

async fn store_dlog_share_and_fetch_previous(format: StorageFormat) -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_db_with(format).await?;
    let mut pg_connection =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch0 = ShareEpoch::default();
    let epoch1 = epoch0.next();
    let epoch2 = epoch1.next();
    let should_epoch_0_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    let should_epoch_1_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    let should_epoch_2_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    // EPOCH 0
    // store at epoch 0
    setup_pending_share(
        &secret_manager,
        &mut pg_connection,
        oprf_key_id,
        epoch0,
        &should_epoch_0_share,
    )
    .await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch0, public_key)
        .await?;

    let epoch_0_dump = all_rows(&mut pg_connection).await?;
    assert_eq!(epoch_0_dump.len(), 1);
    assert_row_matches(
        &secret_manager,
        &epoch_0_dump[0],
        format,
        oprf_key_id,
        Some(should_epoch_0_share.clone()),
        epoch0,
        public_key,
    );

    // should return None when fetching next share from epoch 0
    let should_no_share = secret_manager
        .get_share_by_epoch(oprf_key_id, epoch0.next())
        .await?;
    assert!(should_no_share.is_none());

    // should return epoch zero
    let is_epoch_0_share = secret_manager
        .get_share_by_epoch(oprf_key_id, epoch0)
        .await?
        .expect("should be some");
    assert_eq!(
        ark_babyjubjub::Fr::from(is_epoch_0_share),
        ark_babyjubjub::Fr::from(should_epoch_0_share.clone())
    );

    // EPOCH 1
    // store at epoch 1
    setup_pending_share(
        &secret_manager,
        &mut pg_connection,
        oprf_key_id,
        epoch1,
        &should_epoch_1_share,
    )
    .await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch1, public_key)
        .await?;

    let epoch_1_dump = all_rows(&mut pg_connection).await?;
    assert_eq!(epoch_1_dump.len(), 1);
    assert_row_matches(
        &secret_manager,
        &epoch_1_dump[0],
        format,
        oprf_key_id,
        Some(should_epoch_1_share.clone()),
        epoch1,
        public_key,
    );
    // should return epoch one
    let is_epoch_1_share = secret_manager
        .get_share_by_epoch(oprf_key_id, epoch1)
        .await?
        .expect("should be some");
    assert_eq!(
        ark_babyjubjub::Fr::from(is_epoch_1_share),
        ark_babyjubjub::Fr::from(should_epoch_1_share.clone())
    );
    // now should return none when fetching epoch 0
    let should_no_share = secret_manager
        .get_share_by_epoch(oprf_key_id, epoch1.prev())
        .await?;
    assert!(should_no_share.is_none());
    // now should return none when fetching epoch 2
    let should_no_share = secret_manager
        .get_share_by_epoch(oprf_key_id, epoch1.next())
        .await?;
    assert!(should_no_share.is_none());
    // EPOCH 2
    // store at epoch 2 -> epoch 0 should be gone now
    setup_pending_share(
        &secret_manager,
        &mut pg_connection,
        oprf_key_id,
        epoch2,
        &should_epoch_2_share,
    )
    .await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch2, public_key)
        .await?;
    let is_epoch_2_share = secret_manager
        .get_share_by_epoch(oprf_key_id, epoch2)
        .await?
        .expect("should be some");
    assert_eq!(
        ark_babyjubjub::Fr::from(is_epoch_2_share),
        ark_babyjubjub::Fr::from(should_epoch_2_share.clone())
    );

    let epoch_2_dump = all_rows(&mut pg_connection).await?;
    assert_eq!(epoch_2_dump.len(), 1);
    assert_row_matches(
        &secret_manager,
        &epoch_2_dump[0],
        format,
        oprf_key_id,
        Some(should_epoch_2_share.clone()),
        epoch2,
        public_key,
    );
    Ok(())
}

async fn store_dlog_share_as_consumer(format: StorageFormat) -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_db_with(format).await?;
    let mut pg_connection =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch42 = ShareEpoch::new(42);
    let epoch128 = ShareEpoch::new(128);
    let should_epoch_42_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    let should_epoch_128_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    //store epoch 42 without inserting anything beforehand
    setup_pending_share(
        &secret_manager,
        &mut pg_connection,
        oprf_key_id,
        epoch42,
        &should_epoch_42_share,
    )
    .await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch42, public_key)
        .await?;

    let epoch_42_dump = all_rows(&mut pg_connection).await?;
    assert_eq!(epoch_42_dump.len(), 1);
    assert_row_matches(
        &secret_manager,
        &epoch_42_dump[0],
        format,
        oprf_key_id,
        Some(should_epoch_42_share.clone()),
        epoch42,
        public_key,
    );

    //store epoch 128 after epoch 42 - now prev should be None again
    setup_pending_share(
        &secret_manager,
        &mut pg_connection,
        oprf_key_id,
        epoch128,
        &should_epoch_128_share,
    )
    .await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch128, public_key)
        .await?;
    let epoch_128_dump = all_rows(&mut pg_connection).await?;
    assert_eq!(epoch_128_dump.len(), 1);
    assert_row_matches(
        &secret_manager,
        &epoch_128_dump[0],
        format,
        oprf_key_id,
        Some(should_epoch_128_share.clone()),
        epoch128,
        public_key,
    );

    Ok(())
}

async fn try_retrieve_random_empty_epochs(format: StorageFormat) -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_db_with(format).await?;
    let mut pg_connection =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch42 = ShareEpoch::new(42);
    let should_epoch_42_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    //store epoch 42 without inserting anything beforehand
    setup_pending_share(
        &secret_manager,
        &mut pg_connection,
        oprf_key_id,
        epoch42,
        &should_epoch_42_share,
    )
    .await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch42, public_key)
        .await?;

    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, ShareEpoch::default())
            .await?
            .is_none()
    );
    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, ShareEpoch::new(12))
            .await?
            .is_none()
    );
    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, epoch42.prev())
            .await?
            .is_none()
    );
    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, epoch42.next())
            .await?
            .is_none()
    );
    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, ShareEpoch::new(1289))
            .await?
            .is_none()
    );
    Ok(())
}

async fn confirm_after_abort_keygen_fails(format: StorageFormat) -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_db_with(format).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch = ShareEpoch::new(42);
    let share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    setup_pending_share(&secret_manager, &mut conn, oprf_key_id, epoch, &share).await?;
    secret_manager.abort_keygen(oprf_key_id).await?;

    let err = secret_manager
        .confirm_dlog_share(oprf_key_id, epoch, public_key)
        .await
        .expect_err("confirm after abort should fail");
    assert!(matches!(
        err,
        SecretManagerError::MissingIntermediates(id, pending_epoch)
            if id == oprf_key_id && pending_epoch == epoch
    ));
    Ok(())
}

async fn confirm_same_epoch_without_restaging_is_idempotent(
    format: StorageFormat,
) -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_db_with(format).await?;
    let mut pg_connection =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch42 = ShareEpoch::new(42);
    let should_epoch_42_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    //store epoch 42 without inserting anything beforehand
    setup_pending_share(
        &secret_manager,
        &mut pg_connection,
        oprf_key_id,
        epoch42,
        &should_epoch_42_share,
    )
    .await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch42, public_key)
        .await?;

    let epoch_42_dump = all_rows(&mut pg_connection).await?;
    assert_eq!(epoch_42_dump.len(), 1);
    assert_row_matches(
        &secret_manager,
        &epoch_42_dump[0],
        format,
        oprf_key_id,
        Some(should_epoch_42_share.clone()),
        epoch42,
        public_key,
    );

    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch42, public_key)
        .await
        .expect("repeating confirm for an already finalized epoch should be a no-op");
    let epoch_42_dump_new = all_rows(&mut pg_connection).await?;
    assert_eq!(epoch_42_dump_new.len(), 1);
    assert_row_matches(
        &secret_manager,
        &epoch_42_dump_new[0],
        format,
        oprf_key_id,
        Some(should_epoch_42_share.clone()),
        epoch42,
        public_key,
    );
    assert_eq!(
        intermediate_count(oprf_key_id, &mut pg_connection).await?,
        0
    );

    Ok(())
}

async fn confirm_same_epoch_after_restaging_is_idempotent(
    format: StorageFormat,
) -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_db_with(format).await?;
    let mut pg_connection =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch42 = ShareEpoch::new(42);
    let original_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    let retried_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    setup_pending_share(
        &secret_manager,
        &mut pg_connection,
        oprf_key_id,
        epoch42,
        &original_share,
    )
    .await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch42, public_key)
        .await?;

    setup_pending_share(
        &secret_manager,
        &mut pg_connection,
        oprf_key_id,
        epoch42,
        &retried_share,
    )
    .await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch42, public_key)
        .await
        .expect("retrying confirm with restaged data should keep the finalized share");

    let epoch_42_dump = all_rows(&mut pg_connection).await?;
    assert_eq!(epoch_42_dump.len(), 1);
    assert_row_matches(
        &secret_manager,
        &epoch_42_dump[0],
        format,
        oprf_key_id,
        Some(original_share.clone()),
        epoch42,
        public_key,
    );

    let stored_share = secret_manager
        .get_share_by_epoch(oprf_key_id, epoch42)
        .await?
        .expect("share should still be present");
    assert_eq!(
        ark_babyjubjub::Fr::from(stored_share),
        ark_babyjubjub::Fr::from(original_share)
    );
    assert_eq!(
        intermediate_count(oprf_key_id, &mut pg_connection).await?,
        0
    );
    Ok(())
}

async fn delete_oprf_key_material_is_idempotent_and_soft_deletes_share(
    format: StorageFormat,
) -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_db_with(format).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch = ShareEpoch::new(42);
    let next_epoch = epoch.next();
    let share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    setup_pending_share(&secret_manager, &mut conn, oprf_key_id, epoch, &share).await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch, public_key)
        .await?;
    insert_intermediate_row(oprf_key_id, next_epoch, None, vec![0_u8], &mut conn).await?;

    secret_manager.delete_oprf_key_material(oprf_key_id).await?;
    secret_manager.delete_oprf_key_material(oprf_key_id).await?;

    assert_eq!(intermediate_count(oprf_key_id, &mut conn).await?, 0);
    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, epoch)
            .await?
            .is_none()
    );

    let rows = all_rows(&mut conn).await?;
    assert_eq!(rows.len(), 1);
    assert_row_matches(
        &secret_manager,
        &rows[0],
        format,
        oprf_key_id,
        None,
        epoch,
        public_key,
    );
    Ok(())
}

async fn confirm_deleted_share_returns_store_on_deleted_share(
    format: StorageFormat,
) -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_db_with(format).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch = ShareEpoch::new(42);
    let next_epoch = epoch.next();
    let share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    setup_pending_share(&secret_manager, &mut conn, oprf_key_id, epoch, &share).await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch, public_key)
        .await?;
    secret_manager.delete_oprf_key_material(oprf_key_id).await?;

    let next_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    setup_pending_share(
        &secret_manager,
        &mut conn,
        oprf_key_id,
        next_epoch,
        &next_share,
    )
    .await?;

    let err = secret_manager
        .confirm_dlog_share(oprf_key_id, next_epoch, public_key)
        .await
        .expect_err("confirm on deleted share should fail");
    assert!(matches!(err, SecretManagerError::StoreOnDeletedShare));

    let rows = all_rows(&mut conn).await?;
    assert_eq!(rows.len(), 1);
    assert_row_matches(
        &secret_manager,
        &rows[0],
        format,
        oprf_key_id,
        None,
        epoch,
        public_key,
    );
    Ok(())
}

async fn test_delete(format: StorageFormat) -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_db_with(format).await?;
    let mut pg_connection =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch42 = ShareEpoch::new(42);
    let should_epoch_42_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    // should work but shouldn't have any effect
    secret_manager.delete_oprf_key_material(oprf_key_id).await?;

    setup_pending_share(
        &secret_manager,
        &mut pg_connection,
        oprf_key_id,
        epoch42,
        &should_epoch_42_share,
    )
    .await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch42, public_key)
        .await?;

    let epoch_42_dump = all_rows(&mut pg_connection).await?;
    assert_eq!(epoch_42_dump.len(), 1);
    assert_row_matches(
        &secret_manager,
        &epoch_42_dump[0],
        format,
        oprf_key_id,
        Some(should_epoch_42_share.clone()),
        epoch42,
        public_key,
    );

    // remove the key and check if DB is empty now
    secret_manager.delete_oprf_key_material(oprf_key_id).await?;
    let epoch_42_deleted = all_rows(&mut pg_connection).await?;
    assert_row_matches(
        &secret_manager,
        &epoch_42_deleted[0],
        format,
        oprf_key_id,
        None,
        epoch42,
        public_key,
    );

    assert!(
        secret_manager
            .get_share_by_epoch(oprf_key_id, epoch42)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn test_load_chain_cursor_on_empty_db() -> eyre::Result<()> {
    let (secret_manager, _pg) = postgres_db().await?;

    let should_genesis_cursor = secret_manager.load_chain_cursor().await?;
    assert!(
        should_genesis_cursor.is_genesis(),
        "Should be genesis cursor on empty DB"
    );
    Ok(())
}

#[tokio::test]
async fn test_insert_chain_cursor_then_load() -> eyre::Result<()> {
    let (secret_manager, _pg) = postgres_db().await?;

    let should_chain_cursor = ChainCursor::new(42, 0x42);
    secret_manager
        .store_chain_cursor(should_chain_cursor)
        .await?;
    let is_chain_cursor = secret_manager.load_chain_cursor().await?;
    assert_eq!(
        is_chain_cursor, should_chain_cursor,
        "Should load inserted chain cursor"
    );
    Ok(())
}

#[tokio::test]
async fn test_insert_chain_cursor_refusing_rollback() -> eyre::Result<()> {
    let (secret_manager, _pg) = postgres_db().await?;

    let should_chain_cursor = ChainCursor::new(42, 0x42);
    let chain_cursor_earlier_block = ChainCursor::new(41, 0x42);
    let chain_cursor_earlier_index = ChainCursor::new(42, 0x41);

    secret_manager
        .store_chain_cursor(should_chain_cursor)
        .await?;

    secret_manager
        .store_chain_cursor(chain_cursor_earlier_block)
        .await?;

    assert_eq!(
        should_chain_cursor,
        secret_manager.load_chain_cursor().await?,
        "Should have refused insertions of older cursor"
    );

    secret_manager
        .store_chain_cursor(chain_cursor_earlier_index)
        .await?;

    assert_eq!(
        should_chain_cursor,
        secret_manager.load_chain_cursor().await?,
        "Should have refused insertions of older cursor"
    );
    Ok(())
}

#[tokio::test]
async fn check_violation_on_other_constraint_is_not_store_on_deleted_share() -> eyre::Result<()> {
    let (_secret_manager, pg, schema) = postgres_db_with(StorageFormat::Direct).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    // violates `shares_storage_format_check`, not `deleted_share_null`
    let sqlx_err = sqlx::query(
        "INSERT INTO shares (id, share, epoch, public_key, storage_format)
         VALUES ($1, $2, 1, $3, 'bogus')",
    )
    .bind(&[1_u8; 20][..])
    .bind(&[2_u8; 3][..])
    .bind(&[3_u8; 3][..])
    .execute(&mut conn)
    .await
    .expect_err("unknown storage format must be rejected");
    assert!(
        sqlx_err
            .as_database_error()
            .is_some_and(sqlx::error::DatabaseError::is_check_violation),
        "expected a check violation, got {sqlx_err:?}"
    );

    let err = SecretManagerError::from(PostgresDbError::DbError(sqlx_err));
    assert!(
        matches!(err, SecretManagerError::Internal(_)),
        "unrelated check violation must map to Internal, got {err:?}"
    );
    Ok(())
}

#[test]
fn store_error_mapping_keeps_db_errors_retryable() {
    let err = PostgresDbError::from(oprf_store::StoreError::Db(sqlx::Error::PoolTimedOut));
    assert!(
        matches!(err, PostgresDbError::DbError(sqlx::Error::PoolTimedOut)),
        "StoreError::Db must map to DbError, got {err:?}"
    );
    assert!(
        super::is_retryable_error(&err),
        "a transient database error wrapped in StoreError must be retried"
    );

    let err = PostgresDbError::from(oprf_store::StoreError::Corrupt("bad".to_owned()));
    assert!(
        matches!(
            err,
            PostgresDbError::Store(oprf_store::StoreError::Corrupt(_))
        ),
        "other StoreError variants must map to Store, got {err:?}"
    );
    assert!(
        !super::is_retryable_error(&err),
        "corrupt data is not retried"
    );

    let err = PostgresDbError::from(oprf_store::StoreError::UnsupportedStorageFormat(
        "envelopeV1".to_owned(),
    ));
    assert!(
        !super::is_retryable_error(&err),
        "unsupported storage format is not retried"
    );
    assert!(
        matches!(
            SecretManagerError::from(err),
            SecretManagerError::Internal(_)
        ),
        "unsupported storage format must be an internal error"
    );
}

/// Intermediates of a consumer: an ephemeral secret key and no polynomial.
fn consumer_intermediates() -> KeyGenIntermediateValues {
    let mut bytes = oprf_store::codec::to_bytes(&rand::random::<ark_babyjubjub::Fr>()).to_vec();
    // `None` for the polynomial
    bytes.push(0);
    oprf_store::codec::from_bytes(&bytes).expect("valid intermediates")
}

fn random_share() -> DLogShareShamir {
    DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>())
}

/// Stages and confirms a random share through `db`.
async fn confirm_random_share(
    db: &PostgresDb,
    conn: &mut PgConnection,
    oprf_key_id: OprfKeyId,
    epoch: ShareEpoch,
    public_key: OprfPublicKey,
) -> eyre::Result<()> {
    setup_pending_share(db, conn, oprf_key_id, epoch, &random_share()).await?;
    db.confirm_dlog_share(oprf_key_id, epoch, public_key)
        .await?;
    Ok(())
}

async fn assert_share_decrypt_fails(db: &PostgresDb, oprf_key_id: OprfKeyId, epoch: ShareEpoch) {
    let err = db
        .get_share_by_epoch(oprf_key_id, epoch)
        .await
        .map(drop)
        .expect_err("a tampered share must not be readable");
    assert!(
        matches!(
            err,
            SecretManagerError::StorageFormat(EnvelopeError::Decrypt)
        ),
        "expected StorageFormat(Decrypt), got {err:?}"
    );
}

#[tokio::test]
async fn envelope_rows_are_not_plaintext() -> eyre::Result<()> {
    let (db, pg, schema) = postgres_db_with(StorageFormat::EnvelopeV1).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let epoch = ShareEpoch::new(1);
    let intermediates = consumer_intermediates();
    let intermediates_plain = oprf_store::codec::to_bytes(&intermediates).to_vec();
    let share = random_share();
    let share_plain = oprf_store::codec::to_bytes(&share).to_vec();

    db.try_store_keygen_intermediates(oprf_key_id, epoch, intermediates)
        .await?;
    db.store_pending_dlog_share(oprf_key_id, epoch, share)
        .await?;
    let (stored_intermediates, pending_share, format, data_key_id): (
        Vec<u8>,
        Option<Vec<u8>>,
        String,
        Option<Uuid>,
    ) = sqlx::query_as(
        "SELECT intermediates, pending_share, storage_format, data_key_id
         FROM in_progress_keygens WHERE id = $1",
    )
    .bind(oprf_key_id.to_le_bytes())
    .fetch_one(&mut conn)
    .await?;
    assert_eq!(format, "envelopeV1", "in-progress row format");
    assert!(data_key_id.is_some(), "in-progress row names its data key");

    db.confirm_dlog_share(oprf_key_id, epoch, OprfPublicKey::new(rand::random()))
        .await?;
    let (stored_share, format, data_key_id): (Option<Vec<u8>>, String, Option<Uuid>) =
        sqlx::query_as("SELECT share, storage_format, data_key_id FROM shares WHERE id = $1")
            .bind(oprf_key_id.to_le_bytes())
            .fetch_one(&mut conn)
            .await?;
    assert_eq!(format, "envelopeV1", "share row format");
    assert!(data_key_id.is_some(), "share row names its data key");

    for (column, stored, plain) in [
        (
            "intermediates",
            Some(stored_intermediates),
            &intermediates_plain,
        ),
        ("pending_share", pending_share, &share_plain),
        ("share", stored_share, &share_plain),
    ] {
        let stored = stored.expect("column is set");
        assert_ne!(&stored, plain, "{column} must not be plaintext");
        assert_eq!(
            stored.len(),
            plain.len() + 28,
            "{column} must be nonce || ciphertext || tag"
        );
    }
    Ok(())
}

#[tokio::test]
async fn confirm_rebinds_share_to_public_key() -> eyre::Result<()> {
    let (db, pg, schema) = postgres_db_with(StorageFormat::EnvelopeV1).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let epoch = ShareEpoch::new(42);
    confirm_random_share(
        &db,
        &mut conn,
        oprf_key_id,
        epoch,
        OprfPublicKey::new(rand::random()),
    )
    .await?;

    sqlx::query("UPDATE shares SET public_key = $2 WHERE id = $1")
        .bind(oprf_key_id.to_le_bytes())
        .bind(oprf_store::codec::to_bytes(&OprfPublicKey::new(rand::random())).as_slice())
        .execute(&mut conn)
        .await?;
    assert_share_decrypt_fails(&db, oprf_key_id, epoch).await;
    Ok(())
}

#[tokio::test]
async fn pending_share_cannot_be_used_as_share() -> eyre::Result<()> {
    let (db, pg, schema) = postgres_db_with(StorageFormat::EnvelopeV1).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let epoch = ShareEpoch::new(42);
    confirm_random_share(
        &db,
        &mut conn,
        oprf_key_id,
        epoch,
        OprfPublicKey::new(rand::random()),
    )
    .await?;
    setup_pending_share(&db, &mut conn, oprf_key_id, epoch, &random_share()).await?;

    sqlx::query(
        "UPDATE shares SET share = (
             SELECT pending_share FROM in_progress_keygens WHERE id = $1 AND pending_epoch = $2
         ) WHERE id = $1",
    )
    .bind(oprf_key_id.to_le_bytes())
    .bind(i64::from(epoch.into_inner()))
    .execute(&mut conn)
    .await?;
    assert_share_decrypt_fails(&db, oprf_key_id, epoch).await;
    Ok(())
}

#[tokio::test]
async fn epoch_tamper_fails() -> eyre::Result<()> {
    let (db, pg, schema) = postgres_db_with(StorageFormat::EnvelopeV1).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let epoch = ShareEpoch::new(42);
    confirm_random_share(
        &db,
        &mut conn,
        oprf_key_id,
        epoch,
        OprfPublicKey::new(rand::random()),
    )
    .await?;

    sqlx::query("UPDATE shares SET epoch = $2 WHERE id = $1")
        .bind(oprf_key_id.to_le_bytes())
        .bind(i64::from(epoch.next().into_inner()))
        .execute(&mut conn)
        .await?;
    assert_share_decrypt_fails(&db, oprf_key_id, epoch.next()).await;
    Ok(())
}

#[tokio::test]
async fn swap_between_keys_fails() -> eyre::Result<()> {
    let (db, pg, schema) = postgres_db_with(StorageFormat::EnvelopeV1).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    let key_a = OprfKeyId::new(U160::from(42));
    let key_b = OprfKeyId::new(U160::from(43));
    let epoch = ShareEpoch::new(42);
    // Same epoch and public key: only the key id tells the rows apart.
    let public_key = OprfPublicKey::new(rand::random());
    confirm_random_share(&db, &mut conn, key_a, epoch, public_key).await?;
    confirm_random_share(&db, &mut conn, key_b, epoch, public_key).await?;

    sqlx::query(
        "UPDATE shares SET share = CASE
             WHEN id = $1 THEN (SELECT share FROM shares WHERE id = $2)
             ELSE (SELECT share FROM shares WHERE id = $1)
         END
         WHERE id IN ($1, $2)",
    )
    .bind(key_a.to_le_bytes())
    .bind(key_b.to_le_bytes())
    .execute(&mut conn)
    .await?;
    assert_share_decrypt_fails(&db, key_a, epoch).await;
    assert_share_decrypt_fails(&db, key_b, epoch).await;
    Ok(())
}

#[tokio::test]
async fn direct_row_rejected_when_direct_not_allowed() -> eyre::Result<()> {
    let (db, pg, schema) = envelope_db(&[StorageFormat::EnvelopeV1]).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let epoch = ShareEpoch::new(42);
    oprf_store::test_utils::insert_share(
        &mut conn,
        oprf_key_id,
        epoch,
        &random_share(),
        &OprfPublicKey::new(rand::random()),
    )
    .await?;

    let err = db
        .get_share_by_epoch(oprf_key_id, epoch)
        .await
        .map(drop)
        .expect_err("direct is not allowed");
    assert!(
        matches!(
            err,
            SecretManagerError::StorageFormat(EnvelopeError::FormatNotAllowed(
                StorageFormat::Direct
            ))
        ),
        "expected StorageFormat(FormatNotAllowed(Direct)), got {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn intermediates_idempotent_across_formats() -> eyre::Result<()> {
    let (db, pg, schema) = postgres_db_with(StorageFormat::EnvelopeV1).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let epoch = ShareEpoch::new(42);
    let stored_plain = oprf_store::codec::to_bytes(&consumer_intermediates()).to_vec();
    // a `direct` row
    insert_intermediate_row(oprf_key_id, epoch, None, stored_plain.clone(), &mut conn).await?;

    let returned = db
        .try_store_keygen_intermediates(oprf_key_id, epoch, consumer_intermediates())
        .await?;
    assert_eq!(
        oprf_store::codec::to_bytes(&returned).to_vec(),
        stored_plain,
        "the stored direct intermediates must be returned"
    );
    Ok(())
}

#[tokio::test]
async fn pending_share_follows_row_data_key() -> eyre::Result<()> {
    let (db1, pg, schema) = postgres_db_with(StorageFormat::EnvelopeV1).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let epoch = ShareEpoch::new(42);
    let row_data_key = || {
        sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT data_key_id FROM in_progress_keygens WHERE id = $1",
        )
        .bind(oprf_key_id.to_le_bytes())
    };

    // intermediates under DEK 1
    db1.try_store_keygen_intermediates(oprf_key_id, epoch, consumer_intermediates())
        .await?;
    let first_key = row_data_key().fetch_one(&mut conn).await?;

    // a fresh instance whose current data key is DEK 2
    let current_key = oprf_store::data_keys::create(&mut conn, &wrapper())
        .await?
        .id();
    let both = [StorageFormat::Direct, StorageFormat::EnvelopeV1];
    let db2 = init_db(
        &pg,
        schema.clone(),
        StorageSettings {
            allowed: both.to_vec(),
            write: StorageFormat::EnvelopeV1,
        },
        None,
    )
    .await?;
    let all_keys = oprf_store::data_keys::load_all(&mut conn, &wrapper()).await?;
    db2.set_crypto_for_tests(
        StorageCrypto::new(&both, aad_context(), all_keys)
            .with_write(StorageFormat::EnvelopeV1, Some(current_key))?,
    );

    let share = random_share();
    db2.store_pending_dlog_share(oprf_key_id, epoch, share.clone())
        .await?;
    assert_eq!(
        row_data_key().fetch_one(&mut conn).await?,
        first_key,
        "the pending share must keep the data key of its row"
    );

    db2.confirm_dlog_share(oprf_key_id, epoch, OprfPublicKey::new(rand::random()))
        .await?;
    let share_data_key: Option<Uuid> =
        sqlx::query_scalar("SELECT data_key_id FROM shares WHERE id = $1")
            .bind(oprf_key_id.to_le_bytes())
            .fetch_one(&mut conn)
            .await?;
    assert_eq!(
        share_data_key,
        Some(current_key),
        "the share must be sealed under the current data key"
    );
    let read = db2
        .get_share_by_epoch(oprf_key_id, epoch)
        .await?
        .expect("share is stored");
    assert_eq!(
        ark_babyjubjub::Fr::from(read),
        ark_babyjubjub::Fr::from(share),
        "share must read back"
    );
    Ok(())
}

/// The values seeded by [`seed_direct_rows`].
struct Seeded {
    /// Live shares: key id, epoch, share.
    live: Vec<(OprfKeyId, ShareEpoch, DLogShareShamir)>,
    /// The soft-deleted share.
    deleted: OprfKeyId,
    /// In-progress rows: key id, pending epoch, intermediates bytes, pending share.
    in_progress: Vec<(OprfKeyId, ShareEpoch, Vec<u8>, Option<DLogShareShamir>)>,
}

/// Seeds through a direct-only `db`: two live shares, one soft-deleted share, one in-progress
/// row with a pending share and one without.
async fn seed_direct_rows(db: &PostgresDb, conn: &mut PgConnection) -> eyre::Result<Seeded> {
    let mut live = Vec::new();
    for (key, epoch) in [(1_u64, 1_u32), (2, 3)] {
        let oprf_key_id = OprfKeyId::new(U160::from(key));
        let epoch = ShareEpoch::new(epoch);
        let share = random_share();
        setup_pending_share(db, conn, oprf_key_id, epoch, &share).await?;
        db.confirm_dlog_share(oprf_key_id, epoch, OprfPublicKey::new(rand::random()))
            .await?;
        live.push((oprf_key_id, epoch, share));
    }

    let deleted = OprfKeyId::new(U160::from(3));
    confirm_random_share(
        db,
        conn,
        deleted,
        ShareEpoch::new(1),
        OprfPublicKey::new(rand::random()),
    )
    .await?;
    db.delete_oprf_key_material(deleted).await?;

    let mut in_progress = Vec::new();
    for (key, with_pending) in [(4_u64, true), (5, false)] {
        let oprf_key_id = OprfKeyId::new(U160::from(key));
        let epoch = ShareEpoch::new(2);
        let intermediates = consumer_intermediates();
        let intermediates_bytes = oprf_store::codec::to_bytes(&intermediates).to_vec();
        db.try_store_keygen_intermediates(oprf_key_id, epoch, intermediates)
            .await?;
        let pending = if with_pending {
            let share = random_share();
            db.store_pending_dlog_share(oprf_key_id, epoch, share.clone())
                .await?;
            Some(share)
        } else {
            None
        };
        in_progress.push((oprf_key_id, epoch, intermediates_bytes, pending));
    }

    let direct: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM shares WHERE storage_format = 'direct')
              + (SELECT COUNT(*) FROM in_progress_keygens WHERE storage_format = 'direct')",
    )
    .fetch_one(&mut *conn)
    .await?;
    assert_eq!(direct, 5, "all seeded rows are direct");
    Ok(Seeded {
        live,
        deleted,
        in_progress,
    })
}

/// A fresh schema seeded with direct rows and a connection to it.
async fn seeded_direct_schema()
-> eyre::Result<(Arc<SharedPostgres>, SanitizedSchema, PgConnection, Seeded)> {
    let (db, pg, schema) = postgres_db_with(StorageFormat::Direct).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    let seeded = seed_direct_rows(&db, &mut conn).await?;
    Ok((pg, schema, conn, seeded))
}

/// Every stored secret column and its format, in a stable order.
type Snapshot = Vec<(
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    String,
    Option<Uuid>,
)>;

async fn snapshot(conn: &mut PgConnection) -> eyre::Result<Snapshot> {
    Ok(sqlx::query_as(
        "SELECT id, epoch, share, NULL::BYTEA, storage_format, data_key_id FROM shares
         UNION ALL
         SELECT id, pending_epoch, intermediates, pending_share, storage_format, data_key_id
         FROM in_progress_keygens
         ORDER BY 1, 2",
    )
    .fetch_all(conn)
    .await?)
}

async fn data_key_count(conn: &mut PgConnection) -> eyre::Result<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM data_keys")
        .fetch_one(conn)
        .await?)
}

/// Asserts that every seeded value reads back unchanged through `db`.
async fn assert_seeded_values(db: &PostgresDb, seeded: &Seeded) -> eyre::Result<()> {
    for (oprf_key_id, epoch, share) in &seeded.live {
        let read = db
            .get_share_by_epoch(*oprf_key_id, *epoch)
            .await?
            .expect("live share is stored");
        assert_eq!(
            ark_babyjubjub::Fr::from(read),
            ark_babyjubjub::Fr::from(share.clone()),
            "share of {oprf_key_id} must read back"
        );
    }
    for (oprf_key_id, epoch, intermediates, pending) in &seeded.in_progress {
        let read = db.fetch_keygen_intermediates(*oprf_key_id, *epoch).await?;
        assert_eq!(
            &oprf_store::codec::to_bytes(&read).to_vec(),
            intermediates,
            "intermediates of {oprf_key_id} must read back"
        );
        let read_pending =
            PostgresDb::fetch_pending_share_inner(db.crypto()?, *oprf_key_id, *epoch, &db.pool)
                .await?;
        assert_eq!(
            read_pending.map(ark_babyjubjub::Fr::from),
            pending.clone().map(ark_babyjubjub::Fr::from),
            "pending share of {oprf_key_id} must read back"
        );
    }
    Ok(())
}

#[tokio::test]
async fn upgrade_converts_all_direct_rows() -> eyre::Result<()> {
    let (pg, schema, mut conn, seeded) = seeded_direct_schema().await?;

    let db = unprepared_envelope_db(&pg, schema).await?;
    let report = db.prepare_storage(aad_context()).await?;
    assert_eq!(
        report,
        StorageReport::new(5, 0, 0),
        "every direct row is upgraded"
    );

    let not_envelope: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM shares WHERE storage_format <> 'envelopeV1')
              + (SELECT COUNT(*) FROM in_progress_keygens WHERE storage_format <> 'envelopeV1')",
    )
    .fetch_one(&mut conn)
    .await?;
    assert_eq!(not_envelope, 0, "every row is envelopeV1");
    assert_seeded_values(&db, &seeded).await?;

    let (share, deleted): (Option<Vec<u8>>, bool) =
        sqlx::query_as("SELECT share, deleted FROM shares WHERE id = $1")
            .bind(seeded.deleted.to_le_bytes())
            .fetch_one(&mut conn)
            .await?;
    assert!(deleted, "the deleted row stays deleted");
    assert!(share.is_none(), "the deleted row has no share");
    Ok(())
}

#[tokio::test]
async fn upgrade_is_idempotent() -> eyre::Result<()> {
    let (pg, schema, mut conn, _) = seeded_direct_schema().await?;

    let db = unprepared_envelope_db(&pg, schema).await?;
    db.prepare_storage(aad_context()).await?;
    let before = snapshot(&mut conn).await?;

    let report = db.prepare_storage(aad_context()).await?;
    assert_eq!(report.upgraded, 0, "nothing is left to upgrade");
    assert_eq!(
        snapshot(&mut conn).await?,
        before,
        "stored bytes are unchanged"
    );
    Ok(())
}

#[tokio::test]
async fn upgrade_resumes_after_partial_run() -> eyre::Result<()> {
    let (pg, schema, mut conn, seeded) = seeded_direct_schema().await?;

    let db = unprepared_envelope_db(&pg, schema).await?;
    let crypto = db.ensure_crypto(aad_context()).await?;
    // An interrupted run: only the first share row (by primary key) is upgraded.
    let (upgraded, last) = upgrade::upgrade_shares_batch(&db.pool, crypto, None, 1).await?;
    assert_eq!(upgraded, 1, "one row is upgraded by hand");
    let first = last.expect("a row was read");
    let first_row = || {
        sqlx::query_as::<_, (Option<Vec<u8>>, String, Option<Uuid>)>(
            "SELECT share, storage_format, data_key_id FROM shares WHERE id = $1",
        )
        .bind(first.clone())
    };
    let before = first_row().fetch_one(&mut conn).await?;
    assert_eq!(before.1, "envelopeV1", "the first row is upgraded");

    let report = db.prepare_storage(aad_context()).await?;
    assert_eq!(
        report,
        StorageReport::new(4, 0, 0),
        "the remaining rows are upgraded"
    );
    assert_eq!(
        first_row().fetch_one(&mut conn).await?,
        before,
        "the first row is untouched"
    );
    assert_seeded_values(&db, &seeded).await?;
    Ok(())
}

#[tokio::test]
async fn upgrade_skips_direct_rows_when_direct_not_allowed() -> eyre::Result<()> {
    let pg = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let schema = nodes_common::test_utils::next_test_schema();
    let db = init_db(
        &pg,
        schema.clone(),
        StorageSettings {
            allowed: vec![StorageFormat::EnvelopeV1],
            write: StorageFormat::EnvelopeV1,
        },
        Some(Arc::new(wrapper())),
    )
    .await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    // Planted `direct` rows: a share and an in-progress key generation.
    oprf_store::test_utils::insert_share(
        &mut conn,
        OprfKeyId::new(U160::from(1)),
        ShareEpoch::new(1),
        &random_share(),
        &OprfPublicKey::new(rand::random()),
    )
    .await?;
    insert_intermediate_row(
        OprfKeyId::new(U160::from(2)),
        ShareEpoch::new(1),
        Some(oprf_store::codec::to_bytes(&random_share()).to_vec()),
        oprf_store::codec::to_bytes(&consumer_intermediates()).to_vec(),
        &mut conn,
    )
    .await?;
    let before = snapshot(&mut conn).await?;

    let report = db.prepare_storage(aad_context()).await?;
    assert_eq!(report.upgraded, 0, "no direct row is upgraded");
    assert_eq!(report.disallowed, 2, "both direct rows are disallowed");
    assert_eq!(snapshot(&mut conn).await?, before, "no row changed");
    assert!(
        before.iter().all(|row| row.4 == "direct"),
        "the rows are still direct"
    );
    Ok(())
}

#[tokio::test]
async fn upgrade_spans_multiple_batches() -> eyre::Result<()> {
    let pg = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let schema = nodes_common::test_utils::next_test_schema();
    let db = unprepared_envelope_db(&pg, schema.clone()).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    // More share rows than one batch, the last one soft-deleted.
    let share_rows = u64::try_from(upgrade::BATCH_SIZE * 2 + 1)?;
    let mut live = Vec::new();
    for key in 1..=share_rows {
        let oprf_key_id = OprfKeyId::new(U160::from(key));
        let epoch = ShareEpoch::new(1);
        let share = random_share();
        oprf_store::test_utils::insert_share(
            &mut conn,
            oprf_key_id,
            epoch,
            &share,
            &OprfPublicKey::new(rand::random()),
        )
        .await?;
        live.push((oprf_key_id, epoch, share));
    }
    let (deleted, _, _) = live.pop().expect("share rows are seeded");
    sqlx::query("UPDATE shares SET share = NULL, deleted = TRUE WHERE id = $1")
        .bind(deleted.to_le_bytes())
        .execute(&mut conn)
        .await?;

    // In-progress rows of one key at several pending epochs, so that a batch ends between two
    // rows with the same id.
    let in_progress_key = OprfKeyId::new(U160::from(1000));
    let mut in_progress = Vec::new();
    for epoch in 1..=u32::try_from(upgrade::BATCH_SIZE + 1)? {
        let epoch = ShareEpoch::new(epoch);
        let intermediates = oprf_store::codec::to_bytes(&consumer_intermediates()).to_vec();
        let pending = random_share();
        insert_intermediate_row(
            in_progress_key,
            epoch,
            Some(oprf_store::codec::to_bytes(&pending).to_vec()),
            intermediates.clone(),
            &mut conn,
        )
        .await?;
        in_progress.push((in_progress_key, epoch, intermediates, Some(pending)));
    }

    let report = db.prepare_storage(aad_context()).await?;
    let rows = share_rows + u64::try_from(in_progress.len())?;
    assert_eq!(
        report,
        StorageReport::new(rows, 0, 0),
        "every direct row is upgraded"
    );
    assert!(
        snapshot(&mut conn)
            .await?
            .iter()
            .all(|row| row.4 == "envelopeV1"),
        "every row is envelopeV1"
    );
    assert_seeded_values(
        &db,
        &Seeded {
            live,
            deleted,
            in_progress,
        },
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn prepare_creates_exactly_one_data_key() -> eyre::Result<()> {
    let pg = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let schema = nodes_common::test_utils::next_test_schema();
    let db = unprepared_envelope_db(&pg, schema.clone()).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    db.prepare_storage(aad_context()).await?;
    db.prepare_storage(aad_context()).await?;
    // A restarted process prepares again on the same database.
    unprepared_envelope_db(&pg, schema)
        .await?
        .prepare_storage(aad_context())
        .await?;
    assert_eq!(data_key_count(&mut conn).await?, 1, "one data key");
    Ok(())
}

#[tokio::test]
async fn concurrent_prepare_creates_one_data_key() -> eyre::Result<()> {
    let pg = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let schema = nodes_common::test_utils::next_test_schema();
    let db1 = unprepared_envelope_db(&pg, schema.clone()).await?;
    let db2 = unprepared_envelope_db(&pg, schema.clone()).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    let (r1, r2) = tokio::join!(
        db1.prepare_storage(aad_context()),
        db2.prepare_storage(aad_context())
    );
    r1?;
    r2?;
    assert_eq!(data_key_count(&mut conn).await?, 1, "one data key");

    let epoch = ShareEpoch::new(1);
    let key1 = OprfKeyId::new(U160::from(1));
    let key2 = OprfKeyId::new(U160::from(2));
    db1.try_store_keygen_intermediates(key1, epoch, consumer_intermediates())
        .await?;
    db2.try_store_keygen_intermediates(key2, epoch, consumer_intermediates())
        .await?;
    db1.fetch_keygen_intermediates(key2, epoch).await?;
    db2.fetch_keygen_intermediates(key1, epoch).await?;
    Ok(())
}

#[tokio::test]
async fn prepare_direct_only_touches_nothing() -> eyre::Result<()> {
    let (pg, schema, mut conn, _) = seeded_direct_schema().await?;
    let before = snapshot(&mut conn).await?;

    let db = init_db(&pg, schema, direct_settings(), None).await?;
    let report = db.prepare_storage(aad_context()).await?;
    assert_eq!(
        report,
        StorageReport::new(0, 5, 0),
        "direct rows are counted, not upgraded"
    );
    assert_eq!(data_key_count(&mut conn).await?, 0, "no data key");
    assert_eq!(snapshot(&mut conn).await?, before, "no row changed");
    Ok(())
}

#[tokio::test]
async fn report_counts_disallowed_rows() -> eyre::Result<()> {
    let (db, pg, schema) = postgres_db_with(StorageFormat::EnvelopeV1).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    confirm_random_share(
        &db,
        &mut conn,
        OprfKeyId::new(U160::from(42)),
        ShareEpoch::new(1),
        OprfPublicKey::new(rand::random()),
    )
    .await?;

    let direct_db = init_db(&pg, schema, direct_settings(), None).await?;
    let report = direct_db.prepare_storage(aad_context()).await?;
    assert_eq!(report.disallowed, 1, "the envelope row is not allowed");
    Ok(())
}

#[tokio::test]
async fn prepare_fails_on_key_arn_mismatch() -> eyre::Result<()> {
    let pg = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let schema = nodes_common::test_utils::next_test_schema();
    let db = unprepared_envelope_db(&pg, schema.clone()).await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    let other_arn = "arn:aws:kms:eu-central-1:000000000000:key/other";
    oprf_store::data_keys::create(&mut conn, &InMemoryWrapper::new(other_arn, [2; 32])).await?;

    let err = db
        .prepare_storage(aad_context())
        .await
        .expect_err("a data key under another KMS key must be refused")
        .to_string();
    assert!(
        err.contains(other_arn) && err.contains(wrapper().key_arn()),
        "the error must name both ARNs: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn operations_before_prepare_fail() -> eyre::Result<()> {
    let pg = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let schema = nodes_common::test_utils::next_test_schema();
    let db = init_db(&pg, schema, direct_settings(), None).await?;

    let err = db
        .get_share_by_epoch(OprfKeyId::new(U160::from(42)), ShareEpoch::new(1))
        .await
        .map(drop)
        .expect_err("storage is not prepared");
    assert!(
        matches!(err, SecretManagerError::Internal(_)),
        "expected Internal, got {err:?}"
    );
    Ok(())
}
