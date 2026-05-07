#![allow(clippy::too_many_lines, reason = "doesn't matter for tests")]
use std::path::PathBuf;
use std::str::FromStr;

use crate::event_cursor_store::ChainCursorStorage;
use crate::postgres::{PostgresDb, to_db_ark_serialize_uncompressed};
use crate::secret_manager::{SecretManager as _, SecretManagerError};
use crate::services::secret_gen::DLogSecretGenService;
use alloy::{primitives::U160, signers::local::PrivateKeySigner, sol_types::SolValue as _};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize as _};
use eyre::Context;
use groth16_material::circom::{CircomGroth16Material, CircomGroth16MaterialBuilder, Validate};
use nodes_common::postgres::{PostgresConfig, SanitizedSchema};
use nodes_common::web3::event_stream::ChainCursor;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_test_utils::{TEST_ETH_ADDRESS, TEST_ETH_PRIVATE_KEY};
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use secrecy::SecretString;
use sqlx::Row;
use sqlx::{PgConnection, postgres::PgRow};

async fn postgres_secret_manager() -> eyre::Result<(PostgresDb, &'static str, SanitizedSchema)> {
    let conn = oprf_test_utils::shared_postgres_testcontainer().await?;
    let schema = oprf_test_utils::next_test_schema();
    let db = postgres_secret_manager_with_schema(conn, schema.clone()).await?;
    Ok((db, conn, schema))
}

async fn postgres_db() -> eyre::Result<PostgresDb> {
    let (db, _, _) = postgres_secret_manager().await?;
    Ok(db)
}

pub(crate) async fn postgres_secret_manager_with_schema(
    connection_string: &str,
    schema: SanitizedSchema,
) -> eyre::Result<PostgresDb> {
    PostgresDb::init(&PostgresConfig::with_default_values(
        SecretString::from(connection_string.to_owned()),
        schema,
    ))
    .await
}

#[tokio::test]
async fn load_wallet_private_key_returns_correct_key() -> eyre::Result<()> {
    let (secret_manager, connection_string, schema) = postgres_secret_manager().await?;

    let key = PrivateKeySigner::from_str(TEST_ETH_PRIVATE_KEY)?;
    let address = key.address();
    secret_manager
        .store_wallet_address(address.to_string())
        .await?;

    // check that the address is stored in the DB
    let mut pg_connection =
        oprf_test_utils::open_pg_connection(connection_string, &schema.to_string()).await?;
    let stored_address: String =
        sqlx::query_scalar("SELECT address FROM evm_address WHERE id = TRUE")
            .fetch_one(&mut pg_connection)
            .await?;

    assert_eq!(stored_address, TEST_ETH_ADDRESS);
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

/// Test helper: directly inserts a pending-share row into `in_progress_keygens`, ready to be confirmed.
async fn setup_pending_share(
    pg_connection: &mut PgConnection,
    oprf_key_id: OprfKeyId,
    pending_epoch: ShareEpoch,
    share: &DLogShareShamir,
) -> eyre::Result<()> {
    let mut share_bytes = Vec::with_capacity(share.uncompressed_size());
    share
        .serialize_uncompressed(&mut share_bytes)
        .expect("Can serialize");
    sqlx::query(
        "INSERT INTO in_progress_keygens (id, pending_epoch, pending_share, intermediates)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (id, pending_epoch) DO UPDATE SET
             pending_share = EXCLUDED.pending_share,
             intermediates = EXCLUDED.intermediates",
    )
    .bind(oprf_key_id.to_le_bytes())
    .bind(i64::from(pending_epoch.into_inner()))
    .bind(share_bytes)
    // `confirm_dlog_share` only reads `pending_share`; these tests do not deserialize `intermediates`.
    .bind(vec![0_u8])
    .execute(&mut *pg_connection)
    .await?;
    Ok(())
}

fn assert_row_matches(
    row: &PgRow,
    should_oprf_key_id: OprfKeyId,
    should_share: Option<DLogShareShamir>,
    should_epoch: ShareEpoch,
    should_public_key: OprfPublicKey,
) {
    let is_id: Vec<u8> = row.get(0);
    let is_share: Option<Vec<u8>> = row.get(1);
    let is_epoch: i64 = row.get(2);
    let is_public_key: Vec<u8> = row.get(3);
    let is_deleted: bool = row.get(4);

    assert_eq!(should_oprf_key_id, OprfKeyId::from_le_slice(&is_id));

    assert_eq!(should_share.is_none(), is_deleted);
    let is_share = is_share.map(|is_share| {
        ark_babyjubjub::Fr::deserialize_uncompressed(is_share.as_slice()).expect("Can deserialize")
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

#[tokio::test]
async fn fetch_keygen_intermediates_missing_returns_none() -> eyre::Result<()> {
    let secret_manager = postgres_db().await?;
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

#[tokio::test]
async fn key_gen_round1_is_idempotent() -> eyre::Result<()> {
    let secret_manager = std::sync::Arc::new(postgres_db().await?);
    let dlog_secret_gen = DLogSecretGenService::init(key_gen_material()?, secret_manager.clone());
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let epoch = ShareEpoch::default();

    let first_contribution = dlog_secret_gen
        .key_gen_round1(oprf_key_id, epoch, 2.try_into().expect("2 is non-zero"))
        .await?;
    let intermediates = secret_manager
        .fetch_keygen_intermediates(oprf_key_id, epoch)
        .await?;

    let serialized_intermediates = super::to_db_ark_serialize_uncompressed(&intermediates);

    let retried_contribution = dlog_secret_gen
        .key_gen_round1(oprf_key_id, epoch, 2.try_into().expect("2 is non-zero"))
        .await
        .expect("retrying round 1 should reuse stored intermediates");

    let stored_after_retry = secret_manager
        .fetch_keygen_intermediates(oprf_key_id, epoch)
        .await?;

    assert_eq!(
        serialized_intermediates,
        to_db_ark_serialize_uncompressed(&stored_after_retry)
    );
    assert_eq!(
        first_contribution.abi_encode(),
        retried_contribution.abi_encode()
    );
    Ok(())
}

#[tokio::test]
async fn store_pending_share_without_intermediates_fails() -> eyre::Result<()> {
    let secret_manager = postgres_db().await?;
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

#[tokio::test]
async fn confirm_without_pending_share_fails() -> eyre::Result<()> {
    let (secret_manager, connection_string, schema) = postgres_secret_manager().await?;
    let mut conn =
        oprf_test_utils::open_pg_connection(connection_string, &schema.to_string()).await?;

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

#[tokio::test]
async fn abort_keygen_is_idempotent_and_preserves_confirmed_share() -> eyre::Result<()> {
    let (secret_manager, connection_string, schema) = postgres_secret_manager().await?;
    let mut conn =
        oprf_test_utils::open_pg_connection(connection_string, &schema.to_string()).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let epoch = ShareEpoch::new(42);
    let next_epoch = epoch.next();
    let public_key = OprfPublicKey::new(rand::random());
    let share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    setup_pending_share(&mut conn, oprf_key_id, epoch, &share).await?;
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

#[tokio::test]
async fn store_dlog_share_and_fetch_previous() -> eyre::Result<()> {
    let (secret_manager, connection_string, schema) = postgres_secret_manager().await?;
    let mut pg_connection =
        oprf_test_utils::open_pg_connection(connection_string, &schema.to_string()).await?;

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
        &epoch_0_dump[0],
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
        &epoch_1_dump[0],
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
        &epoch_2_dump[0],
        oprf_key_id,
        Some(should_epoch_2_share.clone()),
        epoch2,
        public_key,
    );
    Ok(())
}

#[tokio::test]
async fn store_dlog_share_as_consumer() -> eyre::Result<()> {
    let (secret_manager, connection_string, schema) = postgres_secret_manager().await?;
    let mut pg_connection =
        oprf_test_utils::open_pg_connection(connection_string, &schema.to_string()).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch42 = ShareEpoch::new(42);
    let epoch128 = ShareEpoch::new(128);
    let should_epoch_42_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    let should_epoch_128_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    //store epoch 42 without inserting anything beforehand
    setup_pending_share(
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
        &epoch_42_dump[0],
        oprf_key_id,
        Some(should_epoch_42_share.clone()),
        epoch42,
        public_key,
    );

    //store epoch 128 after epoch 42 - now prev should be None again
    setup_pending_share(
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
        &epoch_128_dump[0],
        oprf_key_id,
        Some(should_epoch_128_share.clone()),
        epoch128,
        public_key,
    );

    Ok(())
}

#[tokio::test]
async fn try_retrieve_random_empty_epochs() -> eyre::Result<()> {
    let (secret_manager, connection_string, schema) = postgres_secret_manager().await?;
    let mut pg_connection =
        oprf_test_utils::open_pg_connection(connection_string, &schema.to_string()).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch42 = ShareEpoch::new(42);
    let should_epoch_42_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    //store epoch 42 without inserting anything beforehand
    setup_pending_share(
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

#[tokio::test]
async fn confirm_after_abort_keygen_fails() -> eyre::Result<()> {
    let (secret_manager, connection_string, schema) = postgres_secret_manager().await?;
    let mut conn =
        oprf_test_utils::open_pg_connection(connection_string, &schema.to_string()).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch = ShareEpoch::new(42);
    let share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    setup_pending_share(&mut conn, oprf_key_id, epoch, &share).await?;
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

#[tokio::test]
async fn confirm_same_epoch_without_restaging_is_idempotent() -> eyre::Result<()> {
    let (secret_manager, connection_string, schema) = postgres_secret_manager().await?;
    let mut pg_connection =
        oprf_test_utils::open_pg_connection(connection_string, &schema.to_string()).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch42 = ShareEpoch::new(42);
    let should_epoch_42_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    //store epoch 42 without inserting anything beforehand
    setup_pending_share(
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
        &epoch_42_dump[0],
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
        &epoch_42_dump_new[0],
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

#[tokio::test]
async fn confirm_same_epoch_after_restaging_is_idempotent() -> eyre::Result<()> {
    let (secret_manager, connection_string, schema) = postgres_secret_manager().await?;
    let mut pg_connection =
        oprf_test_utils::open_pg_connection(connection_string, &schema.to_string()).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch42 = ShareEpoch::new(42);
    let original_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    let retried_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    setup_pending_share(&mut pg_connection, oprf_key_id, epoch42, &original_share).await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch42, public_key)
        .await?;

    setup_pending_share(&mut pg_connection, oprf_key_id, epoch42, &retried_share).await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch42, public_key)
        .await
        .expect("retrying confirm with restaged data should keep the finalized share");

    let epoch_42_dump = all_rows(&mut pg_connection).await?;
    assert_eq!(epoch_42_dump.len(), 1);
    assert_row_matches(
        &epoch_42_dump[0],
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

#[tokio::test]
async fn delete_oprf_key_material_is_idempotent_and_soft_deletes_share() -> eyre::Result<()> {
    let (secret_manager, connection_string, schema) = postgres_secret_manager().await?;
    let mut conn =
        oprf_test_utils::open_pg_connection(connection_string, &schema.to_string()).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch = ShareEpoch::new(42);
    let next_epoch = epoch.next();
    let share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    setup_pending_share(&mut conn, oprf_key_id, epoch, &share).await?;
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
    assert_row_matches(&rows[0], oprf_key_id, None, epoch, public_key);
    Ok(())
}

#[tokio::test]
async fn confirm_deleted_share_returns_store_on_deleted_share() -> eyre::Result<()> {
    let (secret_manager, connection_string, schema) = postgres_secret_manager().await?;
    let mut conn =
        oprf_test_utils::open_pg_connection(connection_string, &schema.to_string()).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch = ShareEpoch::new(42);
    let next_epoch = epoch.next();
    let share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    setup_pending_share(&mut conn, oprf_key_id, epoch, &share).await?;
    secret_manager
        .confirm_dlog_share(oprf_key_id, epoch, public_key)
        .await?;
    secret_manager.delete_oprf_key_material(oprf_key_id).await?;

    let next_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    setup_pending_share(&mut conn, oprf_key_id, next_epoch, &next_share).await?;

    let err = secret_manager
        .confirm_dlog_share(oprf_key_id, next_epoch, public_key)
        .await
        .expect_err("confirm on deleted share should fail");
    assert!(matches!(err, SecretManagerError::StoreOnDeletedShare));

    let rows = all_rows(&mut conn).await?;
    assert_eq!(rows.len(), 1);
    assert_row_matches(&rows[0], oprf_key_id, None, epoch, public_key);
    Ok(())
}

#[tokio::test]
async fn test_delete() -> eyre::Result<()> {
    let (secret_manager, connection_string, schema) = postgres_secret_manager().await?;
    let mut pg_connection =
        oprf_test_utils::open_pg_connection(connection_string, &schema.to_string()).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch42 = ShareEpoch::new(42);
    let should_epoch_42_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    // should work but shouldn't have any effect
    secret_manager.delete_oprf_key_material(oprf_key_id).await?;

    setup_pending_share(
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
        &epoch_42_dump[0],
        oprf_key_id,
        Some(should_epoch_42_share.clone()),
        epoch42,
        public_key,
    );

    // remove the key and check if DB is empty now
    secret_manager.delete_oprf_key_material(oprf_key_id).await?;
    let epoch_42_deleted = all_rows(&mut pg_connection).await?;
    assert_row_matches(&epoch_42_deleted[0], oprf_key_id, None, epoch42, public_key);

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
    let secret_manager = postgres_db().await?;

    let should_genesis_cursor = secret_manager.load_chain_cursor().await?;
    assert!(
        should_genesis_cursor.is_genesis(),
        "Should be genesis cursor on empty DB"
    );
    Ok(())
}

#[tokio::test]
async fn test_insert_chain_cursor_then_load() -> eyre::Result<()> {
    let secret_manager = postgres_db().await?;

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
    let secret_manager = postgres_db().await?;

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
