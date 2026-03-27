use std::str::FromStr;

use crate::secret_manager::SecretManager as _;
use crate::secret_manager::postgres::PostgresSecretManager;
use alloy::{primitives::U160, signers::local::PrivateKeySigner};
use ark_serialize::CanonicalDeserialize;
use eyre::Context;
use nodes_common::postgres::PostgresConfig;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_test_utils::{TEST_ETH_ADDRESS, TEST_ETH_PRIVATE_KEY, TEST_SCHEMA};
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use secrecy::SecretString;
use sqlx::Row;
use sqlx::{PgConnection, postgres::PgRow};

async fn postgres_secret_manager(connection_string: &str) -> eyre::Result<PostgresSecretManager> {
    let mut pg_connection =
        oprf_test_utils::open_pg_connection(connection_string, TEST_SCHEMA).await?;
    sqlx::migrate!("./migrations")
        .run(&mut pg_connection)
        .await?;

    PostgresSecretManager::init(&PostgresConfig::with_default_values(
        SecretString::from(connection_string.to_owned()),
        TEST_SCHEMA.parse().expect("Is a valid schema"),
    ))
    .await
}

#[tokio::test]
async fn load_wallet_private_key_returns_correct_key() -> eyre::Result<()> {
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    let secret_manager = postgres_secret_manager(&connection_string).await?;

    let key = PrivateKeySigner::from_str(TEST_ETH_PRIVATE_KEY)?;
    let address = key.address();
    secret_manager
        .store_wallet_address(address.to_string())
        .await?;

    // check that the address is stored in the DB
    let mut pg_connection =
        oprf_test_utils::open_pg_connection(&connection_string, TEST_SCHEMA).await?;
    let stored_address: String =
        sqlx::query_scalar("SELECT address FROM evm_address WHERE id = TRUE")
            .fetch_one(&mut pg_connection)
            .await?;

    assert_eq!(stored_address, TEST_ETH_ADDRESS);
    Ok(())
}

async fn all_rows(conn: &mut PgConnection) -> eyre::Result<Vec<PgRow>> {
    sqlx::query("SELECT * FROM shares")
        .fetch_all(conn)
        .await
        .context("while fetching all rows")
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
async fn store_dlog_share_and_fetch_previous() -> eyre::Result<()> {
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    let secret_manager = postgres_secret_manager(&connection_string).await?;
    let mut pg_connection =
        oprf_test_utils::open_pg_connection(&connection_string, TEST_SCHEMA).await?;

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
    secret_manager
        .store_dlog_share(
            oprf_key_id,
            public_key,
            epoch0,
            should_epoch_0_share.clone(),
        )
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
    secret_manager
        .store_dlog_share(
            oprf_key_id,
            public_key,
            epoch1,
            should_epoch_1_share.clone(),
        )
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
    secret_manager
        .store_dlog_share(
            oprf_key_id,
            public_key,
            epoch2,
            should_epoch_2_share.clone(),
        )
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
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    let secret_manager = postgres_secret_manager(&connection_string).await?;
    let mut pg_connection =
        oprf_test_utils::open_pg_connection(&connection_string, TEST_SCHEMA).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch42 = ShareEpoch::new(42);
    let epoch128 = ShareEpoch::new(128);
    let should_epoch_42_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    let should_epoch_128_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    //store epoch 42 without inserting anything beforehand
    secret_manager
        .store_dlog_share(
            oprf_key_id,
            public_key,
            epoch42,
            should_epoch_42_share.clone(),
        )
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
    secret_manager
        .store_dlog_share(
            oprf_key_id,
            public_key,
            epoch128,
            should_epoch_128_share.clone(),
        )
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
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    let secret_manager = postgres_secret_manager(&connection_string).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch42 = ShareEpoch::new(42);
    let should_epoch_42_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    //store epoch 42 without inserting anything beforehand
    secret_manager
        .store_dlog_share(
            oprf_key_id,
            public_key,
            epoch42,
            should_epoch_42_share.clone(),
        )
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
async fn test_insert_same_epoch_twice() -> eyre::Result<()> {
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    let secret_manager = postgres_secret_manager(&connection_string).await?;
    let mut pg_connection =
        oprf_test_utils::open_pg_connection(&connection_string, TEST_SCHEMA).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch42 = ShareEpoch::new(42);
    let should_epoch_42_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    //store epoch 42 without inserting anything beforehand
    secret_manager
        .store_dlog_share(
            oprf_key_id,
            public_key,
            epoch42,
            should_epoch_42_share.clone(),
        )
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

    // store epoch 42 again - should be noop
    secret_manager
        .store_dlog_share(
            oprf_key_id,
            public_key,
            epoch42,
            should_epoch_42_share.clone(),
        )
        .await?;
    let epoch_42_dump_new = all_rows(&mut pg_connection).await?;
    assert_eq!(epoch_42_dump_new.len(), 1);
    assert_row_matches(
        &epoch_42_dump_new[0],
        oprf_key_id,
        Some(should_epoch_42_share.clone()),
        epoch42,
        public_key,
    );

    Ok(())
}

#[tokio::test]
async fn test_delete() -> eyre::Result<()> {
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    let secret_manager = postgres_secret_manager(&connection_string).await?;
    let mut pg_connection =
        oprf_test_utils::open_pg_connection(&connection_string, TEST_SCHEMA).await?;

    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch42 = ShareEpoch::new(42);
    let should_epoch_42_share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    // should work but shouldn't have any effect
    secret_manager.remove_oprf_key_material(oprf_key_id).await?;

    secret_manager
        .store_dlog_share(
            oprf_key_id,
            public_key,
            epoch42,
            should_epoch_42_share.clone(),
        )
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
    secret_manager.remove_oprf_key_material(oprf_key_id).await?;
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
