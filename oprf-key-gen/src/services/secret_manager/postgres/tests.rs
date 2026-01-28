use std::str::FromStr;

use alloy::{primitives::U160, signers::local::PrivateKeySigner};
use ark_serialize::CanonicalDeserialize;
use eyre::Context;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use sqlx::Row;
use sqlx::{Connection, PgConnection, postgres::PgRow};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ContainerAsync, runners::AsyncRunner as _},
};

use crate::secret_manager::{
    SecretManager,
    aws::test::{localstack_config, localstack_testcontainer},
    postgres::PostgresSecretManager,
};

const TEST_WALLET_PRIVATE_KEY_SECRET_ID: &str = "wallet_private_key_secret_id";

pub const ETH_PRIVATE_KEY: &str =
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba";

pub const ETH_ADDRESS: &str = "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc";

async fn postgres_secret_manager_with_localstack(
    aws_config: &aws_config::SdkConfig,
) -> eyre::Result<(ContainerAsync<Postgres>, String, PostgresSecretManager)> {
    let postgres_container = testcontainers_modules::postgres::Postgres::default()
        .start()
        .await?;
    let connection_string = format!(
        "postgres://postgres:postgres@{}:{}/postgres",
        postgres_container.get_host().await.unwrap(),
        postgres_container.get_host_port_ipv4(5432).await.unwrap()
    );
    let secret_manager = PostgresSecretManager::init(
        connection_string.clone().into(),
        aws_config.to_owned(),
        TEST_WALLET_PRIVATE_KEY_SECRET_ID,
    )
    .await?;
    Ok((postgres_container, connection_string, secret_manager))
}

async fn postgres_secret_manager()
-> eyre::Result<(ContainerAsync<Postgres>, String, PostgresSecretManager)> {
    postgres_secret_manager_with_localstack(&dummy_localstack_config().await).await
}

async fn open_pg_connection(connection_string: &str) -> eyre::Result<PgConnection> {
    PgConnection::connect(connection_string)
        .await
        .context("while opening PgConnection")
}

async fn dummy_localstack_config() -> aws_config::SdkConfig {
    localstack_config("dummy").await
}

#[tokio::test]
async fn load_or_insert_private_key_on_empty_db() -> eyre::Result<()> {
    // for this test we need localstack as well
    let (_localstack, localstack_url) = localstack_testcontainer().await?;
    let aws_config = localstack_config(&localstack_url).await;
    let (_postgres, connection_string, secret_manager) =
        postgres_secret_manager_with_localstack(&aws_config).await?;
    let computed_private_key = secret_manager.load_or_insert_wallet_private_key().await?;

    let localstack_client = aws_sdk_secretsmanager::Client::new(&aws_config);
    let stored_private_key = localstack_client
        .get_secret_value()
        .secret_id(TEST_WALLET_PRIVATE_KEY_SECRET_ID)
        .send()
        .await?
        .secret_string()
        .ok_or_else(|| eyre::eyre!("is not a secret-string"))?
        .to_owned();

    assert_eq!(
        PrivateKeySigner::from_str(&stored_private_key)?,
        computed_private_key
    );

    // check that the address is correct
    let mut pg_connection = open_pg_connection(&connection_string).await?;
    let stored_address: String =
        sqlx::query_scalar("SELECT address FROM evm_address WHERE id = TRUE")
            .fetch_one(&mut pg_connection)
            .await?;

    assert_eq!(stored_address, computed_private_key.address().to_string());
    Ok(())
}

#[tokio::test]
async fn load_or_insert_private_key_on_existing_key() -> eyre::Result<()> {
    // for this test we need localstack as well
    let (_localstack, localstack_url) = localstack_testcontainer().await?;
    let aws_config = localstack_config(&localstack_url).await;
    let (_postgres, connection_string, secret_manager) =
        postgres_secret_manager_with_localstack(&aws_config).await?;

    let localstack_client = aws_sdk_secretsmanager::Client::new(&aws_config);
    localstack_client
        .create_secret()
        .name(TEST_WALLET_PRIVATE_KEY_SECRET_ID)
        .secret_string(ETH_PRIVATE_KEY)
        .send()
        .await?;

    let is_private_key = secret_manager.load_or_insert_wallet_private_key().await?;

    assert_eq!(PrivateKeySigner::from_str(ETH_PRIVATE_KEY)?, is_private_key);

    // check that the address is correct
    let mut pg_connection = open_pg_connection(&connection_string).await?;
    let stored_address: String =
        sqlx::query_scalar("SELECT address FROM evm_address WHERE id = TRUE")
            .fetch_one(&mut pg_connection)
            .await?;

    assert_eq!(stored_address, ETH_ADDRESS);
    Ok(())
}

#[tokio::test]
async fn load_or_insert_private_key_on_existing_key_overwrite_db() -> eyre::Result<()> {
    // for this test we need localstack as well
    let (_localstack, localstack_url) = localstack_testcontainer().await?;
    let aws_config = localstack_config(&localstack_url).await;
    let (_postgres, connection_string, secret_manager) =
        postgres_secret_manager_with_localstack(&aws_config).await?;

    let localstack_client = aws_sdk_secretsmanager::Client::new(&aws_config);
    localstack_client
        .create_secret()
        .name(TEST_WALLET_PRIVATE_KEY_SECRET_ID)
        .secret_string(ETH_PRIVATE_KEY)
        .send()
        .await?;

    let mut pg_connection = open_pg_connection(&connection_string).await?;
    sqlx::query(
        r#"
                INSERT INTO evm_address (id, address)
                VALUES (TRUE, $1)
                ON CONFLICT (id)
                DO UPDATE SET address = EXCLUDED.address
            "#,
    )
    .bind("SOMETHING THAT IS NOT AN ADDRESS")
    .execute(&mut pg_connection)
    .await?;

    let is_private_key = secret_manager.load_or_insert_wallet_private_key().await?;

    assert_eq!(PrivateKeySigner::from_str(ETH_PRIVATE_KEY)?, is_private_key);

    // check that the address is correct
    let stored_address: String =
        sqlx::query_scalar("SELECT address FROM evm_address WHERE id = TRUE")
            .fetch_one(&mut pg_connection)
            .await?;

    assert_eq!(stored_address, ETH_ADDRESS);
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
    should_current: DLogShareShamir,
    should_prev: Option<DLogShareShamir>,
    should_epoch: ShareEpoch,
    should_public_key: OprfPublicKey,
) {
    let is_id: Vec<u8> = row.get(0);
    let is_current: Vec<u8> = row.get(1);
    let is_prev: Option<Vec<u8>> = row.get(2);
    let is_epoch: i64 = row.get(3);
    let is_public_key: Vec<u8> = row.get(4);

    assert_eq!(
        should_oprf_key_id,
        OprfKeyId::from(U160::from_be_slice(&is_id))
    );

    assert_eq!(
        ark_babyjubjub::Fr::from(should_current),
        ark_babyjubjub::Fr::deserialize_uncompressed(is_current.as_slice())
            .expect("Can deserialize")
    );
    let should_prev = should_prev.map(ark_babyjubjub::Fr::from);
    let is_prev = is_prev.map(|prev| {
        ark_babyjubjub::Fr::deserialize_uncompressed(prev.as_slice()).expect("Can deserialize")
    });
    assert_eq!(should_prev, is_prev);
    assert_eq!(should_epoch.into_inner() as i64, is_epoch);
    assert_eq!(
        should_public_key,
        OprfPublicKey::deserialize_compressed_unchecked(is_public_key.as_slice())
            .expect("Can deserialize"),
    );
}

#[tokio::test]
async fn store_dlog_share_and_fetch_previous() -> eyre::Result<()> {
    let (_postgres, connection_string, secret_manager) = postgres_secret_manager().await?;
    let mut pg_connection = open_pg_connection(&connection_string).await?;

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
        should_epoch_0_share.clone(),
        None,
        epoch0,
        public_key,
    );

    // should return None when fetching previous share from epoch 0
    let should_no_share = secret_manager
        .get_previous_share(oprf_key_id, epoch0)
        .await?;
    assert!(should_no_share.is_none());

    // should return epoch zero when fetching previous share from epoch 1
    let is_epoch_0_share = secret_manager
        .get_previous_share(oprf_key_id, epoch1)
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
        should_epoch_1_share.clone(),
        Some(should_epoch_0_share.clone()),
        epoch1,
        public_key,
    );
    // should return epoch one when fetching previous share from epoch 2
    let is_epoch_1_share = secret_manager
        .get_previous_share(oprf_key_id, epoch2)
        .await?
        .expect("should be some");
    assert_eq!(
        ark_babyjubjub::Fr::from(is_epoch_1_share),
        ark_babyjubjub::Fr::from(should_epoch_1_share.clone())
    );
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
        .get_previous_share(oprf_key_id, epoch2.next())
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
        should_epoch_2_share.clone(),
        Some(should_epoch_1_share.clone()),
        epoch2,
        public_key,
    );
    Ok(())
}

#[tokio::test]
async fn store_dlog_share_as_consumer() -> eyre::Result<()> {
    let (_postgres, connection_string, secret_manager) = postgres_secret_manager().await?;
    let mut pg_connection = open_pg_connection(&connection_string).await?;

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
        should_epoch_42_share.clone(),
        None,
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
        should_epoch_128_share.clone(),
        None,
        epoch128,
        public_key,
    );

    Ok(())
}

#[tokio::test]
async fn try_retrieve_random_empty_epochs() -> eyre::Result<()> {
    let (_postgres, _, secret_manager) = postgres_secret_manager().await?;

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
            .get_previous_share(oprf_key_id, ShareEpoch::default())
            .await?
            .is_none()
    );
    assert!(
        secret_manager
            .get_previous_share(oprf_key_id, ShareEpoch::new(12))
            .await?
            .is_none()
    );
    assert!(
        secret_manager
            .get_previous_share(oprf_key_id, ShareEpoch::new(42))
            .await?
            .is_none()
    );
    assert!(
        secret_manager
            .get_previous_share(oprf_key_id, ShareEpoch::new(1289))
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn test_insert_same_epoch_twice() -> eyre::Result<()> {
    let (_postgres, connection_string, secret_manager) = postgres_secret_manager().await?;
    let mut pg_connection = open_pg_connection(&connection_string).await?;

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
        should_epoch_42_share.clone(),
        None,
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
        should_epoch_42_share.clone(),
        None,
        epoch42,
        public_key,
    );

    Ok(())
}

#[tokio::test]
async fn test_delete() -> eyre::Result<()> {
    let (_postgres, connection_string, secret_manager) = postgres_secret_manager().await?;
    let mut pg_connection = open_pg_connection(&connection_string).await?;

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
        should_epoch_42_share.clone(),
        None,
        epoch42,
        public_key,
    );

    // remove the key and check if DB is empty now
    secret_manager.remove_oprf_key_material(oprf_key_id).await?;
    assert!(all_rows(&mut pg_connection).await?.is_empty());
    Ok(())
}
