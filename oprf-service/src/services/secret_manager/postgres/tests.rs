use std::time::Duration;

use crate::secret_manager::{
    GetOprfKeyMaterialError, SecretManager, postgres::PostgresSecretManager,
};
use alloy::primitives::U160;
use ark_serialize::CanonicalSerialize;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_test_utils::{OPRF_PEER_ADDRESS_0, TEST_SCHEMA};
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use secrecy::SecretString;
use sqlx::PgConnection;

#[inline(always)]
fn to_db_ark_serialize_uncompressed<T: CanonicalSerialize>(t: T) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(t.uncompressed_size());
    t.serialize_uncompressed(&mut bytes).expect("Can serialize");
    bytes
}

async fn postgres_secret_manager(connection_string: &str) -> eyre::Result<PostgresSecretManager> {
    let mut pg_connection =
        oprf_test_utils::open_pg_connection(connection_string, TEST_SCHEMA).await?;
    sqlx::migrate!("../oprf-key-gen/migrations")
        .run(&mut pg_connection)
        .await?;
    PostgresSecretManager::init(
        &SecretString::from(connection_string.to_owned()),
        TEST_SCHEMA,
        1.try_into().unwrap(),
        Duration::from_secs(2),
        30.try_into().expect("Is NonZero"),
        Duration::from_secs(1),
    )
    .await
}

async fn insert_row(
    oprf_key_id: OprfKeyId,
    share: DLogShareShamir,
    epoch: ShareEpoch,
    public_key: OprfPublicKey,
    connection: &mut PgConnection,
) -> eyre::Result<()> {
    sqlx::query(
        r#"
            INSERT INTO shares (id, share, epoch, public_key)
            VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(oprf_key_id.to_le_bytes())
    .bind(to_db_ark_serialize_uncompressed(share))
    .bind(i64::from(epoch.into_inner()))
    .bind(to_db_ark_serialize_uncompressed(public_key))
    .execute(connection)
    .await?;
    Ok(())
}

async fn delete_row(oprf_key_id: OprfKeyId, connection: &mut PgConnection) -> eyre::Result<()> {
    let success = sqlx::query(
        r#"
            UPDATE shares
            SET
                share = NULL,
                deleted = true
            WHERE id = $1
        "#,
    )
    .bind(oprf_key_id.to_le_bytes())
    .execute(connection)
    .await?;
    assert!(success.rows_affected() == 1);
    Ok(())
}

async fn insert_address(address: &str, connection: &mut PgConnection) -> eyre::Result<()> {
    sqlx::query(
        r#"
            INSERT INTO evm_address (id, address)
            VALUES (TRUE, $1)
        "#,
    )
    .bind(address)
    .execute(connection)
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_load_all_secret_empty() -> eyre::Result<()> {
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    let secret_manager = postgres_secret_manager(&connection_string).await?;
    let key_material_store = secret_manager.load_secrets().await?;
    assert!(key_material_store.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_empty_schema_name() -> eyre::Result<()> {
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    let should_error = PostgresSecretManager::init(
        &SecretString::from(connection_string.to_owned()),
        "",
        1.try_into().unwrap(),
        Duration::from_secs(2),
        30.try_into().expect("Is NonZero"),
        Duration::from_secs(1),
    )
    .await
    .expect_err("Should fail");
    assert_eq!("while building schema string", should_error.to_string());
    Ok(())
}

#[tokio::test]
async fn load_address_empty() -> eyre::Result<()> {
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    let secret_manager = postgres_secret_manager(&connection_string).await?;
    let report = secret_manager
        .load_address()
        .await
        .expect_err("should be an error");
    assert_eq!(
        report.to_string(),
        "Cannot get address from DB, maybe key-gen needs to start"
    );
    Ok(())
}

#[tokio::test]
async fn load_address_corrupt() -> eyre::Result<()> {
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    let secret_manager = postgres_secret_manager(&connection_string).await?;

    let mut conn = oprf_test_utils::open_pg_connection(&connection_string, TEST_SCHEMA).await?;
    insert_address("SomethingThatIsNotAnAddress", &mut conn).await?;

    let report = secret_manager
        .load_address()
        .await
        .expect_err("should be an error");
    assert_eq!(report.to_string(), "invalid address stored in DB");
    Ok(())
}

#[tokio::test]
async fn load_address_success() -> eyre::Result<()> {
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    let secret_manager = postgres_secret_manager(&connection_string).await?;

    let should_address = OPRF_PEER_ADDRESS_0;
    let mut conn = oprf_test_utils::open_pg_connection(&connection_string, TEST_SCHEMA).await?;
    insert_address(&should_address.to_string(), &mut conn).await?;

    let is_address = secret_manager.load_address().await.expect("Should work");
    assert_eq!(is_address, should_address);
    Ok(())
}

#[tokio::test]
async fn test_load_all_secret_three_shares() -> eyre::Result<()> {
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    // runs migrations
    let secret_manager = postgres_secret_manager(&connection_string).await?;

    let mut conn = oprf_test_utils::open_pg_connection(&connection_string, TEST_SCHEMA).await?;

    let oprf_key_id0 = OprfKeyId::new(U160::from(42));
    let oprf_key_id1 = OprfKeyId::new(U160::from(128));
    let oprf_key_id2 = OprfKeyId::new(U160::from(6891));
    let public_key0 = OprfPublicKey::new(rand::random());
    let public_key1 = OprfPublicKey::new(rand::random());
    let public_key2 = OprfPublicKey::new(rand::random());
    let epoch0 = ShareEpoch::new(42);
    let epoch1 = ShareEpoch::new(32819);
    let epoch2 = ShareEpoch::new(3242);
    let share0 = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    let share1 = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    let share2 = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    insert_row(oprf_key_id0, share0, epoch0, public_key0, &mut conn).await?;
    insert_row(oprf_key_id1, share1.clone(), epoch1, public_key1, &mut conn).await?;
    insert_row(oprf_key_id2, share2.clone(), epoch2, public_key2, &mut conn).await?;

    let key_material_store = secret_manager.load_secrets().await?;
    assert_eq!(key_material_store.len(), 3);
    let is_key_material0 = key_material_store
        .get(&oprf_key_id0)
        .expect("Should be some");
    assert_eq!(is_key_material0.public_key_with_epoch().epoch, epoch0);
    assert_eq!(is_key_material0.public_key_with_epoch().key, public_key0);
    let is_key_material1 = key_material_store
        .get(&oprf_key_id1)
        .expect("Should be some");
    assert_eq!(is_key_material1.public_key_with_epoch().epoch, epoch1);
    assert_eq!(is_key_material1.public_key_with_epoch().key, public_key1);
    let is_key_material2 = key_material_store
        .get(&oprf_key_id2)
        .expect("Should be some");
    assert_eq!(is_key_material2.public_key_with_epoch().epoch, epoch2);
    assert_eq!(is_key_material2.public_key_with_epoch().key, public_key2);
    Ok(())
}

#[tokio::test]
async fn test_get_oprf_key_material() -> eyre::Result<()> {
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    // runs migrations
    let secret_manager = postgres_secret_manager(&connection_string).await?;

    let mut conn = oprf_test_utils::open_pg_connection(&connection_string, TEST_SCHEMA).await?;

    let oprf_key_id0 = OprfKeyId::new(U160::from(42));
    let oprf_key_id1 = OprfKeyId::new(U160::from(128));
    let oprf_key_id_unknown = OprfKeyId::new(U160::from(6891));
    let public_key0 = OprfPublicKey::new(rand::random());
    let public_key1 = OprfPublicKey::new(rand::random());
    let epoch0 = ShareEpoch::new(42);
    let epoch1 = ShareEpoch::new(32819);
    let share0 = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    let share1 = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    insert_row(oprf_key_id0, share0.clone(), epoch0, public_key0, &mut conn).await?;
    insert_row(oprf_key_id1, share1.clone(), epoch1, public_key1, &mut conn).await?;

    let key_material0 = secret_manager
        .get_oprf_key_material(oprf_key_id0, epoch0)
        .await?;
    assert_eq!(
        ark_babyjubjub::Fr::from(key_material0.share()),
        ark_babyjubjub::Fr::from(share0)
    );
    assert!(key_material0.is_epoch(epoch0));
    assert_eq!(key_material0.public_key(), public_key0);

    // should be NotInDb
    assert!(matches!(
        secret_manager
            .get_oprf_key_material(oprf_key_id0, epoch1)
            .await,
        Err(GetOprfKeyMaterialError::NotFound)
    ));

    // should be NotInDb
    assert!(matches!(
        secret_manager
            .get_oprf_key_material(oprf_key_id_unknown, epoch1)
            .await,
        Err(GetOprfKeyMaterialError::NotFound)
    ));

    let key_material1 = secret_manager
        .get_oprf_key_material(oprf_key_id1, epoch1)
        .await?;
    assert_eq!(
        ark_babyjubjub::Fr::from(key_material1.share()),
        ark_babyjubjub::Fr::from(share1)
    );
    assert!(key_material1.is_epoch(epoch1));
    assert_eq!(key_material1.public_key(), public_key1);

    // should be None
    assert!(matches!(
        secret_manager
            .get_oprf_key_material(oprf_key_id1, epoch1.prev())
            .await,
        Err(GetOprfKeyMaterialError::NotFound)
    ));

    Ok(())
}

#[tokio::test]
async fn test_load_all_secret_with_deleted() -> eyre::Result<()> {
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    let secret_manager = postgres_secret_manager(&connection_string).await?;
    let oprf_key_id0 = OprfKeyId::new(U160::from(42));
    let oprf_key_id1 = OprfKeyId::new(U160::from(128));
    let oprf_key_id2 = OprfKeyId::new(U160::from(6891));
    let public_key0 = OprfPublicKey::new(rand::random());
    let public_key1 = OprfPublicKey::new(rand::random());
    let public_key2 = OprfPublicKey::new(rand::random());
    let epoch0 = ShareEpoch::new(42);
    let epoch1 = ShareEpoch::new(32819);
    let epoch2 = ShareEpoch::new(3242);
    let share0 = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    let share1 = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    let share2 = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    let mut conn = oprf_test_utils::open_pg_connection(&connection_string, TEST_SCHEMA).await?;
    insert_row(oprf_key_id0, share0.clone(), epoch0, public_key0, &mut conn).await?;
    insert_row(oprf_key_id1, share1.clone(), epoch1, public_key1, &mut conn).await?;
    insert_row(oprf_key_id2, share2.clone(), epoch2, public_key2, &mut conn).await?;

    delete_row(oprf_key_id1, &mut conn).await?;

    let key_material_store = secret_manager.load_secrets().await?;
    assert_eq!(key_material_store.len(), 2);
    let is_material0 = key_material_store.get(&oprf_key_id0).expect("Must be Some");
    assert!(!key_material_store.contains_key(&oprf_key_id1));
    let is_material2 = key_material_store.get(&oprf_key_id2).expect("Must be Some");
    assert_eq!(is_material0.public_key_with_epoch().key, public_key0);
    assert_eq!(is_material0.public_key_with_epoch().epoch, epoch0);
    assert_eq!(
        ark_babyjubjub::Fr::from(is_material0.share()),
        ark_babyjubjub::Fr::from(share0)
    );
    assert_eq!(is_material2.public_key_with_epoch().key, public_key2);
    assert_eq!(is_material2.public_key_with_epoch().epoch, epoch2);
    assert_eq!(
        ark_babyjubjub::Fr::from(is_material2.share()),
        ark_babyjubjub::Fr::from(share2)
    );
    Ok(())
}

#[tokio::test]
async fn test_get_deleted_secret() -> eyre::Result<()> {
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    let secret_manager = postgres_secret_manager(&connection_string).await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch = ShareEpoch::new(42);
    let share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    let mut conn = oprf_test_utils::open_pg_connection(&connection_string, TEST_SCHEMA).await?;
    insert_row(oprf_key_id, share.clone(), epoch, public_key, &mut conn).await?;

    delete_row(oprf_key_id, &mut conn).await?;

    // this should be an error
    assert!(matches!(
        secret_manager
            .get_oprf_key_material(oprf_key_id, epoch)
            .await,
        Err(GetOprfKeyMaterialError::NotFound)
    ));
    Ok(())
}
