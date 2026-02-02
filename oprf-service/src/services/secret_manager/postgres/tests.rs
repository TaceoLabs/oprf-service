use crate::secret_manager::{SecretManager, postgres::PostgresSecretManager};
use alloy::primitives::U160;
use ark_serialize::CanonicalSerialize;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_test_utils::OPRF_PEER_ADDRESS_0;
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
    let mut pg_connection = oprf_test_utils::open_pg_connection(connection_string).await?;
    sqlx::migrate!("../migrations")
        .run(&mut pg_connection)
        .await?;
    PostgresSecretManager::init(
        &SecretString::from(connection_string.to_owned()),
        "test",
        1.try_into().unwrap(),
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

    let mut conn = oprf_test_utils::open_pg_connection(&connection_string).await?;
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
    let mut conn = oprf_test_utils::open_pg_connection(&connection_string).await?;
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

    let mut conn = oprf_test_utils::open_pg_connection(&connection_string).await?;

    let oprf_key_id0 = OprfKeyId::new(U160::from(42));
    let oprf_key_id1 = OprfKeyId::new(U160::from(128));
    let oprf_key_id2 = OprfKeyId::new(U160::from(6891));
    let oprf_key_id_unknown = OprfKeyId::new(U160::from(32109));
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
    let (session0, _) = key_material_store
        .partial_commit(rand::random(), oprf_key_id0)
        .expect("works");
    assert_eq!(session0.public_key_with_epoch().epoch, epoch0);
    assert_eq!(session0.public_key_with_epoch().key, public_key0);

    let (session1, _) = key_material_store
        .partial_commit(rand::random(), oprf_key_id1)
        .expect("works");
    assert_eq!(session1.public_key_with_epoch().epoch, epoch1);
    assert_eq!(session1.public_key_with_epoch().key, public_key1);

    let (session2, _) = key_material_store
        .partial_commit(rand::random(), oprf_key_id2)
        .expect("works");
    assert_eq!(session2.public_key_with_epoch().epoch, epoch2);
    assert_eq!(session2.public_key_with_epoch().key, public_key2);

    // should no longer work
    assert!(
        key_material_store
            .partial_commit(rand::random(), oprf_key_id_unknown)
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn test_get_oprf_key_material() -> eyre::Result<()> {
    let (_postgres, connection_string) = oprf_test_utils::postgres_testcontainer().await?;
    // runs migrations
    let secret_manager = postgres_secret_manager(&connection_string).await?;

    let mut conn = oprf_test_utils::open_pg_connection(&connection_string).await?;

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
        .await?
        .expect("Should be some");
    assert_eq!(
        ark_babyjubjub::Fr::from(key_material0.share()),
        ark_babyjubjub::Fr::from(share0)
    );
    assert!(key_material0.is_epoch(epoch0));
    assert_eq!(key_material0.public_key(), public_key0);

    // should be None
    assert!(
        secret_manager
            .get_oprf_key_material(oprf_key_id0, epoch1)
            .await?
            .is_none()
    );

    // should be None
    assert!(
        secret_manager
            .get_oprf_key_material(oprf_key_id_unknown, epoch1)
            .await?
            .is_none()
    );

    let key_material1 = secret_manager
        .get_oprf_key_material(oprf_key_id1, epoch1)
        .await?
        .expect("Should be some");
    assert_eq!(
        ark_babyjubjub::Fr::from(key_material1.share()),
        ark_babyjubjub::Fr::from(share1)
    );
    assert!(key_material1.is_epoch(epoch1));
    assert_eq!(key_material1.public_key(), public_key1);

    // should be None
    assert!(
        secret_manager
            .get_oprf_key_material(oprf_key_id1, epoch1.prev())
            .await?
            .is_none()
    );

    Ok(())
}
