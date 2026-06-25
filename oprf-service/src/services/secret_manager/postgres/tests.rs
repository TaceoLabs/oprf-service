use std::num::NonZeroU16;

use crate::secret_manager::{SecretManager, SecretManagerError, postgres::PostgresSecretManager};
use ark_serialize::CanonicalSerialize;
use nodes_common::postgres::{PostgresConfig, SanitizedSchema};
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_test_utils::OPRF_PEER_ADDRESS_0;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    crypto::{OprfPublicKey, PartyId},
    service::NodeInformation,
};
use ruint::aliases::U160;
use secrecy::SecretString;
use sqlx::PgConnection;

#[inline]
fn to_db_ark_serialize_uncompressed<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(t.uncompressed_size());
    t.serialize_uncompressed(&mut bytes).expect("Can serialize");
    bytes
}

async fn postgres_secret_manager()
-> eyre::Result<(PostgresSecretManager, &'static str, SanitizedSchema)> {
    let conn = oprf_test_utils::shared_postgres_testcontainer().await?;
    let schema = oprf_test_utils::next_test_schema();
    let mut pg_connection = oprf_test_utils::open_pg_connection(conn, &schema.to_string()).await?;
    sqlx::migrate!("../oprf-key-gen/migrations")
        .run(&mut pg_connection)
        .await?;
    let mgr = PostgresSecretManager::init(&PostgresConfig::with_default_values(
        SecretString::from(conn.to_owned()),
        schema.clone(),
    ))
    .await?;
    Ok((mgr, conn, schema))
}

async fn insert_row(
    oprf_key_id: OprfKeyId,
    share: DLogShareShamir,
    epoch: ShareEpoch,
    public_key: OprfPublicKey,
    connection: &mut PgConnection,
) -> eyre::Result<()> {
    sqlx::query(
        "
            INSERT INTO shares (id, share, epoch, public_key)
            VALUES ($1, $2, $3, $4)
        ",
    )
    .bind(oprf_key_id.to_le_bytes())
    .bind(to_db_ark_serialize_uncompressed(&share))
    .bind(i64::from(epoch.into_inner()))
    .bind(to_db_ark_serialize_uncompressed(&public_key))
    .execute(connection)
    .await?;
    Ok(())
}

async fn delete_row(oprf_key_id: OprfKeyId, connection: &mut PgConnection) -> eyre::Result<()> {
    let success = sqlx::query(
        "
            UPDATE shares
            SET
                share = NULL,
                deleted = true
            WHERE id = $1
        ",
    )
    .bind(oprf_key_id.to_le_bytes())
    .execute(connection)
    .await?;
    assert!(success.rows_affected() == 1);
    Ok(())
}

async fn insert_node_information(
    eth_address: &str,
    party_id: i32,
    threshold: u16,
    connection: &mut PgConnection,
) -> eyre::Result<()> {
    sqlx::query(
        "
            INSERT INTO node_information (id, eth_address, party_id, threshold)
            VALUES (TRUE, $1, $2, $3)
        ",
    )
    .bind(eth_address)
    .bind(party_id)
    .bind(i32::from(threshold))
    .execute(connection)
    .await?;
    Ok(())
}

#[tokio::test]
async fn load_node_information_empty() -> eyre::Result<()> {
    let (secret_manager, _, _) = postgres_secret_manager().await?;
    let report = secret_manager
        .load_node_information()
        .await
        .expect_err("should be an error");
    assert_eq!(
        report.to_string(),
        "Cannot get node information from DB, maybe key-gen needs to start"
    );
    Ok(())
}

#[tokio::test]
async fn load_node_information_success() -> eyre::Result<()> {
    let (secret_manager, connection_string, schema) = postgres_secret_manager().await?;

    let should_address = OPRF_PEER_ADDRESS_0;
    let should_party_id = PartyId(42);
    let should_threshold = 2;
    let mut conn =
        oprf_test_utils::open_pg_connection(connection_string, &schema.to_string()).await?;
    insert_node_information(
        &should_address.to_string(),
        i32::from(should_party_id.into_inner()),
        should_threshold,
        &mut conn,
    )
    .await?;

    let is_node_information = secret_manager
        .load_node_information()
        .await
        .expect("Should work");
    assert_eq!(
        is_node_information,
        NodeInformation::new(
            should_party_id,
            should_address.to_string(),
            NonZeroU16::try_from(should_threshold).expect("is non-zero")
        )
    );
    Ok(())
}

#[tokio::test]
async fn test_get_oprf_key_material() -> eyre::Result<()> {
    let (secret_manager, connection_string, schema) = postgres_secret_manager().await?;
    let mut conn =
        oprf_test_utils::open_pg_connection(connection_string, &schema.to_string()).await?;

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

    let key_material0 = secret_manager.get_oprf_key_material(oprf_key_id0).await?;
    assert_eq!(
        ark_babyjubjub::Fr::from(key_material0.share()),
        ark_babyjubjub::Fr::from(share0)
    );
    assert!(key_material0.is_epoch(epoch0));
    assert_eq!(key_material0.public_key(), public_key0);

    // unknown key id should return UnknownOprfKeyId
    assert!(matches!(
        secret_manager
            .get_oprf_key_material(oprf_key_id_unknown)
            .await,
        Err(SecretManagerError::UnknownOprfKeyId(_))
    ));

    let key_material1 = secret_manager.get_oprf_key_material(oprf_key_id1).await?;
    assert_eq!(
        ark_babyjubjub::Fr::from(key_material1.share()),
        ark_babyjubjub::Fr::from(share1)
    );
    assert!(key_material1.is_epoch(epoch1));
    assert_eq!(key_material1.public_key(), public_key1);

    Ok(())
}

#[tokio::test]
async fn test_get_deleted_secret() -> eyre::Result<()> {
    let (secret_manager, connection_string, schema) = postgres_secret_manager().await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch = ShareEpoch::new(42);
    let share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    let mut conn =
        oprf_test_utils::open_pg_connection(connection_string, &schema.to_string()).await?;
    insert_row(oprf_key_id, share.clone(), epoch, public_key, &mut conn).await?;

    delete_row(oprf_key_id, &mut conn).await?;

    let err = secret_manager
        .get_oprf_key_material(oprf_key_id)
        .await
        .expect_err("should fail with deleted");
    // deleted key should return DeletedOprfKeyId
    assert!(
        matches!(err, SecretManagerError::DeletedOprfKeyId(is_key_id) if is_key_id == oprf_key_id),
        "should be Err(DeletedOprfKeyId({oprf_key_id})) but is {err}"
    );
    Ok(())
}
