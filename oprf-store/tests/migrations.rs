//! Integration tests proving the `storage_format` migration is safe for existing deployments.
#![cfg(feature = "postgres")]

use std::{fmt::Write as _, sync::Arc};

use nodes_common::test_utils::{SharedPostgres, next_test_schema, open_pg_connection};
use sqlx::{PgConnection, Row as _, error::ErrorKind};
use taceo_oprf_store::MIGRATOR;

/// Last migration version before the storage format migration.
const PRE_CHANGE: i64 = 20_260_526_111_425;

/// Returns the container handle too; the container stops once the last handle is dropped.
async fn fresh_connection() -> eyre::Result<(Arc<SharedPostgres>, PgConnection)> {
    let pg = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let schema = next_test_schema();
    let connection = open_pg_connection(&pg.connection_string, &schema).await?;
    Ok((pg, connection))
}

/// A connection migrated exactly to the pre-change schema.
async fn pre_change_connection() -> eyre::Result<(Arc<SharedPostgres>, PgConnection)> {
    let (pg, mut connection) = fresh_connection().await?;
    MIGRATOR.run_to(PRE_CHANGE, &mut connection).await?;
    Ok((pg, connection))
}

/// A connection with all migrations applied.
async fn migrated_connection() -> eyre::Result<(Arc<SharedPostgres>, PgConnection)> {
    let (pg, mut connection) = fresh_connection().await?;
    MIGRATOR.run(&mut connection).await?;
    Ok((pg, connection))
}

/// Inserts the pre-change shape of a share via the released SQL.
async fn insert_old_share(
    connection: &mut PgConnection,
    id: &[u8],
    share: &[u8],
    epoch: i64,
    public_key: &[u8],
) -> eyre::Result<()> {
    sqlx::query("INSERT INTO shares (id, share, epoch, public_key) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(share)
        .bind(epoch)
        .bind(public_key)
        .execute(connection)
        .await?;
    Ok(())
}

/// Inserts the pre-change shape of an in-progress key-gen via the released SQL.
async fn insert_old_keygen(
    connection: &mut PgConnection,
    id: &[u8],
    pending_epoch: i64,
    intermediates: &[u8],
) -> eyre::Result<()> {
    sqlx::query(
        "INSERT INTO in_progress_keygens (id, pending_epoch, intermediates) VALUES ($1, $2, $3)",
    )
    .bind(id)
    .bind(pending_epoch)
    .bind(intermediates)
    .execute(connection)
    .await?;
    Ok(())
}

/// Inserts a data key and returns its id as text.
async fn insert_data_key(connection: &mut PgConnection) -> eyre::Result<String> {
    let id: String = sqlx::query_scalar(
        "INSERT INTO data_keys (id, wrapped_key, wrapping, kms_key_arn) \
         VALUES (md5(random()::text)::uuid, $1, 'awsKms', 'arn:aws:kms:test') RETURNING id::text",
    )
    .bind(&[9_u8, 9, 9][..])
    .fetch_one(connection)
    .await?;
    Ok(id)
}

/// Returns the database error kind and constraint name of a failed query.
fn violation<T>(result: Result<T, sqlx::Error>) -> (ErrorKind, Option<String>) {
    match result {
        Err(sqlx::Error::Database(e)) => (e.kind(), e.constraint().map(str::to_owned)),
        Err(other) => panic!("expected a database error, got {other:?}"),
        Ok(_) => panic!("expected the statement to fail"),
    }
}

async fn column_exists(
    connection: &mut PgConnection,
    table: &str,
    column: &str,
) -> eyre::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2)",
    )
    .bind(table)
    .bind(column)
    .fetch_one(connection)
    .await?)
}

async fn table_exists(connection: &mut PgConnection, table: &str) -> eyre::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name = $1)",
    )
    .bind(table)
    .fetch_one(connection)
    .await?)
}

/// Expected values of a migrated share: id, share, epoch, public key and deleted flag.
type ExpectedShare<'a> = (&'a [u8], Option<&'a [u8]>, i64, &'a [u8], bool);

/// Asserts a share row kept its pre-migration values and became `direct`.
fn assert_migrated_share(row: &sqlx::postgres::PgRow, expected: ExpectedShare<'_>) {
    let (id, share, epoch, public_key, deleted) = expected;
    assert_eq!(row.get::<Vec<u8>, _>("id"), id, "share id unchanged");
    assert_eq!(
        row.get::<Option<Vec<u8>>, _>("share").as_deref(),
        share,
        "share bytes unchanged"
    );
    assert_eq!(row.get::<i64, _>("epoch"), epoch, "share epoch unchanged");
    assert_eq!(
        row.get::<Vec<u8>, _>("public_key"),
        public_key,
        "public key unchanged"
    );
    assert_eq!(row.get::<bool, _>("deleted"), deleted, "deleted unchanged");
    assert_eq!(
        row.get::<String, _>("storage_format"),
        "direct",
        "share becomes direct"
    );
    assert_eq!(
        row.get::<Option<String>, _>("data_key_id"),
        None,
        "share has no data key"
    );
}

#[tokio::test]
async fn existing_rows_become_direct() -> eyre::Result<()> {
    let (_pg, mut connection) = pre_change_connection().await?;

    insert_old_share(&mut connection, &[1], &[10, 11], 3, &[20, 21]).await?;
    sqlx::query(
        "INSERT INTO shares (id, share, epoch, public_key, deleted) VALUES ($1, NULL, $2, $3, true)",
    )
    .bind(&[2_u8][..])
    .bind(4_i64)
    .bind(&[22_u8, 23][..])
    .execute(&mut connection)
    .await?;
    sqlx::query(
        "INSERT INTO in_progress_keygens (id, pending_epoch, pending_share, intermediates) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&[3_u8][..])
    .bind(5_i64)
    .bind(&[30_u8, 31][..])
    .bind(&[40_u8, 41][..])
    .execute(&mut connection)
    .await?;

    MIGRATOR.run(&mut connection).await?;

    let shares = sqlx::query(
        "SELECT id, share, epoch, public_key, deleted, storage_format, data_key_id::text AS data_key_id \
         FROM shares ORDER BY id",
    )
    .fetch_all(&mut connection)
    .await?;
    assert_eq!(shares.len(), 2, "both shares survive the migration");

    assert_migrated_share(&shares[0], (&[1], Some(&[10, 11]), 3, &[20, 21], false));
    assert_migrated_share(&shares[1], (&[2], None, 4, &[22, 23], true));

    let keygen = sqlx::query(
        "SELECT id, pending_epoch, pending_share, intermediates, storage_format, \
         data_key_id::text AS data_key_id FROM in_progress_keygens",
    )
    .fetch_one(&mut connection)
    .await?;
    assert_eq!(keygen.get::<Vec<u8>, _>("id"), vec![3], "keygen id");
    assert_eq!(keygen.get::<i64, _>("pending_epoch"), 5, "keygen epoch");
    assert_eq!(
        keygen.get::<Option<Vec<u8>>, _>("pending_share"),
        Some(vec![30, 31]),
        "pending share unchanged"
    );
    assert_eq!(
        keygen.get::<Vec<u8>, _>("intermediates"),
        vec![40, 41],
        "intermediates unchanged"
    );
    assert_eq!(
        keygen.get::<String, _>("storage_format"),
        "direct",
        "keygen becomes direct"
    );
    assert_eq!(
        keygen.get::<Option<String>, _>("data_key_id"),
        None,
        "keygen has no data key"
    );
    Ok(())
}

#[tokio::test]
async fn old_node_queries_still_work() -> eyre::Result<()> {
    let (_pg, mut connection) = migrated_connection().await?;
    insert_old_share(&mut connection, &[7], &[1, 2, 3], 9, &[4, 5, 6]).await?;
    sqlx::query(
        "INSERT INTO node_information (eth_address, party_id, threshold) VALUES ($1, $2, $3)",
    )
    .bind("0xabc")
    .bind(2_i32)
    .bind(3_i32)
    .execute(&mut connection)
    .await?;

    let row = sqlx::query("SELECT id, share, epoch, deleted, public_key FROM shares WHERE id = $1")
        .bind(&[7_u8][..])
        .fetch_one(&mut connection)
        .await?;
    assert_eq!(row.get::<Vec<u8>, _>("id"), vec![7], "id");
    assert_eq!(
        row.get::<Option<Vec<u8>>, _>("share"),
        Some(vec![1, 2, 3]),
        "share"
    );
    assert_eq!(row.get::<i64, _>("epoch"), 9, "epoch");
    assert!(!row.get::<bool, _>("deleted"), "deleted");
    assert_eq!(
        row.get::<Vec<u8>, _>("public_key"),
        vec![4, 5, 6],
        "public key"
    );

    let info =
        sqlx::query("SELECT eth_address,party_id,threshold FROM node_information WHERE id = TRUE")
            .fetch_one(&mut connection)
            .await?;
    assert_eq!(info.get::<String, _>("eth_address"), "0xabc", "eth address");
    assert_eq!(info.get::<i32, _>("party_id"), 2, "party id");
    assert_eq!(info.get::<i32, _>("threshold"), 3, "threshold");
    Ok(())
}

#[tokio::test]
async fn old_keygen_writes_still_work() -> eyre::Result<()> {
    let (_pg, mut connection) = migrated_connection().await?;
    insert_old_share(&mut connection, &[1], &[1, 2], 1, &[3, 4]).await?;
    insert_old_keygen(&mut connection, &[2], 2, &[5, 6]).await?;

    for table in ["shares", "in_progress_keygens"] {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT storage_format, data_key_id::text AS data_key_id FROM {table}"
        )))
        .fetch_one(&mut connection)
        .await?;
        assert_eq!(
            row.get::<String, _>("storage_format"),
            "direct",
            "old write into {table} is direct"
        );
        assert_eq!(
            row.get::<Option<String>, _>("data_key_id"),
            None,
            "old write into {table} has no data key"
        );
    }
    Ok(())
}

#[tokio::test]
async fn format_check_rejects_unknown_value() -> eyre::Result<()> {
    let (_pg, mut connection) = migrated_connection().await?;
    insert_old_share(&mut connection, &[1], &[1, 2], 1, &[3, 4]).await?;
    insert_old_keygen(&mut connection, &[2], 2, &[5, 6]).await?;

    for (table, constraint) in [
        ("shares", "shares_storage_format_check"),
        (
            "in_progress_keygens",
            "in_progress_keygens_storage_format_check",
        ),
    ] {
        let result = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE {table} SET storage_format = 'bogus'"
        )))
        .execute(&mut connection)
        .await;
        let (kind, name) = violation(result);
        assert_eq!(kind, ErrorKind::CheckViolation, "{table}: error kind");
        assert_eq!(name.as_deref(), Some(constraint), "{table}: constraint");
    }
    Ok(())
}

#[tokio::test]
async fn data_key_must_match_format() -> eyre::Result<()> {
    let (_pg, mut connection) = migrated_connection().await?;
    let data_key = insert_data_key(&mut connection).await?;
    insert_old_share(&mut connection, &[1], &[1, 2], 1, &[3, 4]).await?;
    insert_old_keygen(&mut connection, &[2], 2, &[5, 6]).await?;

    check_data_key_rules(
        &mut connection,
        &data_key,
        "shares",
        "shares_data_key_matches_format",
        "shares_data_key_id_fkey",
    )
    .await?;
    check_data_key_rules(
        &mut connection,
        &data_key,
        "in_progress_keygens",
        "in_progress_keygens_data_key_matches_format",
        "in_progress_keygens_data_key_id_fkey",
    )
    .await
}

/// Exercises the data key rules on the single row of `table`.
async fn check_data_key_rules(
    connection: &mut PgConnection,
    data_key: &str,
    table: &str,
    match_constraint: &str,
    fk_constraint: &str,
) -> eyre::Result<()> {
    // envelopeV1 without a data key
    let result = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE {table} SET storage_format = 'envelopeV1'"
    )))
    .execute(&mut *connection)
    .await;
    let (kind, name) = violation(result);
    assert_eq!(
        kind,
        ErrorKind::CheckViolation,
        "{table}: envelopeV1 without key kind"
    );
    assert_eq!(
        name.as_deref(),
        Some(match_constraint),
        "{table}: envelopeV1 without key constraint"
    );

    // direct with a data key
    let result = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE {table} SET data_key_id = $1::uuid"
    )))
    .bind(data_key)
    .execute(&mut *connection)
    .await;
    let (kind, name) = violation(result);
    assert_eq!(
        kind,
        ErrorKind::CheckViolation,
        "{table}: direct with key kind"
    );
    assert_eq!(
        name.as_deref(),
        Some(match_constraint),
        "{table}: direct with key constraint"
    );

    // unknown data key
    let result = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE {table} SET storage_format = 'envelopeV1', data_key_id = md5(random()::text)::uuid"
    )))
    .execute(&mut *connection)
    .await;
    let (kind, name) = violation(result);
    assert_eq!(
        kind,
        ErrorKind::ForeignKeyViolation,
        "{table}: unknown key kind"
    );
    assert_eq!(
        name.as_deref(),
        Some(fk_constraint),
        "{table}: unknown key constraint"
    );

    // envelopeV1 with an existing data key
    let updated = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE {table} SET storage_format = 'envelopeV1', data_key_id = $1::uuid"
    )))
    .bind(data_key)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    assert_eq!(updated, 1, "{table}: valid envelope row accepted");

    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT storage_format, data_key_id::text AS data_key_id FROM {table}"
    )))
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(
        row.get::<String, _>("storage_format"),
        "envelopeV1",
        "{table}: format stored"
    );
    assert_eq!(
        row.get::<Option<String>, _>("data_key_id"),
        Some(data_key.to_owned()),
        "{table}: data key stored"
    );
    Ok(())
}

#[tokio::test]
async fn down_migration_restores_previous_schema() -> eyre::Result<()> {
    let (_pg, mut connection) = migrated_connection().await?;
    assert!(
        table_exists(&mut connection, "data_keys").await?,
        "data_keys exists after up"
    );

    MIGRATOR.undo(&mut connection, PRE_CHANGE).await?;

    assert!(
        !table_exists(&mut connection, "data_keys").await?,
        "data_keys is dropped"
    );
    for table in ["shares", "in_progress_keygens"] {
        for column in ["storage_format", "data_key_id"] {
            assert!(
                !column_exists(&mut connection, table, column).await?,
                "{table}.{column} is dropped"
            );
        }
    }
    assert!(
        table_exists(&mut connection, "node_information").await?,
        "earlier migrations stay applied"
    );

    insert_old_share(&mut connection, &[1], &[1, 2], 1, &[3, 4]).await?;
    insert_old_keygen(&mut connection, &[2], 2, &[5, 6]).await?;
    let shares: i64 = sqlx::query_scalar("SELECT count(*) FROM shares")
        .fetch_one(&mut connection)
        .await?;
    let keygens: i64 = sqlx::query_scalar("SELECT count(*) FROM in_progress_keygens")
        .fetch_one(&mut connection)
        .await?;
    assert_eq!(shares, 1, "pre-change share insert works");
    assert_eq!(keygens, 1, "pre-change keygen insert works");
    Ok(())
}

/// Version of the storage format migration.
const STORAGE_FORMAT: i64 = 20_261_111_000_000;

/// Runs the down migration, expects it to be refused, and asserts the schema and data survived.
async fn assert_down_migration_refused(
    connection: &mut PgConnection,
    shares: i64,
    data_keys: i64,
) -> eyre::Result<()> {
    let err = MIGRATOR
        .undo(&mut *connection, PRE_CHANGE)
        .await
        .expect_err("down migration must be refused");
    assert!(
        err.to_string().contains("refusing to undo"),
        "down migration must fail with the guard message, got {err}"
    );

    assert!(
        table_exists(connection, "data_keys").await?,
        "data_keys is kept"
    );
    for table in ["shares", "in_progress_keygens"] {
        for column in ["storage_format", "data_key_id"] {
            assert!(
                column_exists(connection, table, column).await?,
                "{table}.{column} is kept"
            );
        }
    }
    let applied: i64 =
        sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE version = $1")
            .bind(STORAGE_FORMAT)
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(applied, 1, "storage format migration stays applied");
    let share_count: i64 = sqlx::query_scalar("SELECT count(*) FROM shares")
        .fetch_one(&mut *connection)
        .await?;
    let data_key_count: i64 = sqlx::query_scalar("SELECT count(*) FROM data_keys")
        .fetch_one(&mut *connection)
        .await?;
    assert_eq!(share_count, shares, "shares are kept");
    assert_eq!(data_key_count, data_keys, "data keys are kept");
    Ok(())
}

#[tokio::test]
async fn down_migration_refused_with_envelope_share() -> eyre::Result<()> {
    let (_pg, mut connection) = migrated_connection().await?;
    let data_key = insert_data_key(&mut connection).await?;
    insert_old_share(&mut connection, &[1], &[1, 2], 1, &[3, 4]).await?;
    sqlx::query("UPDATE shares SET storage_format = 'envelopeV1', data_key_id = $1::uuid")
        .bind(&data_key)
        .execute(&mut connection)
        .await?;

    assert_down_migration_refused(&mut connection, 1, 1).await?;
    let format: String = sqlx::query_scalar("SELECT storage_format FROM shares")
        .fetch_one(&mut connection)
        .await?;
    assert_eq!(format, "envelopeV1", "envelope share is kept");
    Ok(())
}

#[tokio::test]
async fn down_migration_refused_with_data_key_only() -> eyre::Result<()> {
    let (_pg, mut connection) = migrated_connection().await?;
    insert_data_key(&mut connection).await?;

    assert_down_migration_refused(&mut connection, 0, 1).await
}

#[test]
fn moved_migrations_keep_their_checksums() {
    let expected: [(i64, &str); 4] = [
        (
            20_260_128_092_844,
            "b72b4433645ddd68158e400af5bb83111d900e269c4aac30aa12a367ee8862309d823d8be49aaeac7f9b5fbe74ddc53f",
        ),
        (
            20_260_416_133_133,
            "f3d8183b6272f8eedb709a9cce0cb30591d236cb1541aa48b0478832bbd0d85ea7220e95356523e1776c6ec230394362",
        ),
        (
            20_260_428_072_903,
            "8252fa289f70a6e71a5e9f82f016e5773c128d61a3aa9539cb4347578ace6547f236127090bcc70e524e01d6b81d59c7",
        ),
        (
            20_260_526_111_425,
            "4c0006cf5688eefb417c5eea8b35d268bc3b2024733716408f1a9c1507a7729f792f7ddcd30b3a8d71ae4d4a2002b51d",
        ),
    ];
    for (version, checksum) in expected {
        let migration = MIGRATOR
            .iter()
            .find(|m| m.version == version && m.migration_type.is_up_migration())
            .unwrap_or_else(|| panic!("up migration {version} is embedded"));
        let hex = migration
            .checksum
            .iter()
            .fold(String::new(), |mut acc, byte| {
                write!(acc, "{byte:02x}").expect("writing to a String cannot fail");
                acc
            });
        assert_eq!(hex, checksum, "checksum of migration {version} changed");
    }
}
