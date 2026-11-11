use ark_babyjubjub::Fr;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::crypto::OprfPublicKey;

use crate::{StoreError, codec};

#[test]
fn codec_round_trip() {
    let share = DLogShareShamir::from(rand::random::<Fr>());
    let public_key = OprfPublicKey::new(rand::random());

    let share_back: DLogShareShamir =
        codec::from_bytes(&codec::to_bytes(&share)).expect("share decodes");
    let public_key_back: OprfPublicKey =
        codec::from_bytes(&codec::to_bytes(&public_key)).expect("public key decodes");

    assert_eq!(
        Fr::from(share),
        Fr::from(share_back),
        "share must survive round trip"
    );
    assert_eq!(
        public_key, public_key_back,
        "public key must survive round trip"
    );
}

#[test]
fn codec_corrupt_bytes_are_an_error() {
    assert!(
        matches!(
            codec::from_bytes::<OprfPublicKey>(&[]),
            Err(StoreError::Corrupt(_))
        ),
        "empty slice must be corrupt"
    );
    assert!(
        matches!(
            codec::from_bytes::<OprfPublicKey>(&[0xFF; 64]),
            Err(StoreError::Corrupt(_))
        ),
        "invalid point must be corrupt"
    );
}

#[test]
fn codec_trailing_bytes_are_an_error() {
    let share = DLogShareShamir::from(rand::random::<Fr>());
    let public_key = OprfPublicKey::new(rand::random());

    let mut share_bytes = codec::to_bytes(&share).to_vec();
    let mut public_key_bytes = codec::to_bytes(&public_key).to_vec();
    share_bytes.push(0);
    public_key_bytes.push(0);
    assert!(
        matches!(
            codec::from_bytes::<DLogShareShamir>(&share_bytes),
            Err(StoreError::Corrupt(_))
        ),
        "share with a trailing byte must be corrupt"
    );
    assert!(
        matches!(
            codec::from_bytes::<OprfPublicKey>(&public_key_bytes),
            Err(StoreError::Corrupt(_))
        ),
        "public key with a trailing byte must be corrupt"
    );
}

#[test]
fn codec_from_vec() {
    let share = DLogShareShamir::from(rand::random::<Fr>());
    let share_back: DLogShareShamir =
        codec::from_vec(codec::to_bytes(&share).to_vec()).expect("share decodes");
    assert_eq!(
        Fr::from(share_back),
        Fr::from(share),
        "share must survive round trip"
    );
}

#[cfg(feature = "postgres")]
mod postgres {
    mod with_retry {
        use std::{
            num::NonZeroUsize,
            sync::atomic::{AtomicUsize, Ordering},
            time::Duration,
        };

        use crate::retry;

        fn backoff(max_retries: usize) -> backon::ConstantBackoff {
            retry::backoff(
                NonZeroUsize::new(max_retries).expect("nonzero"),
                Duration::ZERO,
            )
        }

        #[tokio::test]
        async fn retries_up_to_max_and_returns_last_error() {
            let calls = AtomicUsize::new(0);
            let res: Result<(), String> = retry::with_retry(
                "test-op",
                backoff(3),
                |_| true,
                || async {
                    let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                    Err(format!("attempt {n}"))
                },
            )
            .await;
            assert_eq!(
                calls.load(Ordering::SeqCst),
                4,
                "one attempt plus three retries"
            );
            assert_eq!(res, Err("attempt 4".to_owned()), "last error is returned");
        }

        #[tokio::test]
        async fn does_not_retry_when_predicate_is_false() {
            let calls = AtomicUsize::new(0);
            let res: Result<(), sqlx::Error> =
                retry::with_retry("test-op", backoff(3), retry::is_transient, || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(sqlx::Error::RowNotFound)
                })
                .await;
            assert_eq!(calls.load(Ordering::SeqCst), 1, "no retry");
            assert!(
                matches!(res, Err(sqlx::Error::RowNotFound)),
                "error is returned"
            );
        }
    }

    #[cfg(feature = "test-utils")]
    mod shares_table {
        use std::num::NonZeroU16;

        use alloy::primitives::Address;
        use ark_babyjubjub::Fr;
        use oprf_core::ddlog_equality::shamir::DLogShareShamir;
        use oprf_types::{
            OprfKeyId, ShareEpoch,
            crypto::{OprfPublicKey, PartyId},
        };
        use ruint::aliases::U160;

        use crate::{
            Dek, EnvelopeError, InMemoryWrapper, MIGRATOR, StorageCrypto, StoreError,
            aad::AadContext, data_keys, format::StorageFormat, shares, test_utils,
        };

        /// Returns the container handle too; the container stops once the last handle is dropped.
        async fn migrated_connection() -> eyre::Result<(
            std::sync::Arc<nodes_common::test_utils::SharedPostgres>,
            sqlx::PgConnection,
        )> {
            let pg = nodes_common::test_utils::shared_postgres_testcontainer().await?;
            let schema = nodes_common::test_utils::next_test_schema();
            let mut connection =
                nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema)
                    .await?;
            MIGRATOR.run(&mut connection).await?;
            Ok((pg, connection))
        }

        fn random_key() -> (OprfKeyId, DLogShareShamir, OprfPublicKey) {
            (
                OprfKeyId::new(U160::from(rand::random::<u128>())),
                DLogShareShamir::from(rand::random::<Fr>()),
                OprfPublicKey::new(rand::random()),
            )
        }

        #[tokio::test]
        async fn share_row_debug_does_not_leak_share() -> eyre::Result<()> {
            let (_pg, mut connection) = migrated_connection().await?;
            let (id, share, public_key) = random_key();
            test_utils::insert_share(&mut connection, id, ShareEpoch::new(7), &share, &public_key)
                .await?;
            let row = shares::fetch(&mut connection, id)
                .await?
                .expect("row exists");

            let debug = format!("{row:?}");
            let share_bytes = crate::codec::to_bytes(&share);
            assert!(
                !debug.contains(&format!("{:?}", share_bytes.as_slice())),
                "debug output must not contain the share bytes"
            );
            assert!(debug.contains("epoch: 7"), "debug output must show epoch");
            Ok(())
        }

        #[tokio::test]
        async fn deleted_row_is_flagged_and_does_not_open() -> eyre::Result<()> {
            let (_pg, mut connection) = migrated_connection().await?;
            let (id, share, public_key) = random_key();
            test_utils::insert_share(&mut connection, id, ShareEpoch::new(1), &share, &public_key)
                .await?;
            sqlx::query("UPDATE shares SET share = NULL, deleted = true WHERE id = $1")
                .bind(id.to_le_bytes())
                .execute(&mut connection)
                .await?;

            let row = shares::fetch(&mut connection, id)
                .await?
                .expect("row exists");
            assert!(row.is_deleted(), "row must be flagged deleted");
            assert!(
                matches!(row.open(&direct_only()), Err(StoreError::Corrupt(_))),
                "deleted row must not open"
            );
            Ok(())
        }

        #[tokio::test]
        async fn epoch_out_of_range_is_corrupt() -> eyre::Result<()> {
            let (_pg, mut connection) = migrated_connection().await?;
            let (id, share, public_key) = random_key();
            test_utils::insert_share(&mut connection, id, ShareEpoch::new(1), &share, &public_key)
                .await?;
            sqlx::query("UPDATE shares SET epoch = 4294967296 WHERE id = $1")
                .bind(id.to_le_bytes())
                .execute(&mut connection)
                .await?;

            let row = shares::fetch(&mut connection, id)
                .await?
                .expect("row exists");
            assert!(
                matches!(row.epoch(), Err(StoreError::Corrupt(_))),
                "epoch outside u32 must be corrupt"
            );
            Ok(())
        }

        #[tokio::test]
        async fn corrupt_share_bytes_are_an_error() -> eyre::Result<()> {
            let (_pg, mut connection) = migrated_connection().await?;
            let (id, share, public_key) = random_key();
            test_utils::insert_share(&mut connection, id, ShareEpoch::new(1), &share, &public_key)
                .await?;
            sqlx::query("UPDATE shares SET share = $2 WHERE id = $1")
                .bind(id.to_le_bytes())
                .bind(&[0xFF_u8; 3][..])
                .execute(&mut connection)
                .await?;

            let row = shares::fetch(&mut connection, id)
                .await?
                .expect("row exists");
            assert!(
                matches!(row.open(&direct_only()), Err(StoreError::Corrupt(_))),
                "invalid share bytes must be corrupt"
            );
            Ok(())
        }

        fn crypto(allowed: &[StorageFormat], deks: Vec<Dek>) -> StorageCrypto {
            StorageCrypto::new(
                allowed,
                AadContext {
                    chain_id: 31337,
                    registry: Address::from([0xAA; 20]),
                    party_id: PartyId(1),
                    threshold: NonZeroU16::new(2).expect("nonzero"),
                },
                deks,
            )
        }

        /// A read-only policy that only allows `direct`.
        fn direct_only() -> StorageCrypto {
            crypto(&[StorageFormat::Direct], vec![])
        }

        fn assert_opens_to(
            row: &shares::ShareRow,
            crypto: &StorageCrypto,
            id: OprfKeyId,
            epoch: ShareEpoch,
            share: &DLogShareShamir,
            public_key: &OprfPublicKey,
        ) -> eyre::Result<()> {
            let stored = row.open(crypto)?;
            assert_eq!(stored.oprf_key_id, id, "id must match");
            assert_eq!(stored.epoch, epoch, "epoch must match");
            assert_eq!(stored.public_key, *public_key, "public key must match");
            assert_eq!(
                Fr::from(stored.share),
                Fr::from(share.clone()),
                "share must match"
            );
            Ok(())
        }

        #[tokio::test]
        async fn open_direct_row() -> eyre::Result<()> {
            let (_pg, mut connection) = migrated_connection().await?;
            let (id, share, public_key) = random_key();
            let epoch = ShareEpoch::new(7);
            test_utils::insert_share(&mut connection, id, epoch, &share, &public_key).await?;

            let row = shares::fetch(&mut connection, id)
                .await?
                .expect("row exists");
            assert!(!row.is_deleted(), "row must be live");
            assert_eq!(row.epoch()?, epoch, "epoch must match");
            assert_eq!(row.data_key_id(), None, "direct row has no data key");
            let crypto = direct_only();
            assert_opens_to(&row, &crypto, id, epoch, &share, &public_key)
        }

        #[tokio::test]
        async fn open_envelope_row() -> eyre::Result<()> {
            let (_pg, mut connection) = migrated_connection().await?;
            let wrapper = InMemoryWrapper::new("arn:test:key", [1; 32]);
            let dek = data_keys::create(&mut connection, &wrapper).await?;
            let dek_id = dek.id();
            let crypto = crypto(&[StorageFormat::EnvelopeV1], vec![dek])
                .with_write(StorageFormat::EnvelopeV1, Some(dek_id))?;
            let (id, share, public_key) = random_key();
            let epoch = ShareEpoch::new(7);
            test_utils::insert_share_sealed(
                &mut connection,
                &crypto,
                id,
                epoch,
                &share,
                &public_key,
            )
            .await?;

            let row = shares::fetch(&mut connection, id)
                .await?
                .expect("row exists");
            assert_eq!(row.data_key_id(), Some(dek_id), "row names its data key");
            assert_opens_to(&row, &crypto, id, epoch, &share, &public_key)
        }

        #[tokio::test]
        async fn open_rejects_disallowed_format() -> eyre::Result<()> {
            let (_pg, mut connection) = migrated_connection().await?;
            let (id, share, public_key) = random_key();
            test_utils::insert_share(&mut connection, id, ShareEpoch::new(7), &share, &public_key)
                .await?;

            let row = shares::fetch(&mut connection, id)
                .await?
                .expect("row exists");
            let err = row
                .open(&crypto(&[StorageFormat::EnvelopeV1], vec![]))
                .expect_err("direct is not allowed");
            assert!(
                matches!(
                    err,
                    StoreError::Envelope(EnvelopeError::FormatNotAllowed(StorageFormat::Direct))
                ),
                "expected FormatNotAllowed(Direct), got {err:?}"
            );
            Ok(())
        }

        #[tokio::test]
        async fn envelope_row_is_refused_by_direct_only_policy() -> eyre::Result<()> {
            let (_pg, mut connection) = migrated_connection().await?;
            let (envelope_id, share, public_key) = random_key();
            test_utils::insert_share(
                &mut connection,
                envelope_id,
                ShareEpoch::new(1),
                &share,
                &public_key,
            )
            .await?;
            // The share bytes stay a valid plaintext share; only the format column changes.
            let data_key_id: uuid::Uuid = sqlx::query_scalar(
                "INSERT INTO data_keys (id, wrapped_key, wrapping, kms_key_arn) \
                 VALUES (md5(random()::text)::uuid, $1, 'awsKms', 'arn:test:key') RETURNING id",
            )
            .bind(&[9_u8, 9, 9][..])
            .fetch_one(&mut connection)
            .await?;
            sqlx::query(
                "UPDATE shares SET storage_format = 'envelopeV1', data_key_id = $2 WHERE id = $1",
            )
            .bind(envelope_id.to_le_bytes())
            .bind(data_key_id)
            .execute(&mut connection)
            .await?;

            let row = shares::fetch(&mut connection, envelope_id)
                .await?
                .expect("row exists");
            let err = row
                .open(&direct_only())
                .expect_err("envelopeV1 row must not open with a direct-only policy");
            assert!(
                matches!(
                    err,
                    StoreError::Envelope(EnvelopeError::FormatNotAllowed(
                        StorageFormat::EnvelopeV1
                    ))
                ),
                "expected FormatNotAllowed(EnvelopeV1), got {err:?}"
            );
            Ok(())
        }
    }

    #[cfg(feature = "test-utils")]
    mod data_keys_table {
        use sqlx::postgres::PgPoolOptions;
        use uuid::Uuid;

        use crate::{
            Dek, InMemoryWrapper, MIGRATOR,
            data_keys::{self, DataKeyError},
        };

        const ARN: &str = "arn:test:key";

        /// Returns the container handle too; the container stops once the last handle is dropped.
        async fn migrated_pool() -> eyre::Result<(
            std::sync::Arc<nodes_common::test_utils::SharedPostgres>,
            sqlx::PgPool,
        )> {
            let pg = nodes_common::test_utils::shared_postgres_testcontainer().await?;
            let schema = nodes_common::test_utils::next_test_schema();
            let mut connection =
                nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema)
                    .await?;
            MIGRATOR.run(&mut connection).await?;
            let search_path = format!("SET search_path TO \"{schema}\"");
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .after_connect(move |conn, _meta| {
                    let search_path = search_path.clone();
                    Box::pin(async move {
                        sqlx::query(sqlx::AssertSqlSafe(search_path))
                            .execute(conn)
                            .await?;
                        Ok(())
                    })
                })
                .connect(&pg.connection_string)
                .await?;
            Ok((pg, pool))
        }

        #[tokio::test]
        async fn create_then_load_all() -> eyre::Result<()> {
            let (_pg, pool) = migrated_pool().await?;
            let wrapper = InMemoryWrapper::new(ARN, [1; 32]);
            let created = data_keys::create(&pool, &wrapper).await?;
            let sealed = created.seal(b"aad", b"secret");

            let loaded = data_keys::load_all(&pool, &wrapper).await?;
            assert_eq!(loaded.len(), 1, "exactly one key");
            assert_eq!(loaded[0].id(), created.id(), "same id");
            assert_eq!(
                loaded[0].open(b"aad", &sealed)?.as_slice(),
                b"secret",
                "loaded key must open a value sealed with the created key"
            );
            Ok(())
        }

        #[tokio::test]
        async fn load_all_returns_every_key() -> eyre::Result<()> {
            let (_pg, pool) = migrated_pool().await?;
            let wrapper = InMemoryWrapper::new(ARN, [1; 32]);
            let a = data_keys::create(&pool, &wrapper).await?;
            let b = data_keys::create(&pool, &wrapper).await?;
            let c = data_keys::create(&pool, &wrapper).await?;

            let mut expected = vec![a.id(), b.id(), c.id()];
            expected.sort();
            let mut ids: Vec<Uuid> = data_keys::load_all(&pool, &wrapper)
                .await?
                .iter()
                .map(Dek::id)
                .collect();
            ids.sort();
            assert_eq!(ids, expected, "every created key must be loaded");

            let one = data_keys::load_one(&pool, &wrapper, b.id())
                .await?
                .expect("key exists");
            assert_eq!(one.id(), b.id(), "load_one returns the requested key");
            Ok(())
        }

        #[tokio::test]
        async fn current_id_is_newest() -> eyre::Result<()> {
            let (_pg, pool) = migrated_pool().await?;
            let wrapper = InMemoryWrapper::new(ARN, [1; 32]);
            let old = data_keys::create(&pool, &wrapper).await?;
            let newest = data_keys::create(&pool, &wrapper).await?;
            let middle = data_keys::create(&pool, &wrapper).await?;
            for (id, created_at) in [
                (old.id(), "2024-01-01T00:00:00Z"),
                (middle.id(), "2025-01-01T00:00:00Z"),
                (newest.id(), "2026-01-01T00:00:00Z"),
            ] {
                sqlx::query("UPDATE data_keys SET created_at = $2::timestamptz WHERE id = $1")
                    .bind(id)
                    .bind(created_at)
                    .execute(&pool)
                    .await?;
            }
            assert_eq!(
                data_keys::current_id(&pool).await?,
                Some(newest.id()),
                "the newest created_at wins"
            );
            Ok(())
        }

        #[tokio::test]
        async fn key_arn_mismatch_is_error() -> eyre::Result<()> {
            let (_pg, pool) = migrated_pool().await?;
            let created = data_keys::create(&pool, &InMemoryWrapper::new("arn:a", [1; 32])).await?;
            let other = InMemoryWrapper::new("arn:b", [1; 32]);

            let err = data_keys::load_all(&pool, &other)
                .await
                .expect_err("ARN differs");
            assert!(
                matches!(&err, DataKeyError::KeyArnMismatch { id, stored, configured }
                    if *id == created.id() && stored == "arn:a" && configured == "arn:b"),
                "expected KeyArnMismatch, got {err:?}"
            );
            let message = err.to_string();
            assert!(message.contains("arn:a"), "message names stored ARN");
            assert!(message.contains("arn:b"), "message names configured ARN");

            let err = data_keys::load_one(&pool, &other, created.id())
                .await
                .expect_err("ARN differs");
            assert!(
                matches!(err, DataKeyError::KeyArnMismatch { .. }),
                "load_one must also check the ARN"
            );
            Ok(())
        }

        #[tokio::test]
        async fn unwrap_failure_is_error() -> eyre::Result<()> {
            let (_pg, pool) = migrated_pool().await?;
            let created = data_keys::create(&pool, &InMemoryWrapper::new(ARN, [1; 32])).await?;
            let other_master = InMemoryWrapper::new(ARN, [2; 32]);

            assert!(
                matches!(
                    data_keys::load_all(&pool, &other_master).await,
                    Err(DataKeyError::Kms(_))
                ),
                "load_all must surface the unwrap failure"
            );
            assert!(
                matches!(
                    data_keys::load_one(&pool, &other_master, created.id()).await,
                    Err(DataKeyError::Kms(_))
                ),
                "load_one must surface the unwrap failure"
            );
            Ok(())
        }

        #[tokio::test]
        async fn foreign_key_arn_after_good_row_fails_whole_load() -> eyre::Result<()> {
            let (_pg, pool) = migrated_pool().await?;
            let wrapper_a = InMemoryWrapper::new("arn:a", [1; 32]);
            data_keys::create(&pool, &wrapper_a).await?;
            let foreign = data_keys::create(&pool, &InMemoryWrapper::new("arn:b", [1; 32])).await?;

            // `load_all` has no ORDER BY: whichever row comes first, the `arn:a` row loads fine
            // and the `arn:b` row must fail the whole load instead of being skipped.
            let err = data_keys::load_all(&pool, &wrapper_a)
                .await
                .expect_err("a row wrapped under another ARN must fail the whole load");
            assert!(
                matches!(&err, DataKeyError::KeyArnMismatch { id, stored, configured }
                    if *id == foreign.id() && stored == "arn:b" && configured == "arn:a"),
                "expected KeyArnMismatch for the arn:b row, got {err:?}"
            );
            Ok(())
        }
    }
}
