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
        use ark_babyjubjub::Fr;
        use oprf_core::ddlog_equality::shamir::DLogShareShamir;
        use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
        use ruint::aliases::U160;

        use crate::{MIGRATOR, StoreError, shares, test_utils};

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
        async fn fetch_and_decode_live_share() -> eyre::Result<()> {
            let (_pg, mut connection) = migrated_connection().await?;
            let (id, share, public_key) = random_key();
            let epoch = ShareEpoch::new(7);
            test_utils::insert_share(&mut connection, id, epoch, &share, &public_key).await?;

            let row = shares::fetch(&mut connection, id)
                .await?
                .expect("row exists");
            assert!(!row.is_deleted(), "row must be live");
            assert_eq!(row.epoch()?, epoch, "epoch must match");
            let stored = row.decode()?;
            assert_eq!(stored.oprf_key_id, id, "id must match");
            assert_eq!(stored.epoch, epoch, "epoch must match");
            assert_eq!(stored.public_key, public_key, "public key must match");
            assert_eq!(Fr::from(stored.share), Fr::from(share), "share must match");
            Ok(())
        }

        #[tokio::test]
        async fn deleted_row_is_flagged_and_does_not_decode() -> eyre::Result<()> {
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
                matches!(row.decode(), Err(StoreError::Corrupt(_))),
                "deleted row must not decode"
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
                matches!(row.decode(), Err(StoreError::Corrupt(_))),
                "invalid share bytes must be corrupt"
            );
            Ok(())
        }

        #[tokio::test]
        async fn non_direct_row_does_not_decode() -> eyre::Result<()> {
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
            let data_key_id: String = sqlx::query_scalar(
                "INSERT INTO data_keys (id, wrapped_key, wrapping, kms_key_arn) \
                 VALUES (md5(random()::text)::uuid, $1, 'awsKms', 'arn:test:key') RETURNING id::text",
            )
            .bind(&[9_u8, 9, 9][..])
            .fetch_one(&mut connection)
            .await?;
            sqlx::query(
                "UPDATE shares SET storage_format = 'envelopeV1', data_key_id = $2::uuid WHERE id = $1",
            )
            .bind(envelope_id.to_le_bytes())
            .bind(&data_key_id)
            .execute(&mut connection)
            .await?;

            let row = shares::fetch(&mut connection, envelope_id)
                .await?
                .expect("row exists");
            let err = row.decode().expect_err("envelopeV1 row must not decode");
            assert!(
                matches!(&err, StoreError::UnsupportedStorageFormat(format) if format == "envelopeV1"),
                "expected UnsupportedStorageFormat(\"envelopeV1\"), got {err:?}"
            );
            Ok(())
        }
    }
}
