use ark_babyjubjub::Fr;
use ark_serialize::CanonicalSerialize as _;
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
fn codec_matches_legacy_encoding() {
    let share = DLogShareShamir::from(rand::random::<Fr>());
    let public_key = OprfPublicKey::new(rand::random());

    let mut legacy_share = Vec::new();
    share
        .serialize_uncompressed(&mut legacy_share)
        .expect("can serialize");
    let mut legacy_public_key = Vec::new();
    public_key
        .serialize_uncompressed(&mut legacy_public_key)
        .expect("can serialize");

    assert_eq!(
        codec::to_bytes(&share).as_slice(),
        legacy_share.as_slice(),
        "share encoding must not change"
    );
    assert_eq!(
        codec::to_bytes(&public_key).as_slice(),
        legacy_public_key.as_slice(),
        "public key encoding must not change"
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
    use crate::{MIGRATOR, retry};

    #[test]
    fn retry_classification() {
        assert!(retry::is_transient(&sqlx::Error::PoolTimedOut));
        assert!(retry::is_transient(&sqlx::Error::WorkerCrashed));
        assert!(retry::is_transient(&sqlx::Error::BeginFailed));
        assert!(!retry::is_transient(&sqlx::Error::RowNotFound));

        assert!(retry::is_transient_or_conflict(&sqlx::Error::PoolTimedOut));
        assert!(retry::is_transient_or_conflict(&sqlx::Error::WorkerCrashed));
        assert!(retry::is_transient_or_conflict(&sqlx::Error::BeginFailed));
        assert!(!retry::is_transient_or_conflict(&sqlx::Error::RowNotFound));
    }

    #[tokio::test]
    async fn migrations_apply_on_empty_schema() -> eyre::Result<()> {
        let pg = nodes_common::test_utils::shared_postgres_testcontainer().await?;
        let schema = nodes_common::test_utils::next_test_schema();
        let mut connection =
            nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
        MIGRATOR.run(&mut connection).await?;
        assert_eq!(
            MIGRATOR.iter().count(),
            8,
            "four up and four down migrations"
        );
        Ok(())
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
        async fn fetch_unknown_is_none() -> eyre::Result<()> {
            let (_pg, mut connection) = migrated_connection().await?;
            let (id, _, _) = random_key();
            assert!(
                shares::fetch(&mut connection, id).await?.is_none(),
                "unknown key must not be found"
            );
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
    }
}
