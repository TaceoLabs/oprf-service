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
}
