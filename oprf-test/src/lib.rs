use std::num::NonZeroU32;
use std::time::Duration;

pub mod deploy_anvil;
pub mod key_gen_setup;
pub mod node_setup;
mod oprf_key_registry;
pub mod setup;

use ark_serialize::CanonicalSerialize;
pub use deploy_anvil::*;
pub use oprf_key_registry::*;
pub use setup::*;

use nodes_common::StartedServices;
use nodes_common::postgres::PostgresConfig;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use sqlx::PgPool;

/// 120s on CI (the `CI` env var is set by GitHub Actions), 20s locally.
pub fn test_timeout() -> Duration {
    if std::env::var_os("CI").is_some() {
        Duration::from_secs(120)
    } else {
        Duration::from_secs(20)
    }
}

#[inline]
pub(crate) fn to_db_ark_serialize_uncompressed<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(t.uncompressed_size());
    t.serialize_uncompressed(&mut bytes).expect("Can serialize");
    bytes
}

/// Postgres config pointing at the process-shared testcontainer, with a fresh
/// schema and max_connections = 1 (many parallel tests share one container).
pub async fn test_postgres_config() -> eyre::Result<PostgresConfig> {
    let connection_string = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let schema = nodes_common::test_utils::next_test_schema();
    let mut config = PostgresConfig::with_default_values(connection_string.into(), schema);
    config.max_connections = NonZeroU32::new(1).expect("1 is non-zero");
    Ok(config)
}

pub(crate) async fn insert_key_material(
    pool: &PgPool,
    key_id: OprfKeyId,
    epoch: ShareEpoch,
    share: DLogShareShamir,
    public_key: OprfPublicKey,
) -> eyre::Result<()> {
    sqlx::query(
        "
        INSERT INTO shares (id, share, epoch, public_key)
        VALUES ($1, $2, $3, $4)
    ",
    )
    .bind(key_id.to_le_bytes())
    .bind(to_db_ark_serialize_uncompressed(&share).as_slice())
    .bind(i64::from(epoch))
    .bind(to_db_ark_serialize_uncompressed(&public_key).as_slice())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn wait_until_started(started_services: &StartedServices) -> eyre::Result<()> {
    tokio::time::timeout(test_timeout(), async {
        loop {
            if started_services.all_started() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    Ok(())
}
