use std::num::NonZeroU32;
use std::time::Duration;

use ark_serialize::CanonicalSerialize;
use nodes_common::StartedServices;
use nodes_common::postgres::PostgresConfig;

pub mod key_gen_setup;
pub mod node_setup;
pub mod setup;

pub const TEST_TIMEOUT: Duration = if option_env!("CI").is_some() {
    Duration::from_secs(120)
} else {
    Duration::from_secs(20)
};

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

pub async fn wait_until_started(started_services: &StartedServices) -> eyre::Result<()> {
    tokio::time::timeout(TEST_TIMEOUT, async {
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
