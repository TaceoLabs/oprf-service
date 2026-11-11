use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use nodes_common::StartedServices;
use nodes_common::postgres::PostgresConfig;
use nodes_common::test_utils::SharedPostgres;

pub mod key_gen_setup;
pub mod node_setup;
pub mod setup;

pub const TEST_TIMEOUT: Duration = if option_env!("CI").is_some() {
    Duration::from_secs(120)
} else {
    Duration::from_secs(20)
};

/// Postgres config pointing at the process-shared testcontainer, with a fresh
/// schema and max_connections = 1 (many parallel tests share one container).
pub async fn test_postgres_config() -> eyre::Result<(PostgresConfig, Arc<SharedPostgres>)> {
    let pg = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let schema = nodes_common::test_utils::next_test_schema();
    let mut config =
        PostgresConfig::with_default_values(pg.connection_string.clone().into(), schema);
    config.max_connections = NonZeroU32::new(1).expect("1 is non-zero");
    Ok((config, pg))
}

/// The chain id of the Anvil chain every [`setup::TestSetup`] runs on.
pub const TEST_CHAIN_ID: u64 = 31_337;

/// The KMS key ARN of party `party_id`, shared by its key-gen and its node.
#[must_use]
pub fn party_kms_key_arn(party_id: usize) -> String {
    format!("arn:aws:kms:eu-central-1:000000000000:key/party-{party_id}")
}

/// The in-memory KMS of party `party_id`.
///
/// Key-gen `i` and node `i` get equal wrappers (same ARN, same master key), so the node can
/// unwrap the data keys its key-gen created; different parties use different master keys.
#[must_use]
pub fn party_dek_wrapper(party_id: usize) -> Arc<dyn oprf_store::DekWrapper> {
    let master = u8::try_from(party_id + 1).expect("party id fits into u8");
    Arc::new(oprf_store::InMemoryWrapper::new(
        &party_kms_key_arn(party_id),
        [master; 32],
    ))
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
