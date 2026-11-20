//! OPRF Key Gen Binary
//!
//! This is the main entry point for the OPRF key-gen service.
//! It initializes tracing, metrics, and starts the service with configuration
//! from environment variables using the `TACEO_OPRF_KEY_GEN__` prefix.

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use std::{net::SocketAddr, process::ExitCode, sync::Arc, time::Duration};

use config::Config;
use eyre::Context;
use nodes_common::{StartedServices, postgres::PostgresConfig};
use serde::Deserialize;
use taceo_oprf_key_gen::{
    config::{OprfKeyGenServiceConfig, StorageConfig},
    postgres::{PostgresDb, Storage},
};

/// The top-level configuration for the OPRF key-gen binary.
///
/// Configured via environment variables using the `TACEO_OPRF_KEY_GEN__` prefix and `__` as separator.
#[derive(Clone, Debug, Deserialize)]
struct OprfKeyGenConfig {
    /// The bind addr of the AXUM server
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,

    /// Max wait time the service waits for its workers during shutdown.
    #[serde(default = "default_max_wait_shutdown")]
    #[serde(with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required")]
    pub max_wait_time_shutdown: Duration,

    /// The OPRF key-gen service config
    #[serde(rename = "service")]
    pub key_gen_config: OprfKeyGenServiceConfig,

    /// Postgres config used by the shared [`PostgresDb`] backend (secret manager and chain cursor store).
    #[serde(rename = "postgres")]
    pub postgres_config: PostgresConfig,

    /// How secrets are stored in the database; defaults to `direct` only.
    #[serde(default)]
    pub storage: StorageConfig,
}

fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:4321".parse().expect("valid SocketAddr")
}

fn default_max_wait_shutdown() -> Duration {
    Duration::from_secs(10)
}

fn env_source() -> config::Environment {
    config::Environment::with_prefix("TACEO_OPRF_KEY_GEN")
        .separator("__")
        .list_separator(",")
        .with_list_parse_key("service.rpc.http_urls")
        .with_list_parse_key("storage.allowed_storage_formats")
        .try_parsing(true)
}

// we are not allowed to build an eyre::Report yet because telemetry-batteries expects to install
// the color-eyre hook
fn load_key_gen_config() -> Result<OprfKeyGenConfig, config::ConfigError> {
    let cfg = Config::builder().add_source(env_source());

    let key_gen_config = cfg.build()?.try_deserialize()?;

    // Unset all env vars with our prefix to prevent leakage to subprocesses.
    let keys_to_remove: Vec<String> = std::env::vars()
        .filter_map(|(k, _)| k.starts_with("TACEO_OPRF_KEY_GEN_").then_some(k))
        .collect();
    for key in keys_to_remove {
        // SAFETY: no other threads are running at this point in the startup sequence.
        unsafe {
            std::env::remove_var(&key);
        }
    }

    Ok(key_gen_config)
}

async fn run(config: OprfKeyGenConfig) -> eyre::Result<()> {
    taceo_oprf_key_gen::metrics::describe_metrics();
    tracing::info!("{}", nodes_common::version_info!());

    // The stored secrets are bound to the party id, so it is loaded before the database is opened.
    let node_information = taceo_oprf_key_gen::load_node_information(&config.key_gen_config)
        .await
        .context("while loading node information")?;

    tracing::info!("connecting to postgres DB...");

    // Only a deployment that uses `envelopeV1` gets a wrapper; with a KMS key it is the only one
    // that touches AWS.
    let storage = match config.storage {
        StorageConfig::Direct => Storage::Direct,
        StorageConfig::Envelope { mode, key } => {
            let wrapper = key
                .wrapper()
                .await
                .context("invalid storage configuration")?;
            tracing::info!(
                wrapping = wrapper.wrapping(),
                key_id = wrapper.key_id(),
                "wrapping data keys"
            );
            Storage::Envelope { mode, wrapper }
        }
    };
    let postgres = PostgresDb::init(&config.postgres_config, storage, node_information)
        .await
        .context("while starting postgres secret-manager")?;

    // Init postgres secret manager (Postgres backed)
    let secret_manager = Arc::new(postgres.clone());

    // Init chain event store (Postgres backed)
    let chain_cursor_store = Arc::new(postgres.clone());

    let (cancellation_token, _) =
        nodes_common::spawn_shutdown_task(nodes_common::default_shutdown_signal());

    // Clone the values we need afterwards as well
    let bind_addr = config.bind_addr;
    let max_wait_time_shutdown = config.max_wait_time_shutdown;

    let (key_gen_router, key_gen_task) = taceo_oprf_key_gen::start(
        config.key_gen_config,
        secret_manager,
        chain_cursor_store,
        StartedServices::new(),
        cancellation_token.clone(),
    )
    .await
    .context("while initiating key-gen service")?;

    let server = tokio::spawn({
        let cancellation_token = cancellation_token.clone();
        async move {
            // we cancel the token if this task closes for some reason
            let _drop_guard = cancellation_token.drop_guard_ref();
            tracing::info!("starting axum server on to {bind_addr}");
            let tcp_listener = tokio::net::TcpListener::bind(bind_addr)
                .await
                .context("while binding tcp-listener")?;
            let axum_result = axum::serve(tcp_listener, key_gen_router)
                .with_graceful_shutdown({
                    let cancellation_token = cancellation_token.clone();
                    async move { cancellation_token.cancelled().await }
                })
                .await
                .context("while running axum");
            tracing::info!("axum server shutdown");
            axum_result
        }
    });

    tracing::info!("everything started successfully - now waiting for shutdown...");
    cancellation_token.cancelled().await;

    tracing::info!("waiting for shutdown of services (max wait time {max_wait_time_shutdown:?})..");

    match tokio::time::timeout(max_wait_time_shutdown, async move {
        let (axum_result, key_gen_result) = tokio::join!(server, key_gen_task.join());
        axum_result??;
        key_gen_result?;
        eyre::Ok(())
    })
    .await
    {
        Ok(Ok(())) => {
            tracing::info!("successfully finished shutdown in time");
            Ok(())
        }
        Ok(Err(err)) => Err(err),
        Err(_) => {
            eyre::bail!("could not finish shutdown in time");
        }
    }
}

fn main() -> ExitCode {
    // try loading config and unsetting vars before we do any potentially multithreaded work;
    let maybe_config = load_key_gen_config();

    // we panic if we cannot setup tracing + TLS - if that fails we won't see anything anyways on tracing endpoint
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Can install");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Can build Tokio runtime");
    runtime.block_on(async {
        let _guard = telemetry_batteries::init().expect("Can initialize tracing");

        // load the config
        let config = match maybe_config {
            Ok(config) => config,
            Err(err) => {
                tracing::error!(%err, "failed to load config");
                return ExitCode::FAILURE;
            }
        };
        tracing::info!("starting taceo-oprf-key-gen with config: {config:#?}");
        match run(config).await {
            Ok(()) => {
                tracing::info!("good night");
                ExitCode::SUCCESS
            }
            Err(err) => {
                tracing::error!(?err, "key-gen did shutdown");
                tracing::error!("good night anyways");
                ExitCode::FAILURE
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use taceo_oprf_key_gen::config::WrappingKeyConfig;

    use super::*;

    #[derive(Deserialize)]
    struct OnlyStorage {
        #[serde(default)]
        storage: StorageConfig,
    }

    fn storage_from_env(vars: &[(&str, &str)]) -> Result<StorageConfig, config::ConfigError> {
        let vars = vars
            .iter()
            .map(|(key, value)| {
                (
                    format!("TACEO_OPRF_KEY_GEN__STORAGE__{key}"),
                    (*value).to_owned(),
                )
            })
            .collect();
        let config: OnlyStorage = Config::builder()
            .add_source(env_source().source(Some(vars)))
            .build()?
            .try_deserialize()?;
        Ok(config.storage)
    }

    #[test]
    fn storage_is_parsed_from_env() {
        const KEY_ARN: &str = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd";
        assert_eq!(
            storage_from_env(&[]).expect("default"),
            StorageConfig::Direct
        );

        let envelope = storage_from_env(&[
            ("ALLOWED_STORAGE_FORMATS", "direct,envelopeV1"),
            ("STORAGE_WRITE_FORMAT", "envelopeV1"),
            ("KMS_KEY_ARN", KEY_ARN),
        ])
        .expect("valid envelope config");
        let StorageConfig::Envelope {
            mode,
            key: WrappingKeyConfig::Kms(kms),
        } = envelope
        else {
            panic!("expected an envelope config with a KMS key, got {envelope:?}");
        };
        assert_eq!(
            mode,
            taceo_oprf_key_gen::config::EnvelopeMode::WriteEnvelope
        );
        assert_eq!(kms.key_arn.to_string(), KEY_ARN);

        let err = storage_from_env(&[
            ("ALLOWED_STORAGE_FORMATS", "envelopeV1"),
            ("KMS_KEY_ARN", KEY_ARN),
        ])
        .expect_err("write format direct is not allowed");
        assert!(err.to_string().contains("storage_write_format"), "{err}");
    }
}
