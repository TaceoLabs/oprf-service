#![deny(missing_docs)]
//! This crate provides the OPRF key generation functionality for TACEO:OPRF.
//!
//! It implements a service that listens for OPRF key generation events of the  `OprfKeyRegistry`
//! and participates in the distributed key generation protocol to generate and register OPRF keys.
//! The generated keys are stored securely using the provided `SecretManagerService`.
//! From there, they can be fetched by the OPRF nodes that handle OPRF requests.
//!
//! For details on the OPRF protocol, see the [design document](https://github.com/TaceoLabs/oprf-service/blob/main/docs/oprf.pdf).

use crate::{
    config::OprfKeyGenServiceConfig,
    metrics::{
        METRICS_ATTRID_WALLET_ADDRESS, METRICS_ID_I_AM_ALIVE, METRICS_ID_KEY_GEN_WALLET_BALANCE,
    },
    services::{
        key_event_watcher::KeyEventWatcherTaskConfig, secret_gen::DLogSecretGenService,
        secret_manager::SecretManagerService, transaction_handler::TransactionHandler,
    },
};
use alloy::{consensus::constants::ETH_TO_WEI, network::EthereumWallet, providers::Provider as _};
use eyre::Context as _;
use groth16_material::circom::CircomGroth16MaterialBuilder;
use oprf_types::{chain::OprfKeyRegistry, crypto::PartyId};

pub(crate) mod api;
pub mod config;
pub mod metrics;
pub(crate) mod services;

pub use nodes_common::StartedServices;
pub use services::secret_manager;
use tokio_util::sync::CancellationToken;

/// The tasks spawned by the key-gen library. Should call [`KeyGenTasks::join`] when shutting down for graceful shutdown.
pub struct KeyGenTasks {
    key_event_watcher: tokio::task::JoinHandle<eyre::Result<()>>,
}

impl KeyGenTasks {
    /// Consumes the task by joining every registered `JoinHandle`.
    pub async fn join(self) -> eyre::Result<()> {
        self.key_event_watcher.await??;
        Ok(())
    }
}

/// Starts the OPRF key generation service by spawning all necessary sub-tasks. Additionally, creates an `axum::Router` that serves three routes:
/// - The health and readiness endpoint `/health`.
/// - The used version `/version`.
/// - The public wallet of this node `/wallet`.
///
/// The spawned tasks are:
/// - `key_event_watcher`: subscribes to configured chain and executes the key-gen/reshare protocol
pub async fn start(
    config: OprfKeyGenServiceConfig,
    secret_manager: SecretManagerService,
    started_services: StartedServices,
    cancellation_token: CancellationToken,
) -> eyre::Result<(axum::Router, KeyGenTasks)> {
    tracing::info!("init oprf key-gen service..");
    tracing::info!("loading ETH private key from secret manager..");
    let private_key = secret_manager
        .load_or_insert_wallet_private_key()
        .await
        .context("while loading ETH private key from secret-manager")?;
    let address = private_key.address();
    tracing::info!("my wallet address: {address}");
    let wallet = EthereumWallet::from(private_key);

    let rpc_provider =
        nodes_common::web3::RpcProviderBuilder::with_config(&config.rpc_provider_config)
            .environment(config.environment)
            .wallet(wallet)
            .build()
            .await
            .context("while init blockchain connection")?;

    let balance = rpc_provider
        .http()
        .get_balance(address)
        .await
        .context("while get_balance")?;
    tracing::info!(
        "wallet balance: {} ETH",
        alloy::primitives::utils::format_ether(balance)
    );
    ::metrics::gauge!(METRICS_ID_KEY_GEN_WALLET_BALANCE, METRICS_ATTRID_WALLET_ADDRESS => address.to_string())
        .set(f64::from(balance) / ETH_TO_WEI as f64);

    tracing::info!("loading party id..");
    let contract = OprfKeyRegistry::new(config.oprf_key_registry_contract, rpc_provider.http());
    // Fetch the party ID and log it.
    // This call verifies whether we are registered at the contract as participant and serves as early failing point if not
    let party_id = PartyId(
        contract
            .getPartyIdForParticipant(address)
            .call()
            .await
            .context("while loading party id")?
            .try_into()?,
    );
    tracing::info!("we are party id: {party_id}");

    tracing::info!("init dlog secret gen service..");
    let key_gen_material = tokio::task::spawn_blocking(move || {
        CircomGroth16MaterialBuilder::new()
            .bbf_inv()
            .bbf_num_2_bits_helper()
            .build_from_paths(config.zkey_path, config.witness_graph_path)
    })
    .await
    .context("while joining build groth16 task")?
    .context("while building groth16 material")?;
    let dlog_secret_gen_service = DLogSecretGenService::init(key_gen_material);
    let transaction_handler = TransactionHandler::new(
        config.max_wait_time_transaction_confirmation,
        config.max_gas_per_transaction,
        config.confirmations_for_transaction,
        rpc_provider.clone(),
        address,
    );

    tracing::info!("spawning key event watcher..");
    let key_event_watcher = tokio::spawn({
        let contract_address = config.oprf_key_registry_contract;
        let cancellation_token = cancellation_token.clone();
        services::key_event_watcher::key_event_watcher_task(KeyEventWatcherTaskConfig {
            contract_address,
            dlog_secret_gen_service,
            start_block: config.start_block,
            secret_manager,
            start_signal: started_services.new_service(),
            cancellation_token,
            rpc_provider,
            transaction_handler,
        })
    });

    let key_gen_router = api::routes(address, started_services.clone());

    tokio::task::spawn({
        let cancellation_token = cancellation_token.clone();
        let mut interval = tokio::time::interval(config.i_am_alive_interval);
        async move {
            tracing::info!("starting i am alive task");
            loop {
                tokio::select! {
                   _ = interval.tick() => {
                        if started_services.all_started() {
                            ::metrics::counter!(METRICS_ID_I_AM_ALIVE).increment(1);
                        }
                   },
                   _ = cancellation_token.cancelled() => {
                       break;
                   }
                }
            }
            tracing::info!("shutting down i am alive task");
        }
    });

    Ok((key_gen_router, KeyGenTasks { key_event_watcher }))
}
