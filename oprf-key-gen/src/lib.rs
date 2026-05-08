#![deny(missing_docs)]
#![deny(clippy::all, clippy::pedantic)]
#![deny(
    clippy::allow_attributes_without_reason,
    clippy::assertions_on_result_states,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::iter_over_hash_type,
    clippy::let_underscore_must_use,
    clippy::missing_assert_message,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_safety_comment,
    clippy::unwrap_used
)]
//! This crate provides the OPRF key generation functionality for TACEO:OPRF.
//!
//! It implements a service that listens for OPRF key generation events of the  `OprfKeyRegistry`
//! and participates in the distributed key generation protocol to generate and register OPRF keys.
//! The generated keys are stored securely using the provided `SecretManagerService`.
//! From there, they can be fetched by the OPRF nodes that handle OPRF requests.
//!
//! For details on the OPRF protocol, see the [design document](https://github.com/TaceoLabs/oprf-service/blob/main/docs/oprf.pdf).

use std::{str::FromStr as _, time::Duration};

use crate::{
    config::OprfKeyGenServiceConfig,
    services::{
        event_cursor_store::ChainCursorService,
        secret_gen::DLogSecretGenService,
        secret_manager::SecretManagerService,
        transaction_handler::{TransactionHandler, TransactionHandlerArgs},
    },
};
use alloy::{
    network::EthereumWallet,
    primitives::Address,
    providers::{DynProvider, Provider as _, ProviderBuilder, WsConnect},
    signers::local::PrivateKeySigner,
};
use eyre::Context as _;
use groth16_material::circom::CircomGroth16MaterialBuilder;
use nodes_common::web3::{self, event_stream::ChainCursor};
use oprf_types::{chain::OprfKeyRegistry, crypto::PartyId};
use secrecy::ExposeSecret;
use tokio_util::sync::CancellationToken;

pub(crate) mod api;
pub mod config;
pub mod metrics;
pub mod postgres;
pub(crate) mod services;

#[cfg(test)]
mod tests;

pub use nodes_common::Environment;
pub use nodes_common::StartedServices;
pub use services::event_cursor_store;
pub use services::secret_manager;

/// The tasks spawned by the key-gen library. Should call [`KeyGenTasks::join`] when shutting down for graceful shutdown.
pub struct KeyGenTasks {
    key_event_watcher: tokio::task::JoinHandle<eyre::Result<()>>,
    i_am_alive_task: tokio::task::JoinHandle<()>,
    cursor_checkpoint_task: tokio::task::JoinHandle<()>,

    // keep the providers alive as long as the tasks are
    _http_rpc_provider: web3::HttpRpcProvider,
    _ws_rpc_provider: DynProvider,
}

impl KeyGenTasks {
    /// Consumes the task by joining every registered `JoinHandle`.
    ///
    /// # Errors
    /// Returns the error from the inner tasks or an error if the task panicked.
    pub async fn join(self) -> eyre::Result<()> {
        self.key_event_watcher.await??;
        self.i_am_alive_task.await?;
        self.cursor_checkpoint_task.await?;
        Ok(())
    }
}

async fn contract_sanity_checks(
    rpc_provider: &web3::HttpRpcProvider,
    key_gen_wallet_address: Address,
    config: &OprfKeyGenServiceConfig,
) -> eyre::Result<()> {
    tracing::info!(
        "loading party id and checking if numPeers and threshold match. Expect {}/{}",
        config.expected_threshold,
        config.expected_num_peers
    );
    let contract = OprfKeyRegistry::new(config.oprf_key_registry_contract, rpc_provider.inner());
    // Fetch the party ID and log it.
    // This call verifies whether we are registered at the contract as participant and serves as early failing point if not
    let get_party_id_call = contract.getPartyIdForParticipant(key_gen_wallet_address);
    let threshold_call = contract.threshold();
    let num_peers_call = contract.numPeers();
    let (party_id_contract, threshold_contract, num_peers_contract) = tokio::join!(
        get_party_id_call.call(),
        threshold_call.call(),
        num_peers_call.call(),
    );
    let party_id = PartyId(
        party_id_contract
            .context("while loading party id")?
            .try_into()?,
    );
    let threshold_contract = threshold_contract.context("while loading threshold")?;
    let num_peers_contract = num_peers_contract.context("while loading num peers")?;
    eyre::ensure!(
        threshold_contract == config.expected_threshold.get(),
        "Expected threshold {} but contract reported {threshold_contract}",
        config.expected_threshold
    );
    eyre::ensure!(
        num_peers_contract == config.expected_num_peers.get(),
        "Expected num_peers {} but contract reported {num_peers_contract}",
        config.expected_num_peers
    );
    tracing::info!("we are party id: {party_id}. Threshold/NumPeers also match");
    Ok(())
}

/// Starts the OPRF key generation service and spawns all required background tasks.
/// Additionally, returns an `axum::Router` exposing basic service endpoints.
///
/// # Exposed Routes
/// The returned router provides the following endpoints:
/// - `/health` – health and readiness endpoint.
/// - `/version` – returns the running service version.
/// - `/wallet` – returns the public Ethereum wallet address of this node.
///
/// # Initialization
/// During startup the service performs several initialization steps:
/// - Initializes the Ethereum wallet from the configured private key.
/// - Stores the derived wallet address in the configured secret manager.
/// - Initializes the RPC provider used to interact with the configured blockchain.
/// - Fetches and logs the wallet balance.
/// - Loads the party ID from the `OprfKeyRegistry` contract to verify that this
///   node is registered as a participant.
/// - Builds the Groth16 proving material required for the key generation protocol.
/// - Initializes the `DLogSecretGenService`, which uses the secret manager to persist in-progress key-gen state between rounds.
/// - Creates a `TransactionHandler` used for submitting and confirming on-chain transactions.
///
/// # Parameters
/// - `secret_manager` – Postgres-backed store for key shares and in-progress state.
/// - `chain_cursor_service` – Postgres-backed cursor store; the `key_event_watcher` loads
///   the persisted `(block, log_index)` on startup so backfill resumes from where the
///   previous run left off rather than from the chain head.
///
/// # Spawned Tasks
/// The service spawns the following background tasks:
/// - `key_event_watcher` – subscribes to the `OprfKeyRegistry` contract events and
///   drives the key generation / resharing protocol. Backfills missed events from the
///   last persisted chain cursor.
/// - `i_am_alive` – periodically emits a metric once all services have started,
///   used as a basic liveness indicator.
///
/// # Returns
/// Returns:
/// - An `axum::Router` exposing the service endpoints.
/// - A `KeyGenTasks` handle containing the spawned tasks.
///
/// # Errors
/// Returns an error if:
/// - the configured wallet private key cannot be parsed,
/// - the RPC provider cannot be initialized,
/// - the node is not registered in the `OprfKeyRegistry` contract,
/// - the Groth16 proving material cannot be built.
pub async fn start(
    config: OprfKeyGenServiceConfig,
    secret_manager: SecretManagerService,
    chain_cursor_service: ChainCursorService,
    started_services: StartedServices,
    cancellation_token: CancellationToken,
) -> eyre::Result<(axum::Router, KeyGenTasks)> {
    tracing::info!("init oprf key-gen service..");

    tracing::info!("initializing wallet...");
    let private_key = PrivateKeySigner::from_str(config.wallet_private_key.expose_secret())
        .context("while loading wallet private key")?;
    let address = private_key.address();
    secret_manager
        .store_wallet_address(address.to_string())
        .await
        .context("while storing wallet address in secret manager")?;
    tracing::info!("my wallet address: {address}");
    let wallet = EthereumWallet::from(private_key);

    let http_rpc_provider =
        nodes_common::web3::HttpRpcProviderBuilder::with_config(&config.rpc_provider_config)
            .environment(config.environment)
            .wallet(wallet)
            .build()
            .context("while init blockchain connection")?;

    let ws_rpc_provider = ProviderBuilder::new()
        .connect_ws(WsConnect::new(config.ws_rpc_url.clone()))
        .await
        .context("while connecting ws provider")?
        .erased();

    let balance = http_rpc_provider
        .get_balance(address)
        .await
        .context("while get_balance")?;
    let balance = alloy::primitives::utils::format_ether(balance);

    tracing::info!("wallet balance: {balance} ETH");
    metrics::wallet::set_wallet_balance(&balance);

    contract_sanity_checks(&http_rpc_provider, address, &config)
        .await
        .context("while doing sanity checks")?;

    let key_gen_material = tokio::task::spawn_blocking(move || {
        CircomGroth16MaterialBuilder::new()
            .bbf_inv()
            .bbf_num_2_bits_helper()
            .build_from_paths(config.zkey_path, config.witness_graph_path)
    })
    .await
    .context("while joining build groth16 task")?
    .context("while building groth16 material")?;

    let dlog_secret_gen_service =
        DLogSecretGenService::init(key_gen_material, secret_manager.clone());
    let transaction_handler = TransactionHandler::new(TransactionHandlerArgs {
        max_wait_time_watch_transaction: config.max_wait_time_transaction_confirmation,
        confirmations_for_transaction: config.confirmations_for_transaction,
        sleep_between_get_receipt: config.sleep_between_get_receipt,
        max_tries_fetching_receipt: config.max_tries_fetching_receipt,
        max_gas_per_transaction: config.max_gas_per_transaction,
        rpc_provider: http_rpc_provider.clone(),
        wallet_address: address,
        contract_address: config.oprf_key_registry_contract,
    });

    tracing::info!("spawning key event watcher..");
    let key_event_watcher = tokio::spawn({
        let contract_address = config.oprf_key_registry_contract;
        let cancellation_token = cancellation_token.clone();
        services::key_event_watcher::key_event_watcher_task(
            services::key_event_watcher::KeyEventWatcherTaskConfig {
                http_rpc_provider: http_rpc_provider.clone(),
                ws_rpc_provider: ws_rpc_provider.clone(),
                contract_address,
                dlog_secret_gen_service,
                chain_cursor_service: chain_cursor_service.clone(),
                start_signal: started_services.new_service(),
                transaction_handler,
                event_stream_config: config.event_stream_config,
                threshold: config.expected_threshold,
                cancellation_token,
            },
        )
    });

    let key_gen_router = api::routes(address, started_services.clone());

    let i_am_alive_task = tokio::task::spawn(start_i_am_alive_task(
        started_services,
        config.i_am_alive_interval,
        cancellation_token.clone(),
    ));

    let cursor_checkpoint_task = tokio::task::spawn(start_cursor_checkpoint_task(
        config.cursor_checkpoint_interval,
        http_rpc_provider.clone(),
        chain_cursor_service,
        cancellation_token,
    ));

    Ok((
        key_gen_router,
        KeyGenTasks {
            key_event_watcher,
            i_am_alive_task,
            cursor_checkpoint_task,
            _http_rpc_provider: http_rpc_provider,
            _ws_rpc_provider: ws_rpc_provider,
        },
    ))
}

async fn start_cursor_checkpoint_task(
    checkpoint_interval: Duration,
    rpc_provider: web3::HttpRpcProvider,
    chain_cursor_service: ChainCursorService,
    cancellation_token: CancellationToken,
) {
    let mut interval = tokio::time::interval(checkpoint_interval);
    // first interval ticks immediately
    interval.tick().await;
    tracing::info!("starting cursor checkpoint task");
    loop {
        let checkpoint = match rpc_provider.get_block_number().await {
            Ok(checkpoint) => Some(ChainCursor::new(checkpoint, 0)),
            Err(err) => {
                tracing::warn!(%err, "cannot fetch checkpoint for cursor");
                tracing::warn!("tying again in {checkpoint_interval:?}");
                None
            }
        };
        tokio::select! {
            _ = interval.tick() => {
            }
            () = cancellation_token.cancelled() => {
                break;
            }
        }
        if let Some(checkpoint) = checkpoint {
            tracing::info!("persisting chain-cursor checkpoint: {checkpoint}");
            match chain_cursor_service.store_chain_cursor(checkpoint).await {
                Ok(()) => {
                    tracing::info!("successfully called store_chain_cursor");
                }
                Err(err) => {
                    tracing::warn!(%err, "cannot persist checkpoint to DB");
                    tracing::warn!("tying again in {checkpoint_interval:?}");
                }
            }
        }
    }
    tracing::info!("shutting down cursor checkpoint task");
}

async fn start_i_am_alive_task(
    started_services: StartedServices,
    i_am_alive_interval: Duration,
    cancellation_token: CancellationToken,
) {
    let mut interval = tokio::time::interval(i_am_alive_interval);
    tracing::info!("starting i am alive task");
    loop {
        tokio::select! {
           _ = interval.tick() => {
                if started_services.all_started() {
                    metrics::health::inc_i_am_alive();
                }
           },
           () = cancellation_token.cancelled() => {
               break;
           }
        }
    }
    tracing::info!("shutting down i am alive task");
}
