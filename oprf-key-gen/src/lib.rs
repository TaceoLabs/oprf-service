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

use std::str::FromStr as _;

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
use alloy::{
    consensus::constants::ETH_TO_WEI, network::EthereumWallet, primitives::Address,
    providers::Provider as _, signers::local::PrivateKeySigner,
};
use eyre::Context as _;
use groth16_material::circom::CircomGroth16MaterialBuilder;
use nodes_common::web3::RpcProvider;
use oprf_types::{chain::OprfKeyRegistry, crypto::PartyId};

pub(crate) mod api;
pub mod config;
pub mod metrics;
pub(crate) mod services;

pub use nodes_common::Environment;
pub use nodes_common::StartedServices;
use secrecy::ExposeSecret;
pub use services::secret_manager;
use tokio_util::sync::CancellationToken;

/// The tasks spawned by the key-gen library. Should call [`KeyGenTasks::join`] when shutting down for graceful shutdown.
pub struct KeyGenTasks {
    key_event_watcher: tokio::task::JoinHandle<eyre::Result<()>>,
}

impl KeyGenTasks {
    /// Consumes the task by joining every registered `JoinHandle`.
    ///
    /// # Errors
    /// Returns the error from the inner tasks or an error if the task panicked.
    pub async fn join(self) -> eyre::Result<()> {
        self.key_event_watcher.await??;
        Ok(())
    }
}

async fn contract_sanity_checks(
    rpc_provider: &RpcProvider,
    key_gen_wallet_address: Address,
    config: &OprfKeyGenServiceConfig,
) -> eyre::Result<()> {
    tracing::info!(
        "loading party id and checking if numPeers and threshold match. Expect {}/{}",
        config.expected_threshold,
        config.expected_num_peers
    );
    let contract = OprfKeyRegistry::new(config.oprf_key_registry_contract, rpc_provider.http());
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
/// - Initializes the Ethereum wallet with the provided private key.
/// - Initializes the RPC provider used to interact with the configured blockchain.
/// - Fetches and logs the wallet balance.
/// - Loads the party ID from the `OprfKeyRegistry` contract to verify that this
///   node is registered as a participant.
/// - Builds the Groth16 proving material required for the key generation protocol.
/// - Initializes the `DLogSecretGenService`.
/// - Creates a `TransactionHandler` used for submitting and confirming on-chain transactions.
///
/// # Spawned Tasks
/// The service spawns the following background tasks:
/// - `key_event_watcher` – subscribes to the `OprfKeyRegistry` contract events and
///   drives the key generation / resharing protocol.
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
/// - the wallet private key cannot be loaded,
/// - the RPC provider cannot be initialized,
/// - the node is not registered in the `OprfKeyRegistry` contract,
/// - the Groth16 proving material cannot be built.
pub async fn start(
    config: OprfKeyGenServiceConfig,
    secret_manager: SecretManagerService,
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
    #[allow(clippy::cast_precision_loss,reason="we must use f64 due to API limitations")]
    ::metrics::gauge!(METRICS_ID_KEY_GEN_WALLET_BALANCE, METRICS_ATTRID_WALLET_ADDRESS => address.to_string())
        .set(f64::from(balance) / ETH_TO_WEI as f64);

    contract_sanity_checks(&rpc_provider, address, &config)
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
                   () = cancellation_token.cancelled() => {
                       break;
                   }
                }
            }
            tracing::info!("shutting down i am alive task");
        }
    });

    Ok((key_gen_router, KeyGenTasks { key_event_watcher }))
}
