#![deny(missing_docs)]
//! This crate provides the OPRF key generation functionality for TACEO:OPRF.
//!
//! It implements a service that listens for OPRF key generation events of the  `OprfKeyRegistry`
//! and participates in the distributed key generation protocol to generate and register OPRF keys.
//! The generated keys are stored securely using the provided `SecretManagerService`.
//! From there, they can be fetched by the OPRF nodes that handle OPRF requests.
//!
//! For details on the OPRF protocol, see the [design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf).
use std::sync::{Arc, atomic::AtomicBool};

use crate::{
    config::OprfKeyGenConfig,
    metrics::{METRICS_ATTRID_WALLET_ADDRESS, METRICS_ID_KEY_GEN_WALLET_BALANCE},
    services::{
        key_event_watcher::KeyEventWatcherTaskConfig,
        secret_gen::DLogSecretGenService,
        secret_manager::SecretManagerService,
        transaction_handler::{TransactionHandler, TransactionHandlerInitArgs},
    },
};
use alloy::{
    consensus::constants::ETH_TO_WEI,
    network::EthereumWallet,
    providers::{
        Provider as _, ProviderBuilder, WsConnect,
        fillers::{BlobGasFiller, ChainIdFiller},
    },
};
use eyre::Context as _;
use groth16_material::circom::CircomGroth16MaterialBuilder;
use oprf_types::{chain::OprfKeyRegistry, crypto::PartyId};
use secrecy::ExposeSecret as _;

pub(crate) mod api;
pub mod config;
pub mod metrics;
pub(crate) mod services;

pub use services::secret_manager;
use tokio_util::sync::CancellationToken;

/// The tasks spawned by the key-gen library. Should call [`KeyGenTasks::join`] when shutting down for graceful shutdown.
pub struct KeyGenTasks {
    transaction_handler: tokio::task::JoinHandle<eyre::Result<()>>,
    key_event_watcher: tokio::task::JoinHandle<eyre::Result<()>>,
}

impl KeyGenTasks {
    /// Consumes the task by joining every registered `JoinHandle`.
    pub async fn join(self) -> eyre::Result<()> {
        let (transaction_handler_result, key_event_watcher_result) =
            tokio::join!(self.transaction_handler, self.key_event_watcher);
        transaction_handler_result??;
        key_event_watcher_result??;
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
/// - `transaction_handler`: task that subscribes to same contract as `key_event_watcher` and waits for `KeyGenConfirmation` events from chain in case of errors with the RPC provider.
pub async fn start(
    config: OprfKeyGenConfig,
    secret_manager: SecretManagerService,
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

    tracing::info!("init rpc provider..");
    let ws = WsConnect::new(config.chain_ws_rpc_url.expose_secret());
    let provider = ProviderBuilder::new()
        .filler(ChainIdFiller::default())
        .with_simple_nonce_management()
        .filler(BlobGasFiller::default())
        .with_gas_estimation()
        .wallet(wallet)
        .connect_ws(ws)
        .await
        .context("while connecting to RPC")?
        .erased();

    let balance = provider
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
    let contract = OprfKeyRegistry::new(config.oprf_key_registry_contract, provider.clone());
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
    let key_gen_material = CircomGroth16MaterialBuilder::new()
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .build_from_paths(config.key_gen_zkey_path, config.key_gen_witness_graph_path)?;
    let dlog_secret_gen_service = DLogSecretGenService::init(key_gen_material);
    tracing::info!("spawning transaction handler..");
    let (transaction_handler, transaction_handler_handle) =
        TransactionHandler::new(TransactionHandlerInitArgs {
            max_wait_time: config.max_wait_time_transaction_confirmation,
            max_gas_per_transaction: config.max_gas_per_transaction,
            confirmations_for_transaction: config.confirmations_for_transaction,
            attempts: config.max_transaction_attempts,
            party_id,
            contract_address: config.oprf_key_registry_contract,
            provider: provider.clone(),
            wallet_address: address,
            cancellation_token: cancellation_token.clone(),
        })
        .await
        .context("while spawning transaction handler")?;

    let key_event_watcher_started_signal = Arc::new(AtomicBool::default());
    tracing::info!("spawning key event watcher..");
    let key_event_watcher = tokio::spawn({
        let provider = provider.clone();
        let contract_address = config.oprf_key_registry_contract;
        let key_event_watcher_started_signal = key_event_watcher_started_signal.clone();
        let cancellation_token = cancellation_token.clone();
        services::key_event_watcher::key_event_watcher_task(KeyEventWatcherTaskConfig {
            party_id,
            provider,
            contract_address,
            dlog_secret_gen_service,
            start_block: config.start_block,
            secret_manager,
            transaction_handler,
            start_signal: key_event_watcher_started_signal,
            cancellation_token,
        })
    });

    let key_gen_router = api::routes(address, key_event_watcher_started_signal);
    Ok((
        key_gen_router,
        KeyGenTasks {
            transaction_handler: transaction_handler_handle,
            key_event_watcher,
        },
    ))
}
