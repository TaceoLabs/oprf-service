#![deny(missing_docs)]
//! This crate provides the OPRF key generation functionality for TACEO:Oprf.
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
        key_event_watcher::KeyEventWatcherTaskConfig, secret_gen::DLogSecretGenService,
        secret_manager::SecretManagerService, transaction_handler::TransactionHandler,
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

/// Starts the OPRF key generation service and waits for shutdown signal.
pub async fn start(
    config: OprfKeyGenConfig,
    secret_manager: SecretManagerService,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> eyre::Result<()> {
    tracing::info!("starting oprf-key-gen with config: {config:#?}");
    let cancellation_token = nodes_common::spawn_shutdown_task(shutdown_signal);

    tracing::info!("init oprf key-gen service..");
    tracing::info!("loading private from secret manager..");
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
    let (transaction_handler, transaction_handler_handle) = TransactionHandler::new(
        config.max_wait_time_transaction_confirmation,
        config.max_transaction_attempts,
        party_id,
        config.oprf_key_registry_contract,
        provider.clone(),
        address,
        cancellation_token.clone(),
    )
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

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    let axum_cancel_token = cancellation_token.clone();
    let server = tokio::spawn(async move {
        tracing::info!(
            "starting axum server on {}",
            listener
                .local_addr()
                .map(|x| x.to_string())
                .unwrap_or(String::from("invalid addr"))
        );
        let axum_shutdown_signal = axum_cancel_token.clone();
        let axum_result = axum::serve(listener, key_gen_router)
            .with_graceful_shutdown(async move { axum_shutdown_signal.cancelled().await })
            .await;
        tracing::info!("axum server shutdown");
        if let Err(err) = axum_result {
            tracing::error!("got error from axum: {err:?}");
        }
        // we cancel the token in case axum encountered an error to shutdown the service
        axum_cancel_token.cancel();
    });

    tracing::info!("everything started successfully - now waiting for shutdown...");
    cancellation_token.cancelled().await;

    tracing::info!(
        "waiting for shutdown of services (max wait time {:?})..",
        config.max_wait_time_shutdown
    );
    match tokio::time::timeout(config.max_wait_time_shutdown, async move {
        tokio::join!(server, key_event_watcher, transaction_handler_handle)
    })
    .await
    {
        Ok(_) => tracing::info!("successfully finished shutdown in time"),
        Err(_) => tracing::warn!("could not finish shutdown in time"),
    }

    Ok(())
}
