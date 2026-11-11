#![deny(missing_docs)]
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
    pubsub::{ConnectionHandle, PubSubConnect},
    signers::local::PrivateKeySigner,
    transports::{TransportErrorKind, TransportResult, http::reqwest},
};
use eyre::Context as _;
use groth16_material::circom::CircomGroth16MaterialBuilder;
use nodes_common::web3::{self, event_stream::ChainCursor};
use oprf_store::{aad::AadContext, format::StorageFormat};
use oprf_types::{chain::OprfKeyRegistry, crypto::PartyId, service::NodeInformation};
use secrecy::ExposeSecret;
use tokio_util::sync::CancellationToken;

pub(crate) mod api;
pub mod config;
pub mod metrics;
pub mod postgres;
pub(crate) mod services;

pub use nodes_common::Environment;
pub use nodes_common::StartedServices;
pub use services::event_cursor_store;
pub use services::secret_manager;

/// The tasks spawned by the key-gen library. Should call [`KeyGenTasks::join`] when shutting down for graceful shutdown.
pub struct KeyGenTasks {
    key_event_watcher: tokio::task::JoinHandle<eyre::Result<()>>,
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
        self.cursor_checkpoint_task.await?;
        Ok(())
    }
}

// Wraps WsConnect but refuses all reconnect attempts.
//
// When the WS connection drops, alloy's pubsub service calls `try_reconnect()` before
// propagating the error. Returning a NonRetryable error here causes the service to shut
// down immediately, which closes the subscription broadcast channel. The key-event-watcher
// then sees `RecvError::Closed`, its event stream yields `None`, and the task returns
// `Ok(())`. The cancellation-token drop-guard fires, the whole process exits cleanly, and
// the supervisor (k8s) restarts it. On restart, `EventStreamBuilder` backfills missed events
// from the persisted `ChainCursor`.
//
// Why not `WsConnect::with_max_retries(0)`?
// alloy-pubsub v2 always makes ONE reconnect attempt before checking the counter, so
// `max_retries = 0` still silently reconnects on transient errors and keeps the subscription
// alive — missing the gap events entirely.
struct NoReconnect(WsConnect);

impl PubSubConnect for NoReconnect {
    fn is_local(&self) -> bool {
        self.0.is_local()
    }

    fn connect(
        &self,
    ) -> impl core::future::Future<Output = TransportResult<ConnectionHandle>> + Send {
        self.0.connect()
    }

    fn try_reconnect(
        &self,
    ) -> impl core::future::Future<Output = TransportResult<ConnectionHandle>> + Send {
        core::future::ready(Err(TransportErrorKind::non_retryable_str(
            "WS connection lost - refusing to reconnect so the service restarts and backfills",
        )))
    }
}

async fn contract_sanity_checks(
    rpc_provider: &web3::HttpRpcProvider,
    key_gen_wallet_address: Address,
    config: &OprfKeyGenServiceConfig,
) -> eyre::Result<NodeInformation> {
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
    tracing::info!("we are party id: {party_id}. Threshold/NumPeers also match",);
    Ok(NodeInformation::new(
        party_id,
        key_gen_wallet_address.to_string(),
        config.expected_threshold,
    ))
}

/// Returns the chain id bound into stored ciphertexts: the one the RPC reports.
///
/// If `envelopeV1` is allowed, the configured `rpc.chain_id` must be set and equal to it, so
/// that ciphertexts are never bound to the chain of a misconfigured RPC.
fn storage_chain_id(config: &OprfKeyGenServiceConfig, rpc_chain_id: u64) -> eyre::Result<u64> {
    if config
        .allowed_storage_formats
        .contains(&StorageFormat::EnvelopeV1)
    {
        let configured = config.rpc_provider_config.chain_id.ok_or_else(|| {
            eyre::eyre!(
                "rpc.chain_id must be configured when envelopeV1 is allowed (the RPC reports chain id {rpc_chain_id})"
            )
        })?;
        eyre::ensure!(
            configured == rpc_chain_id,
            "configured rpc.chain_id {configured} does not match chain id {rpc_chain_id} reported by the RPC"
        );
    }
    Ok(rpc_chain_id)
}

/// Stores the node information, then prepares the storage of secrets, bound to this deployment
/// (chain, registry, party, threshold).
async fn init_storage(
    secret_manager: &SecretManagerService,
    rpc_provider: &web3::HttpRpcProvider,
    config: &OprfKeyGenServiceConfig,
    node_information: NodeInformation,
) -> eyre::Result<()> {
    let party_id = node_information.party_id();
    secret_manager
        .store_node_information(node_information)
        .await
        .context("while storing node information in secret manager")?;

    let rpc_chain_id = rpc_provider
        .get_chain_id()
        .await
        .context("while loading chain id")?;
    let aad_context = AadContext {
        chain_id: storage_chain_id(config, rpc_chain_id)?,
        registry: config.oprf_key_registry_contract,
        party_id,
        threshold: config.expected_threshold,
    };
    secret_manager
        .prepare_storage(aad_context)
        .await
        .context("while preparing storage")?;
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
/// - Validates the storage configuration (`OprfKeyGenServiceConfig::validate_storage`).
/// - Initializes the Ethereum wallet from the configured private key.
/// - Initializes the RPC provider used to interact with the configured blockchain.
/// - Fetches and logs the wallet balance.
/// - Loads the party ID from the `OprfKeyRegistry` contract to verify that this
///   node is registered as a participant.
/// - Stores the node information (wallet address, party ID, threshold) in the configured
///   secret manager.
/// - Prepares the storage of secrets (`SecretManager::prepare_storage`): loads or creates the
///   data keys and upgrades `direct` rows to the configured write format.
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
///
/// # Returns
/// Returns:
/// - An `axum::Router` exposing the service endpoints.
/// - A `KeyGenTasks` handle containing the spawned tasks.
///
/// # Errors
/// Returns an error if:
/// - the storage configuration is invalid,
/// - the configured wallet private key cannot be parsed,
/// - the RPC provider cannot be initialized,
/// - the node is not registered in the `OprfKeyRegistry` contract,
/// - the configured chain id does not match the RPC while `envelopeV1` is allowed,
/// - preparing the storage fails,
/// - the Groth16 proving material cannot be built.
pub async fn start(
    config: OprfKeyGenServiceConfig,
    secret_manager: SecretManagerService,
    chain_cursor_service: ChainCursorService,
    started_services: StartedServices,
    cancellation_token: CancellationToken,
) -> eyre::Result<(axum::Router, KeyGenTasks)> {
    tracing::info!("init oprf key-gen service..");
    config
        .validate_storage()
        .context("invalid storage configuration")?;

    let private_key = PrivateKeySigner::from_str(config.wallet_private_key.expose_secret())
        .context("while loading wallet private key")?;
    let address = private_key.address();
    tracing::info!("my wallet address: {address}");
    let wallet = EthereumWallet::from(private_key);

    let reqwest_client = reqwest::ClientBuilder::new()
        .timeout(config.rpc_http_timeout)
        // set connection pool to zero to force a new connection on every HTTP request.
        // This should prevent talking to stale/lagging nodes for a longer period
        .pool_max_idle_per_host(0)
        .build()
        .context("while building reqwest Client")?;

    let http_rpc_provider =
        nodes_common::web3::HttpRpcProviderBuilder::with_config(&config.rpc_provider_config)
            .environment(config.environment)
            .reqwest_client(reqwest_client)
            .wallet(wallet)
            .build()
            .context("while init blockchain connection")?;

    // NoReconnect refuses reconnects so that on WS connection errors the pubsub service shuts
    // down, the event stream ends, and the supervisor can restart the process to backfill
    // missed events from the persisted ChainCursor. See `NoReconnect` for the full rationale.
    let ws_rpc_provider = ProviderBuilder::new()
        .connect_pubsub_with(NoReconnect(WsConnect::new(
            config.ws_rpc_url.expose_secret(),
        )))
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

    let node_info = contract_sanity_checks(&http_rpc_provider, address, &config)
        .await
        .context("while doing sanity checks")?;

    init_storage(&secret_manager, &http_rpc_provider, &config, node_info).await?;

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
        sleep_between_simulation: config.sleep_between_simulation,
        max_tries_simulation: config.max_tries_simulation,
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
                explicit_backfill_block: config.explicit_backfill_block,
            },
        )
    });

    let key_gen_router = api::routes(address, started_services.clone());

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
                tracing::warn!(%err, "cannot fetch checkpoint for cursor - trying again in {checkpoint_interval:?}");
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
                    tracing::warn!(
                        ?err,
                        "cannot persist checkpoint to DB - trying again in {checkpoint_interval:?}"
                    );
                }
            }
        }
    }
    tracing::info!("shutting down cursor checkpoint task");
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroU16, path::PathBuf};

    use alloy::primitives::Address;
    use nodes_common::web3::HttpRpcProviderConfig;
    use oprf_store::format::StorageFormat;
    use secrecy::SecretString;

    use crate::{
        Environment,
        config::{OprfKeyGenServiceConfig, OprfKeyGenServiceConfigMandatoryValues},
    };

    fn config(allowed: &[StorageFormat], chain_id: Option<u64>) -> OprfKeyGenServiceConfig {
        let mut config =
            OprfKeyGenServiceConfig::with_default_values(OprfKeyGenServiceConfigMandatoryValues {
                environment: Environment::Dev,
                oprf_key_registry_contract: Address::ZERO,
                wallet_private_key: SecretString::from("0x01"),
                zkey_path: PathBuf::from("zkey"),
                witness_graph_path: PathBuf::from("graph"),
                expected_threshold: NonZeroU16::new(2).expect("non-zero"),
                expected_num_peers: NonZeroU16::new(3).expect("non-zero"),
                rpc_provider_config: HttpRpcProviderConfig::with_default_values([
                    "http://localhost:8545",
                ])
                .expect("valid url"),
                ws_rpc_url: SecretString::from("ws://localhost:8546"),
            });
        config.allowed_storage_formats = allowed.to_vec();
        config.rpc_provider_config.chain_id = chain_id;
        config
    }

    #[test]
    fn storage_chain_id() {
        let envelope = [StorageFormat::Direct, StorageFormat::EnvelopeV1];

        let err = super::storage_chain_id(&config(&envelope, None), 1)
            .expect_err("envelopeV1 needs a configured chain id");
        assert!(err.to_string().contains("rpc.chain_id"), "{err}");

        let err = super::storage_chain_id(&config(&envelope, Some(1)), 2)
            .expect_err("a mismatching chain id is refused");
        let err = err.to_string();
        assert!(
            err.contains("rpc.chain_id 1") && err.contains("chain id 2"),
            "the error must name both chain ids: {err}"
        );

        assert_eq!(
            super::storage_chain_id(&config(&envelope, Some(1)), 1).expect("matching chain id"),
            1,
            "a matching chain id is used"
        );
        assert_eq!(
            super::storage_chain_id(&config(&[StorageFormat::Direct], None), 7)
                .expect("direct-only needs no configured chain id"),
            7,
            "direct-only uses the chain id of the RPC"
        );
    }
}
