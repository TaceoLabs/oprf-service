use clap::Parser;
use eyre::Context;
use oprf_client::Connector;
use oprf_test::{health_checks, oprf_key_registry_scripts};
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use secrecy::ExposeSecret;
use std::time::Instant;
use tokio::task::JoinSet;

use crate::{OprfDevClientConfig, run_oprf};

#[derive(Clone, Parser, Debug)]
pub struct EndlessRunCommand {
    /// The amount of nullifiers to generate
    #[clap(long, env = "OPRF_DEV_CLIENT_NULLIFIER_NUM", default_value = "10")]
    pub oprf_per_epoch: usize,

    /// How many epochs should we do until we are finished.
    #[clap(long, env = "OPRF_DEV_CLIENT_NULLIFIER_NUM", default_value = "10")]
    pub iterations: Option<usize>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn endless_run(
    config: OprfDevClientConfig,
    oprf_key_id: OprfKeyId,
    oprf_public_key: OprfPublicKey,
    endless_run_cmd: EndlessRunCommand,
    connector: Connector,
) -> eyre::Result<()> {
    let mut epoch = ShareEpoch::from(config.start_epoch);
    let EndlessRunCommand {
        oprf_per_epoch,
        iterations,
    } = endless_run_cmd;
    let iterations = iterations.unwrap_or(usize::MAX);
    for run in 0..iterations {
        let instant = Instant::now();
        let mut runs = (0..oprf_per_epoch)
            .map(|_| {
                let connector = connector.clone();
                let nodes = config.services.clone();
                let use_last_epoch = rand::random::<bool>();
                let tested_epoch = if use_last_epoch { epoch.prev() } else { epoch };
                async move {
                    run_oprf(
                        nodes,
                        tested_epoch,
                        config.threshold,
                        oprf_key_id,
                        connector,
                    )
                    .await
                }
            })
            .collect::<JoinSet<_>>();
        let mut counter = 0;
        while let Some(result) = runs.join_next().await {
            result
                .context("could not join")?
                .context("while doing nullifier run")?;
            tracing::debug!("oprf {counter}/{oprf_per_epoch}...");
            counter += 1;
        }
        let elapsed = instant.elapsed();
        if iterations == usize::MAX {
            tracing::info!("finished run {} in {elapsed:?}..", run + 1);
        } else {
            tracing::info!("finished run {}/{iterations} in {elapsed:?}..", run + 1);
        }
        epoch = epoch.next();
        if run != iterations - 1 {
            oprf_key_registry_scripts::init_reshare(
                oprf_key_id,
                config.chain_rpc_url.expose_secret(),
                config.oprf_key_registry_contract,
                config.taceo_private_key.expose_secret(),
            );
            let new_key = health_checks::oprf_public_key_from_services(
                oprf_key_id,
                epoch,
                &config.services,
                config.max_wait_time_key_gen,
            )
            .await?;
            assert_eq!(new_key, oprf_public_key);
        }
    }
    Ok(())
}
