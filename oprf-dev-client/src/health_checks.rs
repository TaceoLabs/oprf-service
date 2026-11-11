use std::time::Duration;

use oprf_types::{OprfKeyId, ShareEpoch, api::OprfPublicKeyWithEpoch, crypto::OprfPublicKey};
use reqwest::StatusCode;
use tokio::task::JoinSet;

async fn health_check(health_url: String) {
    loop {
        if let Ok(resp) = reqwest::get(&health_url).await
            && let Ok(resp) = resp.error_for_status()
            && let Ok(msg) = resp.text().await
            && msg == "healthy"
        {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    tracing::info!("healthy: {health_url}");
}

pub async fn service_down(service: &str, max_wait_time: Duration) -> eyre::Result<()> {
    let health_url = format!("{service}/health");
    tokio::time::timeout(max_wait_time, async move {
        loop {
            if reqwest::get(&health_url).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .map_err(|_| eyre::eyre!("services not healthy in provided time: {max_wait_time:?}"))
}

pub async fn services_health_check(
    services: &[String],
    max_wait_time: Duration,
) -> eyre::Result<()> {
    let health_checks = services
        .iter()
        .map(|service| health_check(format!("{service}/health")))
        .collect::<JoinSet<_>>();

    tokio::time::timeout(max_wait_time, health_checks.join_all())
        .await
        .map_err(|_| eyre::eyre!("services not healthy in provided time: {max_wait_time:?}"))?;
    Ok(())
}

async fn load_oprf_public_key(oprf_key_url: String, epoch: Option<ShareEpoch>) -> OprfPublicKey {
    loop {
        if let Ok(response) = reqwest::get(&oprf_key_url)
            .await
            .and_then(|response| response.error_for_status())
            && let Ok(material) = response.json::<OprfPublicKeyWithEpoch>().await
            && epoch.is_none_or(|epoch| material.epoch == epoch)
        {
            return material.key;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Waits until all `services` report the OPRF public key (at `epoch`, if given) and checks they agree.
pub async fn oprf_public_key_from_services(
    oprf_key_id: OprfKeyId,
    epoch: Option<ShareEpoch>,
    services: &[String],
    max_wait_time: Duration,
) -> eyre::Result<OprfPublicKey> {
    let oprf_public_key_checks = services
        .iter()
        .map(|service| load_oprf_public_key(format!("{service}/oprf_pub/{oprf_key_id}"), epoch))
        .collect::<JoinSet<_>>();
    let mut keys = tokio::time::timeout(max_wait_time, oprf_public_key_checks.join_all())
        .await
        .map_err(|_| {
            eyre::eyre!("could not load OPRF material in provided time: {max_wait_time:?}")
        })?;
    let key = keys
        .pop()
        .ok_or_else(|| eyre::eyre!("no services provided"))?;
    if keys.into_iter().any(|other| other != key) {
        eyre::bail!("keys did not match for all services");
    }
    Ok(key)
}

pub async fn oprf_public_key_not_known_check(health_url: String) {
    loop {
        if let Err(err) = reqwest::get(&health_url)
            .await
            .and_then(|response| response.error_for_status())
            && err.status() == Some(StatusCode::NOT_FOUND)
        {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub async fn assert_key_id_unknown(
    oprf_key_id: OprfKeyId,
    services: &[String],
    max_wait_time: Duration,
) -> eyre::Result<()> {
    let health_checks = services
        .iter()
        .map(|service| oprf_public_key_not_known_check(format!("{service}/oprf_pub/{oprf_key_id}")))
        .collect::<JoinSet<_>>();
    tokio::time::timeout(max_wait_time, health_checks.join_all())
        .await
        .map_err(|_| {
            eyre::eyre!(
                "services still have OPRF public-key {oprf_key_id} after: {max_wait_time:?}"
            )
        })?;
    Ok(())
}
