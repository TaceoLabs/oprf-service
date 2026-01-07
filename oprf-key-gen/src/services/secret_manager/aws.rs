//! AWS Secret Manager Implementation
//!
//! This module provides an implementation of [`SecretManager`] using AWS Secrets Manager
//! to store and retrieve RP (Relying Party) secrets.
//!
//! The module supports both production and development environments:
//! - Production: Uses standard AWS credentials and configuration
//! - Development: Uses LocalStack with hardcoded test credentials
//!
//! Secrets are stored as JSON objects containing the RP's public key, nullifier key,
//! and current/previous epoch secrets.

use alloy::{hex, signers::local::PrivateKeySigner};
use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueError;
use k256::ecdsa::SigningKey;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use std::str::FromStr as _;
use zeroize::Zeroize as _;

use async_trait::async_trait;
use eyre::{Context, ContextCompat};
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfKeyMaterial};
use secrecy::{ExposeSecret, SecretString};
use tracing::instrument;

use crate::services::secret_manager::SecretManager;

/// AWS Secret Manager client wrapper.
#[derive(Debug, Clone)]
pub struct AwsSecretManager {
    client: aws_sdk_secretsmanager::Client,
    oprf_secret_id_prefix: String,
    wallet_private_key_secret_id: String,
}

impl AwsSecretManager {
    /// Initializes an AWS secret manager client.
    ///
    /// Loads AWS configuration from the environment and wraps the client
    /// in a `SecretManagerService`.
    pub async fn init(
        aws_config: aws_config::SdkConfig,
        oprf_secret_id_prefix: &str,
        wallet_private_key_secret_id: &str,
    ) -> Self {
        // loads the latest defaults for aws
        let client = aws_sdk_secretsmanager::Client::new(&aws_config);
        AwsSecretManager {
            client,
            oprf_secret_id_prefix: oprf_secret_id_prefix.to_string(),
            wallet_private_key_secret_id: wallet_private_key_secret_id.to_string(),
        }
    }
}

#[async_trait]
impl SecretManager for AwsSecretManager {
    async fn load_or_insert_wallet_private_key(&self) -> eyre::Result<PrivateKeySigner> {
        tracing::debug!(
            "checking if there exists a private key at: {}",
            self.wallet_private_key_secret_id
        );
        let mut hex_private_key = match self
            .client
            .get_secret_value()
            .secret_id(&self.wallet_private_key_secret_id)
            .send()
            .await
        {
            Ok(secret_string) => {
                tracing::info!("loaded wallet private key from secret-manager");
                SecretString::from(
                    secret_string
                        .secret_string
                        .context("expected string private-key, but is byte")?,
                )
            }
            Err(x) => {
                match x.into_service_error() {
                    GetSecretValueError::ResourceNotFoundException(_) => {
                        tracing::info!("secret not found - will create wallet");
                        // Create a new wallet
                        let private_key = SigningKey::random(&mut rand::thread_rng());
                        let mut private_key_bytes = private_key.to_bytes();
                        let hex_string =
                            SecretString::from(hex::encode_prefixed(private_key_bytes));
                        private_key_bytes.zeroize();
                        tracing::debug!("uploading secret to AWS..");
                        self.client
                            .create_secret()
                            .name(&self.wallet_private_key_secret_id)
                            .secret_string(hex_string.expose_secret())
                            .send()
                            .await
                            .context("while creating wallet secret")?;
                        hex_string
                    }
                    x => Err(x)?,
                }
            }
        };

        let private_key = PrivateKeySigner::from_str(hex_private_key.expose_secret())
            .context("while reading wallet private key")?;
        // set private key to all zeroes
        hex_private_key.zeroize();
        Ok(private_key)
    }

    #[instrument(level = "info", skip(self))]
    async fn get_previous_share(
        &self,
        oprf_key_id: OprfKeyId,
        generated_epoch: ShareEpoch,
    ) -> eyre::Result<Option<DLogShareShamir>> {
        tracing::debug!("loading latest share for {oprf_key_id}");
        let secret_id = to_key_secret_id(&self.oprf_secret_id_prefix, oprf_key_id);
        let secret_value_res = self
            .client
            .get_secret_value()
            .secret_id(secret_id.clone())
            .send()
            .await;
        let secret_value = match secret_value_res {
            Ok(secret_value) => secret_value
                .secret_string()
                .expect("is string and not binary")
                .to_owned(),
            Err(err) => match err.into_service_error() {
                GetSecretValueError::ResourceNotFoundException(_) => {
                    tracing::debug!("cannot find {oprf_key_id}");
                    return Ok(None);
                }
                x => eyre::bail!(x),
            },
        };

        let oprf_key_material: OprfKeyMaterial =
            serde_json::from_str(&secret_value).context("Cannot deserialize AWS Secret")?;
        if let Some((stored_epoch, share)) = oprf_key_material.get_latest_share() {
            tracing::debug!("my latest epoch is: {stored_epoch}");
            if stored_epoch.next() == generated_epoch {
                Ok(Some(share))
            } else {
                tracing::debug!("we missed an epoch - returning None");
                Ok(None)
            }
        } else {
            tracing::warn!("does not contain any shares..");
            Ok(None)
        }
    }

    /// Stores a new DLog share for an OPRF secret-key in AWS Secrets Manager.
    ///
    /// Creates a new secret with the configured prefix and OPRF key id.
    #[instrument(level = "info", skip_all)]
    async fn store_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
        oprf_key_material: OprfKeyMaterial,
    ) -> eyre::Result<()> {
        let secret_id = to_key_secret_id(&self.oprf_secret_id_prefix, oprf_key_id);
        self.client
            .create_secret()
            .name(secret_id)
            .secret_string(serde_json::to_string(&oprf_key_material).expect("can serialize"))
            .send()
            .await
            .context("while creating secret")?;
        tracing::info!("created new OPRF secret for {oprf_key_id}");
        Ok(())
    }

    /// Removes an OPRF secret from AWS Secrets Manager.
    ///
    /// Permanently deletes the secret without recovery period.
    #[instrument(level = "info", skip(self))]
    async fn remove_oprf_key_material(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        let secret_id = to_key_secret_id(&self.oprf_secret_id_prefix, oprf_key_id);
        self.client
            .delete_secret()
            .secret_id(secret_id)
            .force_delete_without_recovery(true)
            .send()
            .await
            .context("while deleting DLog Share")?;
        tracing::info!("deleted secret from AWS {oprf_key_id}");
        Ok(())
    }

    /// Updates an OPRF secret with a new epoch.
    ///
    /// Loads the existing secret, moves the current epoch to previous,
    /// and stores the new share as the current epoch.
    #[instrument(level = "info", skip(self, share))]
    async fn update_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> eyre::Result<()> {
        // Load old secret to preserve previous epoch
        let secret_id = to_key_secret_id(&self.oprf_secret_id_prefix, oprf_key_id);
        tracing::info!("loading old secret first at {secret_id}");
        let secret_value = self
            .client
            .get_secret_value()
            .secret_id(secret_id.clone())
            .send()
            .await
            .context("while loading old secret")?
            .secret_string()
            .expect("is string and not binary")
            .to_owned();

        let mut oprf_key_material: OprfKeyMaterial =
            serde_json::from_str(&secret_value).context("Cannot deserialize AWS Secret")?;

        oprf_key_material.insert_share(epoch, share);
        self.client
            .put_secret_value()
            .secret_id(secret_id)
            .secret_string(serde_json::to_string(&oprf_key_material).expect("can serialize"))
            .send()
            .await
            .context("while storing new secret")?;
        tracing::debug!("updated rp secret for {oprf_key_id} with new epoch: {epoch}");
        Ok(())
    }
}

/// Constructs the full secret ID for an OPRF key-id in AWS Secrets Manager.
///
/// Combines the prefix with the OPRF key-id.
#[inline(always)]
fn to_key_secret_id(key_secret_id_prefix: &str, oprf_key_id: OprfKeyId) -> String {
    format!("{}/{}", key_secret_id_prefix, oprf_key_id.into_inner())
}

#[cfg(test)]
mod test {
    use std::str::FromStr as _;

    use alloy::signers::local::PrivateKeySigner;
    use aws_config::Region;
    use aws_sdk_secretsmanager::config::Credentials;
    use testcontainers_modules::{
        localstack::LocalStack,
        testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _},
    };

    use crate::services::secret_manager::{SecretManager as _, aws::AwsSecretManager};

    const WALLET_SECRET_ID: &str = "wallet_secret_id";
    const OPRF_SECRET_ID_PREFIX: &str = "oprf_suffix";
    async fn localstack_testcontainer() -> eyre::Result<(ContainerAsync<LocalStack>, String)> {
        let container = LocalStack::default()
            .with_env_var("SERVICES", "secretsmanager")
            .start()
            .await?;
        let host_ip = container.get_host().await?;
        let host_port = container.get_host_port_ipv4(4566).await?;
        let endpoint_url = format!("http://{host_ip}:{host_port}");
        Ok((container, endpoint_url))
    }

    async fn localstack_client(
        url: &str,
    ) -> (aws_sdk_secretsmanager::Client, aws_config::SdkConfig) {
        let region_provider = Region::new("us-east-1");
        let credentials = Credentials::new("test", "test", None, None, "Static");
        // use TEST_AWS_ENDPOINT_URL if set in testcontainer
        let aws_config = aws_config::from_env()
            .region(region_provider)
            .endpoint_url(url)
            .credentials_provider(credentials)
            .load()
            .await;
        (aws_sdk_secretsmanager::Client::new(&aws_config), aws_config)
    }

    async fn load_secret(
        client: aws_sdk_secretsmanager::Client,
        secret_id: &str,
    ) -> eyre::Result<String> {
        let secret = client
            .get_secret_value()
            .secret_id(secret_id)
            .send()
            .await?
            .secret_string()
            .ok_or_else(|| eyre::eyre!("is not a secret-string"))?
            .to_owned();
        Ok(secret)
    }

    #[tokio::test]
    async fn load_eth_wallet_empty() -> eyre::Result<()> {
        let (_localstack_container, localstack_url) = localstack_testcontainer().await?;
        let (client, config) = localstack_client(&localstack_url).await;
        let secret_manager =
            AwsSecretManager::init(config, OPRF_SECRET_ID_PREFIX, WALLET_SECRET_ID).await;
        let _ = load_secret(client.clone(), WALLET_SECRET_ID)
            .await
            .expect_err("should not be there");

        let secret_string_new_created = secret_manager.load_or_insert_wallet_private_key().await?;
        let secret_string_loading = secret_manager.load_or_insert_wallet_private_key().await?;
        assert_eq!(secret_string_new_created, secret_string_loading);
        let is_secret = PrivateKeySigner::from_str(&load_secret(client, WALLET_SECRET_ID).await?)
            .expect("valid private key");
        assert_eq!(is_secret, secret_string_new_created);

        Ok(())
    }
}
