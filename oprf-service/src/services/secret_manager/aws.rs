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

use std::collections::HashMap;
use std::str::FromStr as _;

use alloy::primitives::{Address, U160};
use alloy::signers::local::PrivateKeySigner;
use async_trait::async_trait;
use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueError;
use aws_sdk_secretsmanager::types::{Filter, FilterNameStringType};
use eyre::Context;
use oprf_types::crypto::OprfKeyMaterial;
use oprf_types::{OprfKeyId, ShareEpoch};
use secrecy::zeroize::Zeroize as _;
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
            oprf_secret_id_prefix: oprf_secret_id_prefix.to_owned(),
            wallet_private_key_secret_id: wallet_private_key_secret_id.to_owned(),
        }
    }
}

#[async_trait]
impl SecretManager for AwsSecretManager {
    #[instrument(level = "info", skip_all)]
    async fn load_address(&self) -> eyre::Result<Address> {
        tracing::info!("loading address from secret-manager");
        let mut hex_private_key = SecretString::from(
            self.client
                .get_secret_value()
                .secret_id(self.wallet_private_key_secret_id.clone())
                .send()
                .await
                .context("while loading private-key from secret-manager")?
                .secret_string()
                .ok_or_else(|| eyre::eyre!("is not a secret-string"))?
                .to_owned(),
        );
        let private_key = PrivateKeySigner::from_str(hex_private_key.expose_secret())
            .context("while reading wallet private key")?;
        // set private key to all zeroes
        hex_private_key.zeroize();
        Ok(private_key.address())
    }

    /// Loads all OPRF secrets from AWS Secrets Manager.
    ///
    /// Iterates through all secrets with the configured prefix and deserializes
    /// them into an [`OprfKeyMaterial`]s.
    #[instrument(level = "info", skip_all)]
    async fn load_secrets(&self) -> eyre::Result<HashMap<OprfKeyId, OprfKeyMaterial>> {
        tracing::debug!(
            "loading OPRF secrets with prefix: {}",
            self.oprf_secret_id_prefix
        );
        let mut oprf_materials = HashMap::new();
        let mut next_token = None;
        loop {
            let secrets = self
                .client
                .list_secrets()
                .set_next_token(next_token)
                .filters(
                    Filter::builder()
                        .key(FilterNameStringType::Name)
                        .values(&self.oprf_secret_id_prefix)
                        .build(),
                )
                .send()
                .await?;
            tracing::debug!("got {} secrets", secrets.secret_list().len());
            for secret in secrets.secret_list() {
                if let Some(name) = secret.name() {
                    // The filter is a substring match, so double-check the prefix
                    if name.starts_with(&self.oprf_secret_id_prefix) {
                        let secret_value = self
                            .client
                            .get_secret_value()
                            .secret_id(name)
                            .send()
                            .await
                            .context("while retrieving secret key")?
                            .secret_string()
                            .expect("is string and not binary")
                            .to_owned();
                        let oprf_key_id = from_secret_id(&self.oprf_secret_id_prefix, name)
                            .context("while extracting oprf_key_id from secret id")?;
                        let oprf_secret: OprfKeyMaterial = serde_json::from_str(&secret_value)
                            .context("Cannot deserialize AWS Secret")?;
                        tracing::debug!("loaded secret for oprf_key_id: {oprf_key_id}",);
                        oprf_materials.insert(oprf_key_id, oprf_secret);
                    }
                }
            }

            // if a next_token was returned, there are more secrets to load
            // in that case we include it in the next request and continue
            next_token = secrets.next_token;
            if next_token.is_none() {
                break;
            }
        }
        Ok(oprf_materials)
    }

    #[instrument(level = "info", skip(self))]
    async fn get_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> eyre::Result<Option<OprfKeyMaterial>> {
        let secret_id = to_key_secret_id(&self.oprf_secret_id_prefix, oprf_key_id);
        tracing::debug!("loading secret at {secret_id}");
        match self
            .client
            .get_secret_value()
            .secret_id(secret_id.clone())
            .send()
            .await
        {
            Ok(secret) => {
                tracing::debug!("found {secret_id:?} - checking if correct epoch");
                let secret_value = secret
                    .secret_string()
                    .expect("Is string not binary")
                    .to_owned();
                let key_material: OprfKeyMaterial =
                    serde_json::from_str(&secret_value).context("Cannot deserialize AWS Secret")?;
                if key_material.is_epoch(epoch) {
                    tracing::debug!("Found! Returning");
                    Ok(Some(key_material))
                } else {
                    tracing::debug!(
                        "Cannot find requested epoch in secret-manager, latest epoch is: {:?}",
                        key_material.epoch()
                    );
                    Ok(None)
                }
            }
            Err(x) => match x.into_service_error() {
                GetSecretValueError::ResourceNotFoundException(_) => {
                    tracing::debug!("{secret_id} not yet in secret-manager");
                    Ok(None)
                }
                x => Err(x)?,
            },
        }
    }
}

/// Constructs the full secret ID for an OPRF key-id in AWS Secrets Manager.
///
/// Combines the prefix with the OPRF key-id.
#[inline(always)]
fn to_key_secret_id(key_secret_id_prefix: &str, oprf_key_id: OprfKeyId) -> String {
    format!("{}/{}", key_secret_id_prefix, oprf_key_id.into_inner())
}

/// Extracts the OPRF key-id from a full secret ID in AWS Secrets Manager.
#[inline(always)]
fn from_secret_id(key_secret_id_prefix: &str, secret_id: &str) -> eyre::Result<OprfKeyId> {
    Ok(secret_id
        .strip_prefix(&format!("{}/", key_secret_id_prefix))
        .ok_or_else(|| eyre::eyre!("invalid secret id prefix"))?
        .parse::<U160>()
        .map(OprfKeyId::new)?)
}
