use std::str::FromStr as _;

use alloy::signers::local::PrivateKeySigner;
use oprf_test_utils::{OPRF_SECRET_ID_PREFIX, WALLET_SECRET_ID};
use taceo_oprf_key_gen::secret_manager::{SecretManager as _, aws::AwsSecretManager};

#[tokio::test]
async fn load_eth_wallet_empty() -> eyre::Result<()> {
    let (_localstack_container, localstack_url) =
        oprf_test_utils::localstack_testcontainer().await?;
    let (client, config) = oprf_test_utils::localstack_client(&localstack_url).await;
    let secret_manager =
        AwsSecretManager::init(config, OPRF_SECRET_ID_PREFIX, WALLET_SECRET_ID).await;
    let _ = oprf_test_utils::load_secret(client.clone(), WALLET_SECRET_ID)
        .await
        .expect_err("should not be there");

    let secret_string_new_created = secret_manager.load_or_insert_wallet_private_key().await?;
    let secret_string_loading = secret_manager.load_or_insert_wallet_private_key().await?;
    assert_eq!(secret_string_new_created, secret_string_loading);
    let is_secret =
        PrivateKeySigner::from_str(&oprf_test_utils::load_secret(client, WALLET_SECRET_ID).await?)
            .expect("valid private key");
    assert_eq!(is_secret, secret_string_new_created);

    Ok(())
}
