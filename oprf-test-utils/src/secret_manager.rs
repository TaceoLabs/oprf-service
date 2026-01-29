pub mod test_secret_manager;

#[cfg(feature = "aws-test-container")]
pub mod aws {
    use aws_config::Region;
    use aws_sdk_secretsmanager::config::Credentials;
    use testcontainers_modules::{
        localstack::LocalStack,
        testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _},
    };

    pub const WALLET_SECRET_ID: &str = "wallet_secret_id";
    pub const OPRF_SECRET_ID_PREFIX: &str = "oprf_suffix";

    pub async fn localstack_testcontainer() -> eyre::Result<(ContainerAsync<LocalStack>, String)> {
        let container = LocalStack::default()
            .with_env_var("SERVICES", "secretsmanager")
            .start()
            .await?;
        let host_ip = container.get_host().await?;
        let host_port = container.get_host_port_ipv4(4566).await?;
        let endpoint_url = format!("http://{host_ip}:{host_port}");
        Ok((container, endpoint_url))
    }

    pub async fn localstack_config(url: &str) -> aws_config::SdkConfig {
        let region_provider = Region::new("us-east-1");
        let credentials = Credentials::new("test", "test", None, None, "Static");
        // use TEST_AWS_ENDPOINT_URL if set in testcontainer
        aws_config::from_env()
            .region(region_provider)
            .endpoint_url(url)
            .credentials_provider(credentials)
            .load()
            .await
    }

    pub async fn dummy_localstack_config() -> aws_config::SdkConfig {
        localstack_config("dummy").await
    }

    pub async fn localstack_client(
        url: &str,
    ) -> (aws_sdk_secretsmanager::Client, aws_config::SdkConfig) {
        let aws_config = localstack_config(url).await;
        (aws_sdk_secretsmanager::Client::new(&aws_config), aws_config)
    }

    pub async fn load_secret(
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
}

#[cfg(feature = "postgres-test-container")]
pub mod postgres {
    use eyre::Context as _;
    use sqlx::{Connection as _, PgConnection};
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::ContainerAsync;

    pub const TEST_WALLET_PRIVATE_KEY_SECRET_ID: &str = "some-secret-id";
    pub const TEST_ETH_PRIVATE_KEY: &str =
        "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba";
    pub const TEST_ETH_ADDRESS: &str = "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc";

    pub async fn open_pg_connection(connection_string: &str) -> eyre::Result<PgConnection> {
        PgConnection::connect(connection_string)
            .await
            .context("while opening PgConnection")
    }

    #[cfg(feature = "aws-test-container")]
    pub async fn postgres_testcontainer() -> eyre::Result<(ContainerAsync<Postgres>, String)> {
        use testcontainers_modules::testcontainers::runners::AsyncRunner as _;

        let postgres_container = testcontainers_modules::postgres::Postgres::default()
            .start()
            .await?;
        let connection_string = format!(
            "postgres://postgres:postgres@{}:{}/postgres",
            postgres_container.get_host().await.unwrap(),
            postgres_container.get_host_port_ipv4(5432).await.unwrap()
        );
        Ok((postgres_container, connection_string))
    }
}
