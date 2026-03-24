pub mod test_secret_manager;

#[cfg(feature = "postgres-test-container")]
pub mod postgres {
    use eyre::Context as _;
    use sqlx::{Connection as _, Executor as _, PgConnection};
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::ContainerAsync;

    pub const TEST_ETH_PRIVATE_KEY: &str =
        "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba";
    pub const TEST_ETH_ADDRESS: &str = "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc";
    pub const TEST_SCHEMA: &str = "test";

    pub async fn open_pg_connection(
        connection_string: &str,
        schema: &str,
    ) -> eyre::Result<PgConnection> {
        let mut conn = PgConnection::connect(connection_string)
            .await
            .context("while opening PgConnection")?;
        let schema_connect = &format!(
            r#"
                CREATE SCHEMA IF NOT EXISTS "{schema}";
                SET search_path TO "{schema}";
            "#,
        );
        conn.execute(schema_connect.as_ref())
            .await
            .context("TestUtils: cannot pg_connection")?;
        Ok(conn)
    }

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
