//! This module provides an implementation of [`SecretManager`] using a Postgres database to store shares.
//!
//! Additionally, fetches the node-provider's Ethereum address from the DB.

use std::collections::{BTreeMap, HashMap};

use ark_serialize::CanonicalDeserialize;
use async_trait::async_trait;
use eyre::Context as _;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    crypto::{OprfKeyMaterial, OprfPublicKey},
};
use secrecy::{ExposeSecret as _, SecretString};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tracing::instrument;

use crate::{oprf_key_material_store::OprfKeyMaterialStore, secret_manager::SecretManager};

/// The postgres secret manager wrapping a `PgPool`. As we don't want to have multiple connections, we set the `max_pool_size` to 1.
pub struct PostgresSecretManager(PgPool);

#[derive(Debug, sqlx::FromRow)]
struct ShareRow {
    id: Vec<u8>,
    current: Vec<u8>,
    prev: Option<Vec<u8>>,
    epoch: i64,
    public_key: Vec<u8>,
}

impl From<ShareRow> for (OprfKeyId, OprfKeyMaterial) {
    fn from(value: ShareRow) -> Self {
        let id = OprfKeyId::from_le_slice(&value.id);
        let current = from_db_ark_deserialize_uncompressed::<DLogShareShamir>(value.current);
        let prev = value
            .prev
            .map(from_db_ark_deserialize_uncompressed::<DLogShareShamir>);
        // We store as i64, so this always fits into u32
        let epoch = ShareEpoch::new(value.epoch as u32);

        let oprf_public_key =
            from_db_ark_deserialize_uncompressed::<OprfPublicKey>(value.public_key);

        let mut shares = BTreeMap::new();
        shares.insert(epoch, current);

        if let Some(prev) = prev {
            shares.insert(epoch.prev(), prev);
        }

        (id, OprfKeyMaterial::new(shares, oprf_public_key))
    }
}

impl PostgresSecretManager {
    /// Initializes a `PostgresSecretManager` by connecting to the provided `connection_string`. Will open only a single connection to the DB.
    #[instrument(level = "info", skip_all)]
    pub async fn init(connection_string: &SecretString) -> eyre::Result<Self> {
        // we only need one connection but as this will be used behind an Arc, we can't use PgConnection, as this needs a mutable reference to execute queries.
        tracing::info!("connecting to DB...");
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(connection_string.expose_secret())
            .await
            .context("while connecting to postgres DB")?;
        // we don't run migrations, we just read
        // TODO do we need to check version of the DB to fast crash if migrations don't match?
        Ok(Self(pool))
    }
}

#[async_trait]
impl SecretManager for PostgresSecretManager {
    #[instrument(level = "info", skip_all)]
    async fn load_secrets(&self) -> eyre::Result<OprfKeyMaterialStore> {
        tracing::info!("fetching all OPRF keys from DB..");
        let rows: Vec<ShareRow> = sqlx::query_as(
            r#"
                SELECT
                    id,
                    current,
                    prev,
                    epoch,
                    public_key
                FROM shares
            "#,
        )
        .fetch_all(&self.0)
        .await
        .context("while fetching all OPRF keys")?;
        tracing::debug!("loaded {} rows. parsing..", rows.len());
        let map = rows
            .into_iter()
            .map(db_row_into_key_material)
            .collect::<HashMap<_, _>>();
        tracing::info!("successfully parsed {} OPRF entries", map.len());
        Ok(OprfKeyMaterialStore::new(map))
    }

    #[instrument(level = "info", skip_all)]
    async fn get_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
    ) -> eyre::Result<Option<OprfKeyMaterial>> {
        let maybe_row: Option<ShareRow> = sqlx::query_as(
            r#"
                SELECT
                    id,
                    current,
                    prev,
                    epoch,
                    public_key
                FROM shares
                WHERE id = $1 AND epoch = $2
            "#,
        )
        .bind(oprf_key_id.to_le_bytes())
        .bind(i64::from(epoch.into_inner()))
        .fetch_optional(&self.0)
        .await
        .context("while fetching previous share")?;
        if let Some(row) = maybe_row {
            tracing::info!("found new key-material!");
            let (_, key_material) = db_row_into_key_material(row);
            Ok(Some(key_material))
        } else {
            tracing::debug!("Cannot find share for requested key and epoch");
            Ok(None)
        }
    }
}

#[inline(always)]
fn from_db_ark_deserialize_uncompressed<T: CanonicalDeserialize>(b: Vec<u8>) -> T {
    T::deserialize_uncompressed_unchecked(b.as_slice()).expect("DB is sane")
}

/// Converts a row from the DB to an entry in the [`OprfKeyMaterialStore`]. This method will panic if the DB is not sane (i.e., has corrupted data stored).
fn db_row_into_key_material(row: ShareRow) -> (OprfKeyId, OprfKeyMaterial) {
    let id = OprfKeyId::from_le_slice(&row.id);
    let current = from_db_ark_deserialize_uncompressed::<DLogShareShamir>(row.current);
    let prev = row
        .prev
        .map(from_db_ark_deserialize_uncompressed::<DLogShareShamir>);
    // We store as i64, so this always fits into u32
    let epoch = ShareEpoch::new(row.epoch as u32);

    let oprf_public_key = from_db_ark_deserialize_uncompressed::<OprfPublicKey>(row.public_key);

    let mut shares = BTreeMap::new();
    shares.insert(epoch, current);

    if let Some(prev) = prev {
        shares.insert(epoch.prev(), prev);
    }

    (id, OprfKeyMaterial::new(shares, oprf_public_key))
}
