use std::num::NonZeroU16;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::secret_manager::{
    SecretManager, SecretManagerError,
    postgres::{
        Address, DekWrapper, EnvelopeError, NodeStorageConfig, PostgresSecretManager, StorageFormat,
    },
};
use async_trait::async_trait;
use nodes_common::postgres::{PostgresConfig, SanitizedSchema};
use nodes_common::test_utils::SharedPostgres;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_store::{
    InMemoryWrapper, KmsError, StorageCrypto, aad::AadContext, data_keys::DataKeyError,
};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    crypto::{OprfKeyMaterial, OprfPublicKey, PartyId},
    service::NodeInformation,
};
use ruint::aliases::U160;
use secrecy::SecretString;
use sqlx::PgConnection;
use uuid::Uuid;
use zeroize::Zeroizing;

const KEY_ARN: &str = "arn:aws:kms:eu-central-1:000000000000:key/test";
const CHAIN_ID: u64 = 31337;
const PARTY_ID: u16 = 1;
const THRESHOLD: u16 = 2;

fn registry() -> Address {
    Address::repeat_byte(0xAA)
}

/// The AAD context an envelope manager builds from [`envelope_storage`] and the seeded
/// `node_information`.
fn aad_context() -> AadContext {
    AadContext {
        chain_id: CHAIN_ID,
        registry: registry(),
        party_id: PartyId(PARTY_ID),
        threshold: NonZeroU16::new(THRESHOLD).expect("non-zero"),
    }
}

fn wrapper() -> InMemoryWrapper {
    InMemoryWrapper::new(KEY_ARN, [1; 32])
}

/// A storage config allowing `allowed`, with every value `envelopeV1` needs.
fn envelope_storage(allowed: &[StorageFormat]) -> NodeStorageConfig {
    let mut storage = NodeStorageConfig::direct_only();
    storage.allowed_storage_formats = allowed.to_vec();
    storage.kms_key_arn = Some(KEY_ARN.to_owned());
    storage.chain_id = Some(CHAIN_ID);
    storage.oprf_key_registry_contract = Some(registry());
    storage
}

/// A wrapper that counts `unwrap` calls and fails every one of them.
#[derive(Default)]
struct FailingWrapper {
    unwraps: AtomicUsize,
}

impl FailingWrapper {
    fn unwraps(&self) -> usize {
        self.unwraps.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl DekWrapper for FailingWrapper {
    fn key_arn(&self) -> &str {
        KEY_ARN
    }

    async fn generate(&self, _: Uuid) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), KmsError> {
        Err(KmsError::Unwrap)
    }

    async fn unwrap(&self, _: Uuid, _: &[u8]) -> Result<Zeroizing<[u8; 32]>, KmsError> {
        self.unwraps.fetch_add(1, Ordering::SeqCst);
        Err(KmsError::Unwrap)
    }
}

/// A fresh, migrated schema; the container handle must be kept alive for the whole test.
async fn migrated_schema() -> eyre::Result<(Arc<SharedPostgres>, SanitizedSchema, PgConnection)> {
    let pg = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let schema = nodes_common::test_utils::next_test_schema();
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    oprf_store::MIGRATOR.run(&mut conn).await?;
    Ok((pg, schema, conn))
}

async fn init_manager(
    pg: &SharedPostgres,
    schema: &SanitizedSchema,
    storage: &NodeStorageConfig,
    wrapper: Option<Arc<dyn DekWrapper>>,
) -> eyre::Result<PostgresSecretManager> {
    PostgresSecretManager::init_with_wrapper(
        &PostgresConfig::with_default_values(
            SecretString::from(pg.connection_string.clone()),
            schema.clone(),
        ),
        storage,
        wrapper,
    )
    .await
}

async fn postgres_secret_manager()
-> eyre::Result<(PostgresSecretManager, Arc<SharedPostgres>, SanitizedSchema)> {
    let (pg, schema, _) = migrated_schema().await?;
    let mgr = PostgresSecretManager::init(
        &PostgresConfig::with_default_values(
            SecretString::from(pg.connection_string.clone()),
            schema.clone(),
        ),
        &NodeStorageConfig::direct_only(),
    )
    .await?;
    Ok((mgr, pg, schema))
}

async fn insert_row(
    oprf_key_id: OprfKeyId,
    share: DLogShareShamir,
    epoch: ShareEpoch,
    public_key: OprfPublicKey,
    connection: &mut PgConnection,
) -> eyre::Result<()> {
    oprf_store::test_utils::insert_share(connection, oprf_key_id, epoch, &share, &public_key)
        .await?;
    Ok(())
}

async fn delete_row(oprf_key_id: OprfKeyId, connection: &mut PgConnection) -> eyre::Result<()> {
    let success = sqlx::query(
        "
            UPDATE shares
            SET
                share = NULL,
                deleted = true
            WHERE id = $1
        ",
    )
    .bind(oprf_key_id.to_le_bytes())
    .execute(connection)
    .await?;
    assert_eq!(success.rows_affected(), 1);
    Ok(())
}

async fn insert_node_information(
    eth_address: &str,
    party_id: i32,
    threshold: u16,
    connection: &mut PgConnection,
) -> eyre::Result<()> {
    sqlx::query(
        "
            INSERT INTO node_information (id, eth_address, party_id, threshold)
            VALUES (TRUE, $1, $2, $3)
        ",
    )
    .bind(eth_address)
    .bind(party_id)
    .bind(i32::from(threshold))
    .execute(connection)
    .await?;
    Ok(())
}

/// Stores the `node_information` the envelope tests' [`aad_context`] is built from.
async fn insert_test_node_information(connection: &mut PgConnection) -> eyre::Result<()> {
    insert_node_information(
        "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
        i32::from(PARTY_ID),
        THRESHOLD,
        connection,
    )
    .await
}

/// Creates a data key and returns a policy that seals shares under it with [`aad_context`].
async fn envelope_writer(connection: &mut PgConnection) -> eyre::Result<StorageCrypto> {
    let dek = oprf_store::data_keys::create(connection, &wrapper()).await?;
    let id = dek.id();
    Ok(
        StorageCrypto::new(&[StorageFormat::EnvelopeV1], aad_context(), vec![dek])
            .with_write(StorageFormat::EnvelopeV1, Some(id))?,
    )
}

/// A random live share.
struct ShareValues {
    oprf_key_id: OprfKeyId,
    epoch: ShareEpoch,
    share: DLogShareShamir,
    public_key: OprfPublicKey,
}

impl ShareValues {
    fn random(id: u64) -> Self {
        Self {
            oprf_key_id: OprfKeyId::new(U160::from(id)),
            epoch: ShareEpoch::new(7),
            share: DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>()),
            public_key: OprfPublicKey::new(rand::random()),
        }
    }

    async fn insert_sealed(
        &self,
        connection: &mut PgConnection,
        crypto: &StorageCrypto,
    ) -> eyre::Result<()> {
        oprf_store::test_utils::insert_share_sealed(
            connection,
            crypto,
            self.oprf_key_id,
            self.epoch,
            &self.share,
            &self.public_key,
        )
        .await?;
        Ok(())
    }

    fn assert_matches(&self, material: &OprfKeyMaterial) {
        assert_eq!(
            ark_babyjubjub::Fr::from(material.share()),
            ark_babyjubjub::Fr::from(self.share.clone()),
            "share must match"
        );
        assert!(material.is_epoch(self.epoch), "epoch must match");
        assert_eq!(
            material.public_key(),
            self.public_key,
            "public key must match"
        );
    }
}

/// A schema with `node_information`, one data key and two `envelopeV1` share rows.
struct SealedRows {
    pg: Arc<SharedPostgres>,
    schema: SanitizedSchema,
    conn: PgConnection,
    row: ShareValues,
    other: ShareValues,
}

impl SealedRows {
    async fn new() -> eyre::Result<Self> {
        let (pg, schema, mut conn) = migrated_schema().await?;
        insert_test_node_information(&mut conn).await?;
        let writer = envelope_writer(&mut conn).await?;
        let row = ShareValues::random(42);
        let other = ShareValues::random(43);
        row.insert_sealed(&mut conn, &writer).await?;
        other.insert_sealed(&mut conn, &writer).await?;
        Ok(Self {
            pg,
            schema,
            conn,
            row,
            other,
        })
    }

    /// Starts an envelope manager configured with `storage` and reads [`SealedRows::row`].
    async fn read_with(
        &self,
        storage: &NodeStorageConfig,
    ) -> eyre::Result<Result<OprfKeyMaterial, SecretManagerError>> {
        let mgr = init_manager(&self.pg, &self.schema, storage, Some(Arc::new(wrapper()))).await?;
        Ok(mgr.get_oprf_key_material(self.row.oprf_key_id).await)
    }

    async fn read(&self) -> eyre::Result<Result<OprfKeyMaterial, SecretManagerError>> {
        self.read_with(&envelope_storage(&[StorageFormat::EnvelopeV1]))
            .await
    }

    async fn execute(&mut self, sql: &'static str) -> eyre::Result<()> {
        let updated = sqlx::query(sql)
            .bind(self.row.oprf_key_id.to_le_bytes())
            .execute(&mut self.conn)
            .await?;
        assert_eq!(updated.rows_affected(), 1, "{sql} must change one row");
        Ok(())
    }
}

#[track_caller]
fn assert_decrypt_fails(result: Result<OprfKeyMaterial, SecretManagerError>, what: &str) {
    let err = result.expect_err("tampered row must not be readable");
    assert!(
        matches!(
            err,
            SecretManagerError::StorageFormat(EnvelopeError::Decrypt)
        ),
        "{what}: expected StorageFormat(Decrypt), got {err:?}"
    );
}

#[tokio::test]
async fn load_node_information_empty() -> eyre::Result<()> {
    let (secret_manager, _pg, _) = postgres_secret_manager().await?;
    let report = secret_manager
        .load_node_information()
        .await
        .expect_err("should be an error");
    assert_eq!(
        report.to_string(),
        "Cannot get node information from DB, maybe key-gen needs to start"
    );
    Ok(())
}

#[tokio::test]
async fn load_node_information_success() -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_secret_manager().await?;

    let should_address = "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc";
    let should_party_id = PartyId(42);
    let should_threshold = 2;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    insert_node_information(
        should_address,
        i32::from(should_party_id.into_inner()),
        should_threshold,
        &mut conn,
    )
    .await?;

    let is_node_information = secret_manager
        .load_node_information()
        .await
        .expect("Should work");
    assert_eq!(
        is_node_information,
        NodeInformation::new(
            should_party_id,
            should_address.to_string(),
            NonZeroU16::try_from(should_threshold).expect("is non-zero")
        )
    );
    Ok(())
}

#[tokio::test]
async fn test_get_oprf_key_material() -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_secret_manager().await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;

    let oprf_key_id0 = OprfKeyId::new(U160::from(42));
    let oprf_key_id1 = OprfKeyId::new(U160::from(128));
    let oprf_key_id_unknown = OprfKeyId::new(U160::from(6891));
    let public_key0 = OprfPublicKey::new(rand::random());
    let public_key1 = OprfPublicKey::new(rand::random());
    let epoch0 = ShareEpoch::new(42);
    let epoch1 = ShareEpoch::new(32819);
    let share0 = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());
    let share1 = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    insert_row(oprf_key_id0, share0.clone(), epoch0, public_key0, &mut conn).await?;
    insert_row(oprf_key_id1, share1.clone(), epoch1, public_key1, &mut conn).await?;

    let key_material0 = secret_manager.get_oprf_key_material(oprf_key_id0).await?;
    assert_eq!(
        ark_babyjubjub::Fr::from(key_material0.share()),
        ark_babyjubjub::Fr::from(share0)
    );
    assert!(key_material0.is_epoch(epoch0));
    assert_eq!(key_material0.public_key(), public_key0);

    // unknown key id should return UnknownOprfKeyId
    assert!(matches!(
        secret_manager
            .get_oprf_key_material(oprf_key_id_unknown)
            .await,
        Err(SecretManagerError::UnknownOprfKeyId(_))
    ));

    let key_material1 = secret_manager.get_oprf_key_material(oprf_key_id1).await?;
    assert_eq!(
        ark_babyjubjub::Fr::from(key_material1.share()),
        ark_babyjubjub::Fr::from(share1)
    );
    assert!(key_material1.is_epoch(epoch1));
    assert_eq!(key_material1.public_key(), public_key1);

    Ok(())
}

#[tokio::test]
async fn test_get_deleted_secret() -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_secret_manager().await?;
    let oprf_key_id = OprfKeyId::new(U160::from(42));
    let public_key = OprfPublicKey::new(rand::random());
    let epoch = ShareEpoch::new(42);
    let share = DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>());

    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    insert_row(oprf_key_id, share.clone(), epoch, public_key, &mut conn).await?;

    delete_row(oprf_key_id, &mut conn).await?;

    let err = secret_manager
        .get_oprf_key_material(oprf_key_id)
        .await
        .expect_err("should fail with deleted");
    // deleted key should return DeletedOprfKeyId
    assert!(
        matches!(err, SecretManagerError::DeletedOprfKeyId(is_key_id) if is_key_id == oprf_key_id),
        "should be Err(DeletedOprfKeyId({oprf_key_id})) but is {err}"
    );
    Ok(())
}

#[tokio::test]
async fn reads_envelope_share() -> eyre::Result<()> {
    let rows = SealedRows::new().await?;
    let material = rows.read().await??;
    rows.row.assert_matches(&material);
    Ok(())
}

#[tokio::test]
async fn rejects_direct_row_when_direct_not_allowed() -> eyre::Result<()> {
    let (pg, schema, mut conn) = migrated_schema().await?;
    insert_test_node_information(&mut conn).await?;
    let row = ShareValues::random(42);
    insert_row(
        row.oprf_key_id,
        row.share.clone(),
        row.epoch,
        row.public_key,
        &mut conn,
    )
    .await?;
    let mgr = init_manager(
        &pg,
        &schema,
        &envelope_storage(&[StorageFormat::EnvelopeV1]),
        Some(Arc::new(wrapper())),
    )
    .await?;

    let err = mgr
        .get_oprf_key_material(row.oprf_key_id)
        .await
        .expect_err("a direct row must be refused");
    assert!(
        matches!(
            err,
            SecretManagerError::StorageFormat(EnvelopeError::FormatNotAllowed(
                StorageFormat::Direct
            ))
        ),
        "expected StorageFormat(FormatNotAllowed(Direct)), got {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn rejects_envelope_row_when_only_direct_allowed() -> eyre::Result<()> {
    let (secret_manager, pg, schema) = postgres_secret_manager().await?;
    let mut conn =
        nodes_common::test_utils::open_pg_connection(&pg.connection_string, &schema).await?;
    let writer = envelope_writer(&mut conn).await?;
    let row = ShareValues::random(42);
    row.insert_sealed(&mut conn, &writer).await?;

    // The direct-only manager has no wrapper: rejecting the row must not need the data key.
    let err = secret_manager
        .get_oprf_key_material(row.oprf_key_id)
        .await
        .expect_err("an envelopeV1 row must be refused");
    assert!(
        matches!(
            err,
            SecretManagerError::StorageFormat(EnvelopeError::FormatNotAllowed(
                StorageFormat::EnvelopeV1
            ))
        ),
        "expected StorageFormat(FormatNotAllowed(EnvelopeV1)), not unknown or deleted, got {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn changed_public_key_fails_decrypt() -> eyre::Result<()> {
    let mut rows = SealedRows::new().await?;
    let other_public_key = oprf_store::codec::to_bytes(&rows.other.public_key);
    let updated = sqlx::query("UPDATE shares SET public_key = $2 WHERE id = $1")
        .bind(rows.row.oprf_key_id.to_le_bytes())
        .bind(other_public_key.as_slice())
        .execute(&mut rows.conn)
        .await?;
    assert_eq!(updated.rows_affected(), 1, "public key changed");
    assert_decrypt_fails(rows.read().await?, "public_key");
    Ok(())
}

#[tokio::test]
async fn changed_epoch_fails_decrypt() -> eyre::Result<()> {
    let mut rows = SealedRows::new().await?;
    rows.execute("UPDATE shares SET epoch = epoch + 1 WHERE id = $1")
        .await?;
    assert_decrypt_fails(rows.read().await?, "epoch");
    Ok(())
}

#[tokio::test]
async fn share_moved_to_other_key_id_fails_decrypt() -> eyre::Result<()> {
    let mut rows = SealedRows::new().await?;
    // Move the whole sealed value: share bytes, public key and epoch (both rows share one data
    // key), so only the key id differs between sealing and opening.
    let moved = sqlx::query(
        "UPDATE shares SET share = o.share, public_key = o.public_key, epoch = o.epoch \
         FROM shares o WHERE shares.id = $1 AND o.id = $2",
    )
    .bind(rows.row.oprf_key_id.to_le_bytes())
    .bind(rows.other.oprf_key_id.to_le_bytes())
    .execute(&mut rows.conn)
    .await?;
    assert_eq!(moved.rows_affected(), 1, "share bytes moved");
    assert_decrypt_fails(rows.read().await?, "key id");
    Ok(())
}

#[tokio::test]
async fn changed_threshold_fails_decrypt() -> eyre::Result<()> {
    let mut rows = SealedRows::new().await?;
    sqlx::query("UPDATE node_information SET threshold = threshold + 1")
        .execute(&mut rows.conn)
        .await?;
    assert_decrypt_fails(rows.read().await?, "threshold");
    Ok(())
}

#[tokio::test]
async fn changed_party_id_fails_decrypt() -> eyre::Result<()> {
    let mut rows = SealedRows::new().await?;
    sqlx::query("UPDATE node_information SET party_id = party_id + 1")
        .execute(&mut rows.conn)
        .await?;
    assert_decrypt_fails(rows.read().await?, "party_id");
    Ok(())
}

#[tokio::test]
async fn other_chain_id_fails_decrypt() -> eyre::Result<()> {
    let rows = SealedRows::new().await?;
    let mut storage = envelope_storage(&[StorageFormat::EnvelopeV1]);
    storage.chain_id = Some(CHAIN_ID + 1);
    assert_decrypt_fails(rows.read_with(&storage).await?, "chain_id");
    Ok(())
}

#[tokio::test]
async fn other_registry_fails_decrypt() -> eyre::Result<()> {
    let rows = SealedRows::new().await?;
    let mut storage = envelope_storage(&[StorageFormat::EnvelopeV1]);
    storage.oprf_key_registry_contract = Some(Address::repeat_byte(0xBB));
    assert_decrypt_fails(rows.read_with(&storage).await?, "registry");
    Ok(())
}

#[tokio::test]
async fn loads_data_key_created_after_startup() -> eyre::Result<()> {
    let (pg, schema, mut conn) = migrated_schema().await?;
    insert_test_node_information(&mut conn).await?;
    let mgr = init_manager(
        &pg,
        &schema,
        &envelope_storage(&[StorageFormat::EnvelopeV1]),
        Some(Arc::new(wrapper())),
    )
    .await?;

    let writer = envelope_writer(&mut conn).await?;
    let row = ShareValues::random(42);
    row.insert_sealed(&mut conn, &writer).await?;

    let material = mgr.get_oprf_key_material(row.oprf_key_id).await?;
    row.assert_matches(&material);
    Ok(())
}

#[tokio::test]
async fn failed_data_key_load_is_cached() -> eyre::Result<()> {
    let (pg, schema, mut conn) = migrated_schema().await?;
    insert_test_node_information(&mut conn).await?;
    let failing = Arc::new(FailingWrapper::default());
    // Started with an empty `data_keys` table, so startup calls no `unwrap`.
    let mut mgr = init_manager(
        &pg,
        &schema,
        &envelope_storage(&[StorageFormat::EnvelopeV1]),
        Some(failing.clone()),
    )
    .await?;
    let writer = envelope_writer(&mut conn).await?;
    let row = ShareValues::random(42);
    row.insert_sealed(&mut conn, &writer).await?;

    for attempt in 0..2 {
        let err = mgr
            .get_oprf_key_material(row.oprf_key_id)
            .await
            .expect_err("the data key cannot be unwrapped");
        assert!(
            matches!(err, SecretManagerError::Internal(_)),
            "attempt {attempt}: expected Internal, got {err:?}"
        );
    }
    assert_eq!(failing.unwraps(), 1, "the failure is remembered");

    // Paused tokio time cannot be used with the database fixture; end the window instead.
    mgr.set_failed_load_retention(std::time::Duration::ZERO);
    mgr.get_oprf_key_material(row.oprf_key_id)
        .await
        .expect_err("the data key still cannot be unwrapped");
    assert_eq!(
        failing.unwraps(),
        2,
        "after the window the key is loaded again"
    );
    Ok(())
}

#[tokio::test]
async fn unknown_data_key_is_error() -> eyre::Result<()> {
    let mut rows = SealedRows::new().await?;
    let unknown = Uuid::new_v4();
    sqlx::query("ALTER TABLE shares DROP CONSTRAINT shares_data_key_id_fkey")
        .execute(&mut rows.conn)
        .await?;
    sqlx::query("UPDATE shares SET data_key_id = $2 WHERE id = $1")
        .bind(rows.row.oprf_key_id.to_le_bytes())
        .bind(unknown)
        .execute(&mut rows.conn)
        .await?;

    let err = rows
        .read()
        .await?
        .expect_err("a row under an unknown data key must be refused");
    assert!(
        matches!(err, SecretManagerError::StorageFormat(EnvelopeError::UnknownDataKey(id)) if id == unknown),
        "expected StorageFormat(UnknownDataKey({unknown})), got {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn init_fails_on_unwrap_error() -> eyre::Result<()> {
    let (pg, schema, mut conn) = migrated_schema().await?;
    insert_test_node_information(&mut conn).await?;
    oprf_store::data_keys::create(&mut conn, &wrapper()).await?;

    let err = init_manager(
        &pg,
        &schema,
        &envelope_storage(&[StorageFormat::EnvelopeV1]),
        Some(Arc::new(InMemoryWrapper::new(KEY_ARN, [2; 32]))),
    )
    .await
    .expect_err("a data key that cannot be unwrapped must fail startup");
    assert!(
        matches!(err.downcast_ref(), Some(DataKeyError::Kms(_))),
        "expected a KMS error, got {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn init_fails_on_key_arn_mismatch() -> eyre::Result<()> {
    let (pg, schema, mut conn) = migrated_schema().await?;
    insert_test_node_information(&mut conn).await?;
    oprf_store::data_keys::create(
        &mut conn,
        &InMemoryWrapper::new("arn:aws:kms:eu-central-1:000000000000:key/other", [1; 32]),
    )
    .await?;

    let err = init_manager(
        &pg,
        &schema,
        &envelope_storage(&[StorageFormat::EnvelopeV1]),
        Some(Arc::new(wrapper())),
    )
    .await
    .expect_err("a data key under another KMS key must fail startup");
    assert!(
        matches!(
            err.downcast_ref(),
            Some(DataKeyError::KeyArnMismatch { .. })
        ),
        "expected KeyArnMismatch, got {err:?}"
    );
    Ok(())
}

#[test]
fn config_validation() {
    let envelope = || envelope_storage(&[StorageFormat::Direct, StorageFormat::EnvelopeV1]);
    NodeStorageConfig::direct_only()
        .validate()
        .expect("direct only is valid");
    envelope().validate().expect("complete envelope is valid");

    let mut empty = NodeStorageConfig::direct_only();
    empty.allowed_storage_formats.clear();
    let mut no_arn = envelope();
    no_arn.kms_key_arn = None;
    let mut alias_arn = envelope();
    alias_arn.kms_key_arn = Some("arn:aws:kms:eu-central-1:000000000000:alias/oprf".to_owned());
    let mut no_chain_id = envelope();
    no_chain_id.chain_id = None;
    let mut no_registry = envelope();
    no_registry.oprf_key_registry_contract = None;
    for (config, field) in [
        (empty, "allowed_storage_formats"),
        (no_arn, "kms_key_arn"),
        (alias_arn, "full key ARN"),
        (no_chain_id, "chain_id"),
        (no_registry, "oprf_key_registry_contract"),
    ] {
        let err = config.validate().expect_err("invalid config");
        assert!(
            err.to_string().contains(field),
            "the error must name {field}: {err}"
        );
    }
}

#[tokio::test]
async fn deleted_row_needs_no_key() -> eyre::Result<()> {
    let (pg, schema, mut conn) = migrated_schema().await?;
    insert_test_node_information(&mut conn).await?;
    let failing = Arc::new(FailingWrapper::default());
    let mgr = init_manager(
        &pg,
        &schema,
        &envelope_storage(&[StorageFormat::EnvelopeV1]),
        Some(failing.clone()),
    )
    .await?;
    let writer = envelope_writer(&mut conn).await?;
    let row = ShareValues::random(42);
    row.insert_sealed(&mut conn, &writer).await?;
    delete_row(row.oprf_key_id, &mut conn).await?;

    let err = mgr
        .get_oprf_key_material(row.oprf_key_id)
        .await
        .expect_err("the row is deleted");
    assert!(
        matches!(err, SecretManagerError::DeletedOprfKeyId(id) if id == row.oprf_key_id),
        "expected DeletedOprfKeyId, got {err:?}"
    );
    assert_eq!(
        failing.unwraps(),
        0,
        "no data key is loaded for a deleted row"
    );
    Ok(())
}
