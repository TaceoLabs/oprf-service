//! End-to-end tests of converting a deployment from `direct` (plaintext) storage to
//! `envelopeV1`, the way a node operator rolls it out:
//!
//! 1. everything on the defaults (`direct`);
//! 2. nodes allow `[direct, envelopeV1]` while the rows are still `direct`;
//! 3. key-gen restarts writing `envelopeV1`, which upgrades every row while the nodes keep
//!    running;
//! 4. `direct` is removed from the allowed formats everywhere.
#![allow(clippy::large_futures, reason = "doesnt matter for tests")]

use std::time::Duration;

use axum::extract::ws::close_code;
use eyre::Context as _;
use sqlx::PgPool;
use taceo_oprf::core::ddlog_equality::shamir::DLogProofShareShamir;
use taceo_oprf::service::secret_manager::{
    SecretManager as _, SecretManagerError,
    postgres::{
        EnvelopeError,
        StorageFormat::{self, Direct, EnvelopeV1},
    },
};
use taceo_oprf::types::{
    OprfKeyId, ShareEpoch,
    api::{OprfPublicKeyWithEpoch, OprfResponse, oprf_error_codes},
    crypto::OprfPublicKey,
};
use taceo_oprf_test::{
    TEST_TIMEOUT,
    key_gen_setup::{TestKeyGen, TestKeyGenConfig, keygen_asserts},
    node_setup::{self, TestNode, TestNodeConfig, WireFormat},
    setup::{DeploySetup, TestSetup},
};
use tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
use uuid::Uuid;

const KEY_A: u32 = 42;
const KEY_B: u32 = 43;
const KEY_C: u32 = 44;

/// Short enough that a running node reads a share again (e.g. after a reshare) within a test.
const NODE_STORE_TTL: Duration = Duration::from_secs(1);

fn key(id: u32) -> OprfKeyId {
    OprfKeyId::from(id)
}

fn with_epoch(key: OprfPublicKey, epoch: ShareEpoch) -> OprfPublicKeyWithEpoch {
    OprfPublicKeyWithEpoch { key, epoch }
}

/// Starts three key-gens with the given storage settings, all using the in-memory KMS of
/// `kms_party`.
async fn start_key_gens_sharing_kms(
    setup: &TestSetup,
    allowed: &[StorageFormat],
    write: StorageFormat,
    kms_party: usize,
) -> eyre::Result<[TestKeyGen; 3]> {
    let start = |party_id| {
        TestKeyGen::start(
            setup,
            TestKeyGenConfig::new(party_id)
                .with_storage(allowed, write)
                .with_kms_of(kms_party),
        )
    };
    let (k0, k1, k2) = tokio::join!(start(0), start(1), start(2));
    Ok([k0?, k1?, k2?])
}

/// Restarts `key_gen` on its database with new storage settings.
async fn restart_with_storage(
    setup: &TestSetup,
    key_gen: TestKeyGen,
    allowed: &[StorageFormat],
    write: StorageFormat,
) -> eyre::Result<TestKeyGen> {
    let config = key_gen.shutdown().await?.with_storage(allowed, write);
    TestKeyGen::start(setup, config).await
}

async fn restart_key_gens(
    setup: &TestSetup,
    key_gens: [TestKeyGen; 3],
    allowed: &[StorageFormat],
    write: StorageFormat,
) -> eyre::Result<[TestKeyGen; 3]> {
    let [k0, k1, k2] = key_gens;
    let (k0, k1, k2) = tokio::join!(
        restart_with_storage(setup, k0, allowed, write),
        restart_with_storage(setup, k1, allowed, write),
        restart_with_storage(setup, k2, allowed, write),
    );
    Ok([k0?, k1?, k2?])
}

fn node_config(key_gen: &TestKeyGen, allowed: &[StorageFormat]) -> TestNodeConfig {
    TestNodeConfig {
        accepted_oprf_key_ids: vec![key(KEY_A), key(KEY_B), key(KEY_C)],
        store_ttl: Some(NODE_STORE_TTL),
        ..TestNodeConfig::for_key_gen(key_gen).with_storage(allowed)
    }
}

/// Starts one node per key-gen, reading from that key-gen's database.
async fn start_nodes(
    key_gens: &[TestKeyGen],
    allowed: &[StorageFormat],
) -> eyre::Result<Vec<TestNode>> {
    let mut nodes = Vec::with_capacity(key_gens.len());
    for key_gen in key_gens {
        let node = TestNode::start(node_config(key_gen, allowed))
            .await
            .with_context(|| format!("while starting node {}", key_gen.party_id))?;
        nodes.push(node);
    }
    Ok(nodes)
}

/// Asserts that every row with secrets in every key-gen database is stored as `format`, and that
/// `shares` is not empty.
async fn assert_rows_stored_as(
    key_gens: &[TestKeyGen],
    format: StorageFormat,
    phase: &str,
) -> eyre::Result<()> {
    for key_gen in key_gens {
        let party = key_gen.party_id;
        let shares: Vec<String> = sqlx::query_scalar("SELECT storage_format FROM shares")
            .fetch_all(&key_gen.pool)
            .await?;
        assert!(!shares.is_empty(), "{phase}: party {party} has no shares");
        assert!(
            shares.iter().all(|f| f == format.as_str()),
            "{phase}: party {party} stores shares as {shares:?}, expected all {format}"
        );
        // Finished key generations delete their rows, so this table may be empty here.
        let in_progress: Vec<String> =
            sqlx::query_scalar("SELECT storage_format FROM in_progress_keygens")
                .fetch_all(&key_gen.pool)
                .await?;
        assert!(
            in_progress.iter().all(|f| f == format.as_str()),
            "{phase}: party {party} stores in-progress key generations as {in_progress:?}, expected all {format}"
        );
    }
    Ok(())
}

async fn assert_data_key_count(
    key_gens: &[TestKeyGen],
    expected: i64,
    phase: &str,
) -> eyre::Result<()> {
    for key_gen in key_gens {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM data_keys")
            .fetch_one(&key_gen.pool)
            .await?;
        assert_eq!(
            count, expected,
            "{phase}: party {} has {count} data keys, expected {expected}",
            key_gen.party_id
        );
    }
    Ok(())
}

async fn receive(
    ws: &mut axum_test::TestWebSocket,
    what: &str,
) -> eyre::Result<tungstenite::Message> {
    tokio::time::timeout(TEST_TIMEOUT, ws.receive_message())
        .await
        .with_context(|| format!("{what}: no answer from the node in time"))
}

/// Parses a JSON answer of the node; any other message (e.g. a close frame) is an error.
fn parse_json<T: serde::de::DeserializeOwned>(
    message: tungstenite::Message,
    what: &str,
) -> eyre::Result<T> {
    let bytes = match message {
        tungstenite::Message::Text(text) => text.as_bytes().to_vec(),
        tungstenite::Message::Binary(bytes) => bytes.to_vec(),
        other => eyre::bail!("{what}: request failed with {other:?}"),
    };
    serde_json::from_slice(&bytes).with_context(|| format!("{what}: cannot parse the answer"))
}

/// Runs both rounds of an OPRF request for `oprf_key_id` against `node` and asserts that the node
/// answers with `expected` as its public key and epoch.
async fn assert_oprf_request_succeeds(
    node: &TestNode,
    oprf_key_id: OprfKeyId,
    expected: &OprfPublicKeyWithEpoch,
    phase: &str,
) -> eyre::Result<()> {
    let what = format!("{phase}: node {} serving key {oprf_key_id}", node.party_id);
    let mut rng = rand::thread_rng();
    let mut ws = node
        .send_request(
            node_setup::request_with_id(oprf_key_id, &mut rng),
            WireFormat::Json,
        )
        .await;
    let response: OprfResponse = parse_json(receive(&mut ws, &what).await?, &what)?;
    assert_eq!(
        response.oprf_pub_key_with_epoch, *expected,
        "{what}: unexpected public key or epoch"
    );

    // The challenge must contain the node's own coefficient (party id + 1) and be sorted.
    let me = u16::try_from(node.party_id).expect("party id fits into u16") + 1;
    let contributing_parties = if me == 1 {
        vec![1, 2]
    } else {
        vec![me - 1, me]
    };
    node_setup::ws_send(
        &mut ws,
        &node_setup::random_challenge(&mut rng, contributing_parties),
        WireFormat::Json,
    )
    .await;
    let _proof_share: DLogProofShareShamir = parse_json(receive(&mut ws, &what).await?, &what)?;
    Ok(())
}

/// Asserts that `node` refuses to use the stored share of `oprf_key_id`: the request fails with
/// an internal error, not with "unknown OPRF key".
async fn assert_oprf_request_refused(
    node: &TestNode,
    oprf_key_id: OprfKeyId,
    phase: &str,
) -> eyre::Result<()> {
    let what = format!("{phase}: node {} serving key {oprf_key_id}", node.party_id);
    let mut ws = node
        .send_request(
            node_setup::request_with_id(oprf_key_id, &mut rand::thread_rng()),
            WireFormat::Json,
        )
        .await;
    match receive(&mut ws, &what).await? {
        tungstenite::Message::Close(Some(frame)) => {
            assert_ne!(
                frame.code,
                CloseCode::from(oprf_error_codes::UNKNOWN_OPRF_KEY_ID),
                "{what}: the node did not find the share at all"
            );
            assert_eq!(
                frame,
                CloseFrame {
                    code: close_code::ERROR.into(),
                    reason: "unexpected error".into(),
                },
                "{what}: expected the node to refuse the stored share"
            );
        }
        other => panic!("{what}: expected the request to be refused, got {other:?}"),
    }
    Ok(())
}

/// The stored share, format and data key of the share row of `oprf_key_id`.
async fn share_row(
    pool: &PgPool,
    oprf_key_id: OprfKeyId,
) -> eyre::Result<(Option<Vec<u8>>, String, Option<Uuid>)> {
    Ok(
        sqlx::query_as("SELECT share, storage_format, data_key_id FROM shares WHERE id = $1")
            .bind(oprf_key_id.to_le_bytes())
            .fetch_one(pool)
            .await?,
    )
}

/// Copies the share row of `oprf_key_id` and the data key row it references (with its KMS key
/// ARN) from the database `from` into `to`, replacing the row of `oprf_key_id` in `to`.
async fn copy_share_row(from: &PgPool, to: &PgPool, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
    let (share, epoch, public_key, storage_format, data_key_id): (
        Vec<u8>,
        i64,
        Vec<u8>,
        String,
        Uuid,
    ) = sqlx::query_as(
        "SELECT share, epoch, public_key, storage_format, data_key_id FROM shares WHERE id = $1",
    )
    .bind(oprf_key_id.to_le_bytes())
    .fetch_one(from)
    .await
    .context("while reading the share row to copy")?;
    let (wrapped_key, wrapping, kms_key_arn): (Vec<u8>, String, String) =
        sqlx::query_as("SELECT wrapped_key, wrapping, kms_key_arn FROM data_keys WHERE id = $1")
            .bind(data_key_id)
            .fetch_one(from)
            .await
            .context("while reading the data key to copy")?;

    let mut tx = to.begin().await?;
    sqlx::query(
        "INSERT INTO data_keys (id, wrapped_key, wrapping, kms_key_arn) VALUES ($1, $2, $3, $4)",
    )
    .bind(data_key_id)
    .bind(wrapped_key)
    .bind(wrapping)
    .bind(kms_key_arn)
    .execute(&mut *tx)
    .await
    .context("while inserting the copied data key")?;
    sqlx::query("DELETE FROM shares WHERE id = $1")
        .bind(oprf_key_id.to_le_bytes())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO shares (id, share, epoch, public_key, storage_format, data_key_id)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(oprf_key_id.to_le_bytes())
    .bind(share)
    .bind(epoch)
    .bind(public_key)
    .bind(storage_format)
    .bind(data_key_id)
    .execute(&mut *tx)
    .await
    .context("while inserting the copied share")?;
    tx.commit().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn three_phase_conversion() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let epoch0 = ShareEpoch::default();
    let epoch1 = epoch0.next();

    // Phase 1: defaults, everything is `direct`.
    let phase = "phase 1";
    let key_gens = TestKeyGen::start_three(&setup).await?;
    setup.init_keygen(key(KEY_A)).await?;
    let public_key_a = keygen_asserts::all_have_key(&key_gens, key(KEY_A), epoch0)
        .await
        .context("phase 1: key generation of A")?;
    assert_rows_stored_as(&key_gens, Direct, phase).await?;
    assert_data_key_count(&key_gens, 0, phase).await?;

    // Phase 2: nodes also allow `envelopeV1`; the rows are still `direct`.
    let phase = "phase 2";
    let nodes = start_nodes(&key_gens, &[Direct, EnvelopeV1])
        .await
        .context("phase 2: starting the nodes")?;
    for node in &nodes {
        assert_oprf_request_succeeds(node, key(KEY_A), &with_epoch(public_key_a, epoch0), phase)
            .await?;
    }
    assert_data_key_count(&key_gens, 0, phase).await?;

    // Phase 3: key-gen restarts writing `envelopeV1` and upgrades every row; the nodes keep
    // running. They started without any data key, so they load the new one on demand.
    let phase = "phase 3";
    let key_gens = restart_key_gens(&setup, key_gens, &[Direct, EnvelopeV1], EnvelopeV1)
        .await
        .context("phase 3: restarting the key-gens with write = envelopeV1")?;
    assert_rows_stored_as(&key_gens, EnvelopeV1, "phase 3 after the upgrade").await?;
    assert_data_key_count(&key_gens, 1, "phase 3 after the upgrade").await?;

    setup.init_keygen(key(KEY_B)).await?;
    let public_key_b = keygen_asserts::all_have_key(&key_gens, key(KEY_B), epoch0)
        .await
        .context("phase 3: key generation of B")?;
    setup.init_reshare(key(KEY_A)).await?;
    let public_key_a_reshared = keygen_asserts::all_have_key(&key_gens, key(KEY_A), epoch1)
        .await
        .context("phase 3: reshare of A")?;
    assert_eq!(
        public_key_a_reshared, public_key_a,
        "phase 3: the reshare changed the public key of A"
    );
    assert_rows_stored_as(&key_gens, EnvelopeV1, "phase 3 after B and the reshare").await?;
    assert_data_key_count(&key_gens, 1, "phase 3 after B and the reshare").await?;

    // Neither B nor A at epoch 1 was ever cached by the running nodes.
    for node in &nodes {
        node.has_key(key(KEY_A), epoch1, public_key_a)
            .await
            .with_context(|| {
                format!(
                    "phase 3: node {} does not report A at epoch 1 in time",
                    node.party_id
                )
            })?;
        assert_oprf_request_succeeds(node, key(KEY_A), &with_epoch(public_key_a, epoch1), phase)
            .await?;
        assert_oprf_request_succeeds(node, key(KEY_B), &with_epoch(public_key_b, epoch0), phase)
            .await?;
    }
    drop(nodes);

    // Phase 4: lock down, `direct` is no longer allowed anywhere.
    let phase = "phase 4";
    let key_gens = restart_key_gens(&setup, key_gens, &[EnvelopeV1], EnvelopeV1)
        .await
        .context("phase 4: restarting the key-gens with allowed = [envelopeV1]")?;
    assert_rows_stored_as(&key_gens, EnvelopeV1, phase).await?;
    assert_data_key_count(&key_gens, 1, phase).await?;
    let nodes = start_nodes(&key_gens, &[EnvelopeV1])
        .await
        .context("phase 4: starting the nodes with allowed = [envelopeV1]")?;
    for node in &nodes {
        assert_oprf_request_succeeds(node, key(KEY_A), &with_epoch(public_key_a, epoch1), phase)
            .await?;
        assert_oprf_request_succeeds(node, key(KEY_B), &with_epoch(public_key_b, epoch0), phase)
            .await?;
    }

    // A valid plaintext share marked `direct` is refused, the other keys keep working.
    nodes[0]
        .add_random_key_material_with_id(key(KEY_C), &mut rand::thread_rng())
        .await?;
    assert_oprf_request_refused(&nodes[0], key(KEY_C), "phase 4: direct row of C").await?;
    let err = nodes[0]
        .secret_manager
        .get_oprf_key_material(key(KEY_C))
        .await
        .expect_err("phase 4: the direct row of C must be refused");
    assert!(
        matches!(
            err,
            SecretManagerError::StorageFormat(EnvelopeError::FormatNotAllowed(Direct))
        ),
        "phase 4: expected StorageFormat(FormatNotAllowed(Direct)), got {err:?}"
    );

    // Restarting key-gen with the same lock-down settings must not upgrade the planted row.
    let [key_gen0, _key_gen1, _key_gen2] = key_gens;
    let row_c = share_row(&key_gen0.pool, key(KEY_C)).await?;
    assert_eq!(row_c.1, Direct.as_str(), "phase 4: C is planted as direct");
    let key_gen0 = key_gen0
        .restart(&setup)
        .await
        .context("phase 4: restarting key-gen 0 with allowed = [envelopeV1]")?;
    assert_eq!(
        share_row(&key_gen0.pool, key(KEY_C)).await?,
        row_c,
        "phase 4: the restart changed the direct row of C"
    );
    assert_oprf_request_refused(
        &nodes[0],
        key(KEY_C),
        "phase 4: direct row of C after the key-gen restart",
    )
    .await?;
    assert_oprf_request_succeeds(
        &nodes[0],
        key(KEY_A),
        &with_epoch(public_key_a, epoch1),
        "phase 4 after refusing C",
    )
    .await?;
    assert_oprf_request_succeeds(
        &nodes[0],
        key(KEY_B),
        &with_epoch(public_key_b, epoch0),
        "phase 4 after refusing C",
    )
    .await?;
    Ok(())
}

/// All parties share one KMS key (one operator running several nodes). A share row copied
/// from party 0's database into party 1's, together with the data key row it references, cannot
/// be read by party 1: the copied data key unwraps under the shared KMS key, but the associated
/// data binds party 0's id, so decryption fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn second_party_cannot_read_copied_row() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let epoch0 = ShareEpoch::default();
    let key_gens = start_key_gens_sharing_kms(&setup, &[EnvelopeV1], EnvelopeV1, 0).await?;
    setup.init_keygen(key(KEY_A)).await?;
    keygen_asserts::all_have_key(&key_gens, key(KEY_A), epoch0)
        .await
        .context("key generation of A")?;
    setup.init_keygen(key(KEY_B)).await?;
    let public_key_b = keygen_asserts::all_have_key(&key_gens, key(KEY_B), epoch0)
        .await
        .context("key generation of B")?;

    copy_share_row(&key_gens[0].pool, &key_gens[1].pool, key(KEY_A)).await?;

    // Started after the copy, party 1's node unwraps every data key at startup, including the
    // copied one, and reads its own rows.
    let node = TestNode::start(node_config(&key_gens[1], &[EnvelopeV1])).await?;
    assert_oprf_request_succeeds(
        &node,
        key(KEY_B),
        &with_epoch(public_key_b, epoch0),
        "after the copy",
    )
    .await?;

    let err = node
        .secret_manager
        .get_oprf_key_material(key(KEY_A))
        .await
        .expect_err("the row copied from party 0 must not be readable");
    assert!(
        matches!(
            err,
            SecretManagerError::StorageFormat(EnvelopeError::Decrypt)
        ),
        "expected StorageFormat(Decrypt), got {err:?}"
    );
    assert_oprf_request_refused(&node, key(KEY_A), "row copied from party 0").await?;
    Ok(())
}
