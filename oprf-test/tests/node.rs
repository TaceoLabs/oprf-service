#![allow(clippy::large_futures, reason = "doesnt matter for tests")]

use std::time::Duration;

use axum::extract::ws::close_code;
use http::StatusCode;
use oprf_core::ddlog_equality::shamir::DLogProofShareShamir;
use oprf_service::secret_manager::SecretManager as _;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    api::{DelegateOprfResponse, OprfResponse, oprf_error_codes},
};
use ruint::aliases::U160;
use serde::{Deserialize, Serialize};
use taceo_oprf_test::{
    DeploySetup, OPRF_PEER_ADDRESS_0,
    node_setup::{self, INVALID_AUTH_CODE, INVALID_AUTH_MSG, TestNode, WireFormat},
    wait_until_started,
};
use tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
use uuid::Uuid;

#[derive(Default, Serialize, Deserialize)]
struct BadRequest {
    uuid: Uuid,
}

#[tokio::test]
async fn test_can_fetch_new_key() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    let new_oprf_key_id = OprfKeyId::new(U160::random());
    node.doesnt_have_key(new_oprf_key_id).await?;
    let epoch = ShareEpoch::new(rand::random());
    node.add_random_key_material_with_id_epoch(new_oprf_key_id, epoch, &mut rand::thread_rng())
        .await?;
    let should_key = node
        .secret_manager
        .get_oprf_key_material(new_oprf_key_id)
        .await
        .expect("Just inserted")
        .public_key();
    node.has_key(new_oprf_key_id, epoch, should_key).await?;
    node.happy_path(WireFormat::Json).await;
    node.happy_path(WireFormat::Cbor).await;
    Ok(())
}

/// Covers the `/health`, `/wallet`, `/version` and `/oprf_pub/:id` routes against one node.
#[tokio::test]
async fn test_basic_routes() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    wait_until_started(&node.started_services).await?;

    let result = node.server.get("/health").expect_success().await;
    result.assert_status_ok();
    result.assert_text("healthy");

    let result = node.server.get("/wallet").await;
    result.assert_status_ok();
    result.assert_text(OPRF_PEER_ADDRESS_0.to_string());

    let result = node.server.get("/version").await;
    result.assert_status_ok();
    result.assert_text(nodes_common::version_info!());

    let should_public_key_with_epoch = node
        .secret_manager
        .get_oprf_key_material(OprfKeyId::from(node_setup::OPRF_KEY_ID))
        .await
        .expect("Is there")
        .public_key_with_epoch();
    let result = node
        .server
        .get(&format!("/oprf_pub/{}", node_setup::OPRF_KEY_ID))
        .await;
    result.assert_status_ok();
    result.assert_json(&should_public_key_with_epoch);

    let result = node.server.get("/oprf_pub/1234").await;
    result.assert_status_not_found();

    Ok(())
}

#[tokio::test]
async fn test_health_route_not_ready() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    let _not_started_service = node.started_services.new_service();
    let result = node.server.get("/health").expect_failure().await;
    result.assert_status_service_unavailable();
    result.assert_text("starting");
    Ok(())
}

/// Covers every way the server rejects an unsupported / malformed client version.
#[tokio::test]
async fn client_version_rejected() -> eyre::Result<()> {
    let node = TestNode::start().await?;

    let response = node
        .server
        .get_websocket("/api/test/oprf")
        .add_header(
            oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
            "0.0.0",
        )
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    response.assert_text(format!(
        "invalid version, expected: ^{} got: 0.0.0",
        oprf_client::VERSION
    ));

    let response = node
        .server
        .get_websocket("/api/test/oprf?version=0.0.0")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    response.assert_text(format!(
        "invalid version, expected: ^{} got: 0.0.0",
        oprf_client::VERSION
    ));

    let response = node
        .server
        .get_websocket("/api/test/oprf")
        .add_header(
            oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
            "abc",
        )
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    response.assert_text("invalid HTTP header (x-taceo-oprf-protocol-version)");

    let response = node
        .server
        .get_websocket("/api/test/oprf?version=abc")
        .add_header(
            oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
            oprf_client::VERSION,
        )
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    response.assert_text("Failed to deserialize query string: version: expected semver version");

    let response = node
        .server
        .get_websocket("/api/test/oprf?version=abc")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    response.assert_text("Failed to deserialize query string: version: expected semver version");

    let response = node.server.get_websocket("/api/test/oprf").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    response.assert_text("missing client version");

    Ok(())
}

/// Covers the two ways a client version is accepted: via query param, and via query param
/// taking precedence over a wrong header.
#[tokio::test]
async fn client_version_accepted() -> eyre::Result<()> {
    let node = TestNode::start().await?;

    let mut ws = node
        .server
        .get_websocket(&format!("/api/test/oprf?version={}", oprf_client::VERSION))
        .await
        .into_websocket()
        .await;
    node_setup::ws_send(
        &mut ws,
        &node_setup::request(&mut rand::thread_rng()),
        WireFormat::Json,
    )
    .await;
    let _response = node_setup::ws_recv::<OprfResponse>(&mut ws, WireFormat::Json).await;

    let mut ws = node
        .server
        .get_websocket(&format!("/api/test/oprf?version={}", oprf_client::VERSION))
        .add_header(
            oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
            "0.0.0",
        )
        .await
        .into_websocket()
        .await;
    node_setup::ws_send(
        &mut ws,
        &node_setup::request(&mut rand::thread_rng()),
        WireFormat::Json,
    )
    .await;
    let _response = node_setup::ws_recv::<OprfResponse>(&mut ws, WireFormat::Json).await;

    Ok(())
}

#[tokio::test]
async fn session_timeout_no_message() -> eyre::Result<()> {
    let node = TestNode::start_with_session_lifetime(Duration::from_secs(2)).await?;
    let mut ws = node
        .server
        .get_websocket("/api/test/oprf")
        .add_header(
            oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
            oprf_client::VERSION,
        )
        .await
        .into_websocket()
        .await;
    let should_close_frame = CloseFrame {
        code: oprf_error_codes::TIMEOUT.into(),
        reason: "timeout".into(),
    };
    let is_message =
        tokio::time::timeout(taceo_oprf_test::test_timeout(), ws.receive_message())
            .await
            .expect("should receive close frame before timeout");
    node_setup::assert_close_frame(is_message, &should_close_frame);
    Ok(())
}

/// Test that sending a message that exceeds the maximum allowed size returns the correct close code.
async fn message_too_large_inner(node: &TestNode, format: WireFormat) -> eyre::Result<()> {
    let mut ws = node
        .server
        .get_websocket("/api/test/oprf")
        .add_header(
            oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
            oprf_client::VERSION,
        )
        .await
        .into_websocket()
        .await;

    let oversized_payload = vec![0u8; 2048];
    let msg = match format {
        WireFormat::Json => tungstenite::Message::Text(
            String::from_utf8_lossy(&oversized_payload)
                .to_string()
                .into(),
        ),
        WireFormat::Cbor => tungstenite::Message::Binary(oversized_payload.into()),
    };
    ws.send_message(msg).await;

    let should_close_frame = CloseFrame {
        code: CloseCode::Size,
        reason: "size exceeds max frame length".into(),
    };
    let is_message = ws.receive_message().await;
    node_setup::assert_close_frame(is_message, &should_close_frame);

    Ok(())
}

/// Test that checks that the happy path works
async fn happy_path_inner(node: &TestNode, format: WireFormat) -> eyre::Result<()> {
    node.happy_path(format).await;
    Ok(())
}

/// Test that the session ID is dropped after successfully finished request
async fn drop_session_id_inner(node: &TestNode, format: WireFormat) -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let request0 = node_setup::request(&mut rng);
    let mut request1 = node_setup::request(&mut rng);
    request1.request_id = request0.request_id;

    let mut ws = node.send_request(request0, format).await;

    let _response = node_setup::ws_recv::<OprfResponse>(&mut ws, format).await;
    node_setup::ws_send(
        &mut ws,
        &node_setup::random_challenge(&mut rng, vec![1, 2]),
        format,
    )
    .await;

    // Can deserialize
    let _response = node_setup::ws_recv::<DLogProofShareShamir>(&mut ws, format).await;

    // can finish the second request now
    let mut ws = node.send_request(request1, format).await;

    let _response = node_setup::ws_recv::<OprfResponse>(&mut ws, format).await;
    node_setup::ws_send(
        &mut ws,
        &node_setup::random_challenge(&mut rng, vec![1, 2]),
        format,
    )
    .await;

    // Can deserialize
    let _response = node_setup::ws_recv::<DLogProofShareShamir>(&mut ws, format).await;

    Ok(())
}

/// Checks that successfully closes connection after first message is send if runs into timeout
async fn session_timeout_after_init_inner(format: WireFormat) -> eyre::Result<()> {
    let node = TestNode::start_with_session_lifetime(Duration::from_secs(2)).await?;
    let mut ws = node
        .send_success_init_request(format, &mut rand::thread_rng())
        .await;
    let should_close_frame = CloseFrame {
        code: oprf_error_codes::TIMEOUT.into(),
        reason: "timeout".into(),
    };
    let is_message =
        tokio::time::timeout(taceo_oprf_test::test_timeout(), ws.receive_message())
            .await
            .expect("should receive close frame before timeout");
    node_setup::assert_close_frame(is_message, &should_close_frame);
    Ok(())
}

/// Switch encoding between first and second round
async fn switch_encoding_failed_inner(
    node: &TestNode,
    init_format: WireFormat,
    challenge_format: WireFormat,
) -> eyre::Result<()> {
    let mut ws = node
        .send_success_init_request(init_format, &mut rand::thread_rng())
        .await;

    let challenge = node_setup::random_challenge(&mut rand::thread_rng(), vec![42]);
    let should_close_frame = CloseFrame {
        code: close_code::UNSUPPORTED.into(),
        reason: "unexpected ws message".into(),
    };

    node.challenge_expect_error(&mut ws, challenge, challenge_format, &should_close_frame)
        .await;
    Ok(())
}

#[tokio::test]
async fn switch_encoding_failed() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    switch_encoding_failed_inner(&node, WireFormat::Json, WireFormat::Cbor).await?;
    switch_encoding_failed_inner(&node, WireFormat::Cbor, WireFormat::Json).await?;
    Ok(())
}

/// Test that checks that the happy path works
async fn auth_failed_inner(node: &TestNode, format: WireFormat) -> eyre::Result<()> {
    let mut request = node_setup::request(&mut rand::thread_rng());
    request.auth = node_setup::ConfigurableTestRequestAuth(OprfKeyId::from(123_usize));

    let should_close_frame = CloseFrame {
        code: CloseCode::from(INVALID_AUTH_CODE),
        reason: INVALID_AUTH_MSG.into(),
    };
    node.init_expect_error(&request, format, &should_close_frame)
        .await;
    Ok(())
}

/// Tests that after a key is soft-deleted from the secret manager, the node returns the
/// deleted-key error, for both wire formats.
#[tokio::test]
async fn delete_oprf_key() -> eyre::Result<()> {
    let node = TestNode::start().await?;

    let key_id = OprfKeyId::from(node_setup::OPRF_KEY_ID);
    // soft-delete the key from the secret manager
    node.delete_key_material(key_id).await?;

    // check that we can't query the key any longer
    node.doesnt_have_key(key_id).await?;
    let should_close_frame = CloseFrame {
        code: oprf_error_codes::DELETED_OPRF_KEY_ID.into(),
        reason: "OPRF key already deleted".into(),
    };

    for format in [WireFormat::Json, WireFormat::Cbor] {
        node.init_expect_error(
            node_setup::request(&mut rand::thread_rng()),
            format,
            &should_close_frame,
        )
        .await;
    }

    Ok(())
}

/// Tests that reusing the same session ID for multiple init requests results in an error.
async fn init_session_reuse_inner(node: &TestNode, format: WireFormat) -> eyre::Result<()> {
    let request0 = node_setup::request(&mut rand::thread_rng());
    let mut request1 = node_setup::request(&mut rand::thread_rng());
    request1.request_id = request0.request_id;

    let mut ws0 = node.send_request(request0, format).await;
    // can deserialize success message
    let _ = node_setup::ws_recv::<OprfResponse>(&mut ws0, format).await;

    let should_close_frame = CloseFrame {
        code: oprf_error_codes::SESSION_REUSE.into(),
        reason: "session already in use".into(),
    };
    node.init_expect_error(request1, format, &should_close_frame)
        .await;

    Ok(())
}

/// Tests that an init request with the identity element as blinded query is rejected.
async fn init_bad_blinded_query_inner(node: &TestNode, format: WireFormat) -> eyre::Result<()> {
    let mut request = node_setup::request(&mut rand::thread_rng());
    request.blinded_query = ark_babyjubjub::EdwardsAffine::zero();

    let should_close_frame = CloseFrame {
        code: oprf_error_codes::BLINDED_QUERY_IS_IDENTITY.into(),
        reason: "blinded query must not be identity".into(),
    };

    node.init_expect_error(request, format, &should_close_frame)
        .await;
    Ok(())
}

/// Tests that malformed init requests with missing required fields are rejected.
async fn init_bad_request_inner(node: &TestNode, format: WireFormat) -> eyre::Result<()> {
    let mut ws = node
        .server
        .get_websocket("/api/test/oprf")
        .add_header(
            oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
            oprf_client::VERSION,
        )
        .await
        .into_websocket()
        .await;
    node_setup::ws_send(&mut ws, &BadRequest::default(), format).await;
    let is_message = ws.receive_message().await;
    match is_message {
        tungstenite::Message::Close(Some(is_close_frame)) => {
            assert_eq!(
                is_close_frame.code,
                oprf_error_codes::CORRUPTED_MESSAGE.into()
            );
            let expected_reason = match format {
                WireFormat::Json => "invalid json",
                WireFormat::Cbor => "invalid cbor",
            };
            assert_eq!(is_close_frame.reason.to_string(), expected_reason);
        }
        _ => panic!("unexpected message - expected CloseFrame"),
    }
    Ok(())
}

/// Tests that malformed challenge requests with missing required fields are rejected.
async fn challenge_bad_request_inner(node: &TestNode, format: WireFormat) -> eyre::Result<()> {
    let mut ws = node
        .send_success_init_request(format, &mut rand::thread_rng())
        .await;

    node_setup::ws_send(&mut ws, &BadRequest::default(), format).await;
    let is_message = ws.receive_message().await;
    match is_message {
        tungstenite::Message::Close(Some(is_close_frame)) => {
            assert_eq!(
                is_close_frame.code,
                oprf_error_codes::CORRUPTED_MESSAGE.into()
            );
            let expected_reason = match format {
                WireFormat::Json => "invalid json",
                WireFormat::Cbor => "invalid cbor",
            };
            assert_eq!(is_close_frame.reason.to_string(), expected_reason);
        }
        _ => panic!("unexpected message - expected CloseFrame"),
    }
    Ok(())
}

/// Tests that a challenge with incorrect number of contributing parties is rejected.
async fn challenge_bad_contributing_parties_inner(
    node: &TestNode,
    format: WireFormat,
) -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let mut ws = node.send_success_init_request(format, &mut rng).await;

    let challenge = node_setup::random_challenge(&mut rng, vec![42]);

    let should_close_frame = CloseFrame {
        code: oprf_error_codes::COEFFICIENTS_DOES_NOT_EQUAL_THRESHOLD.into(),
        reason: "not exactly threshold many contributions".into(),
    };

    node.challenge_expect_error(&mut ws, challenge, format, &should_close_frame)
        .await;

    Ok(())
}

/// Tests that a challenge where the current node is not in contributing parties is rejected.
async fn challenge_challenge_not_contributing_party_inner(
    node: &TestNode,
    format: WireFormat,
) -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let mut ws = node.send_success_init_request(format, &mut rng).await;

    let challenge = node_setup::random_challenge(&mut rng, vec![2, 3]);

    let should_close_frame = CloseFrame {
        code: oprf_error_codes::MISSING_MY_COEFFICIENT.into(),
        reason: "contributing parties does not contain my coefficient".into(),
    };

    node.challenge_expect_error(&mut ws, challenge, format, &should_close_frame)
        .await;

    Ok(())
}

/// Tests that contributing parties that are not sorted in ascending order are rejected.
async fn challenge_contributing_parties_not_sorted_inner(
    node: &TestNode,
    format: WireFormat,
) -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let mut ws = node.send_success_init_request(format, &mut rng).await;
    let challenge = node_setup::random_challenge(&mut rng, vec![3, 1]);

    let should_close_frame = CloseFrame {
        code: oprf_error_codes::UNSORTED_CONTRIBUTING_PARTIES.into(),
        reason: "contributing parties are not sorted".into(),
    };

    node.challenge_expect_error(&mut ws, challenge, format, &should_close_frame)
        .await;
    Ok(())
}

/// Tests that contributing parties with duplicate entries are rejected.
async fn challenge_duplicate_contributions_inner(
    node: &TestNode,
    format: WireFormat,
) -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let mut ws = node.send_success_init_request(format, &mut rng).await;
    let challenge = node_setup::random_challenge(&mut rng, vec![1, 1]);

    let should_close_frame = CloseFrame {
        code: oprf_error_codes::DUPLICATE_COEFFICIENT.into(),
        reason: "contributing parties contains duplicate coefficients".into(),
    };

    node.challenge_expect_error(&mut ws, challenge, format, &should_close_frame)
        .await;
    Ok(())
}

/// Starts one node and runs `$inner` against it once per [`WireFormat`].
macro_rules! both_formats_test {
    ($test_name:ident, $inner:ident) => {
        #[tokio::test]
        async fn $test_name() -> eyre::Result<()> {
            let node = TestNode::start().await?;
            $inner(&node, WireFormat::Json).await?;
            $inner(&node, WireFormat::Cbor).await?;
            Ok(())
        }
    };
}

both_formats_test!(happy_path, happy_path_inner);
both_formats_test!(auth_failed, auth_failed_inner);
both_formats_test!(init_session_reuse, init_session_reuse_inner);
both_formats_test!(init_bad_blinded_query, init_bad_blinded_query_inner);
both_formats_test!(init_bad_request, init_bad_request_inner);
both_formats_test!(challenge_bad_request, challenge_bad_request_inner);
both_formats_test!(
    challenge_bad_contributing_parties,
    challenge_bad_contributing_parties_inner
);
both_formats_test!(
    challenge_challenge_not_contributing_party,
    challenge_challenge_not_contributing_party_inner
);
both_formats_test!(
    challenge_contributing_parties_not_sorted,
    challenge_contributing_parties_not_sorted_inner
);
both_formats_test!(
    challenge_duplicate_contributions,
    challenge_duplicate_contributions_inner
);
both_formats_test!(drop_session_id, drop_session_id_inner);
both_formats_test!(message_too_large, message_too_large_inner);

#[tokio::test]
async fn session_timeout_after_init_json() -> eyre::Result<()> {
    session_timeout_after_init_inner(WireFormat::Json).await
}

/// Tests that a delegate OPRF request against a real 2-of-3 cluster succeeds end to end.
#[tokio::test]
async fn delegate_happy_path() -> eyre::Result<()> {
    let nodes =
        node_setup::start_nodes_for_delegate(DeploySetup::TwoThree, node_setup::OPRF_KEY_ID.into())
            .await?;

    let node_urls = nodes
        .iter()
        .map(|n| n.server.server_address().expect("Server has address"))
        .collect::<Vec<_>>();
    let node_urls = oprf_client::to_oprf_pub_key_url_many(node_urls)?;
    let client = reqwest::Client::new();
    let should_key = oprf_client::fetch_oprf_public_key(
        &node_urls,
        u16::from(DeploySetup::TwoThree.threshold()) as usize,
        node_setup::OPRF_KEY_ID.into(),
        &client,
    )
    .await?
    .expect("setup should have this key");

    let response = nodes[0]
        .server
        .post("/api/test/delegate")
        .add_query_param("version", oprf_client::VERSION)
        .json(&node_setup::request(&mut rand::thread_rng()))
        .await;
    response.assert_status_ok();
    let body: DelegateOprfResponse = response.json();
    assert_eq!(body.oprf_pub_key_with_epoch, should_key);
    Ok(())
}

/// Tests delegate error paths against one 2-of-3 cluster: a wrong OPRF key id auth (aggregated
/// into a `ThresholdServiceError` -> 400), a missing client version, an unsupported client
/// version, and finally -- since it destroys the cluster -- reachable nodes dropping below
/// threshold (-> 503).
#[tokio::test]
async fn delegate_errors() -> eyre::Result<()> {
    let mut nodes =
        node_setup::start_nodes_for_delegate(DeploySetup::TwoThree, node_setup::OPRF_KEY_ID.into())
            .await?;

    let mut request = node_setup::request(&mut rand::thread_rng());
    request.auth = node_setup::ConfigurableTestRequestAuth(OprfKeyId::from(123_usize));
    let response = nodes[0]
        .server
        .post("/api/test/delegate")
        .add_query_param("version", oprf_client::VERSION)
        .json(&request)
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    response.assert_text(INVALID_AUTH_CODE.to_string());

    let response = nodes[0]
        .server
        .post("/api/test/delegate")
        .json(&node_setup::request(&mut rand::thread_rng()))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    response.assert_text("missing client version");

    let response = nodes[0]
        .server
        .post("/api/test/delegate")
        .add_query_param("version", "0.0.0")
        .json(&node_setup::request(&mut rand::thread_rng()))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    response.assert_text(format!(
        "invalid version, expected: ^{} got: 0.0.0",
        oprf_client::VERSION
    ));

    // drop all but one node so the (threshold-2) cluster can no longer reach consensus;
    // this destroys the cluster, so it must run last
    let delegator = nodes.remove(0);
    drop(nodes);

    let response = delegator
        .server
        .post("/api/test/delegate")
        .add_query_param("version", oprf_client::VERSION)
        .json(&node_setup::request(&mut rand::thread_rng()))
        .await;
    response.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}
