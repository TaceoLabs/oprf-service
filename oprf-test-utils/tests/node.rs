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
use taceo_oprf_test_utils::{
    DeploySetup, OPRF_PEER_ADDRESS_0, TestSetup,
    node_setup::{
        self, INVALID_AUTH_CODE, INVALID_AUTH_MSG, TestNode, WireFormat, wait_until_started,
    },
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

#[tokio::test]
async fn test_health_route() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    wait_until_started(&node.started_services).await?;
    let result = node.server.get("/health").expect_success().await;
    result.assert_status_ok();
    result.assert_text("healthy");
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

#[tokio::test]
async fn test_wallet() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    let result = node.server.get("/wallet").await;
    result.assert_status_ok();
    result.assert_text(OPRF_PEER_ADDRESS_0.to_string());
    Ok(())
}

#[tokio::test]
async fn test_version() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    let result = node.server.get("/version").await;
    result.assert_status_ok();
    result.assert_text(nodes_common::version_info!());
    Ok(())
}

#[tokio::test]
async fn test_oprf_pub() -> eyre::Result<()> {
    let node = TestNode::start().await?;
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
    Ok(())
}

#[tokio::test]
async fn test_oprf_pub_not_know() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    let result = node.server.get("/oprf_pub/1234").await;
    result.assert_status_not_found();
    Ok(())
}

#[tokio::test]
async fn wrong_client_version_header() -> eyre::Result<()> {
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
    Ok(())
}

#[tokio::test]
async fn wrong_client_version_query() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    let response = node
        .server
        .get_websocket("/api/test/oprf?version=0.0.0")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    response.assert_text(format!(
        "invalid version, expected: ^{} got: 0.0.0",
        oprf_client::VERSION
    ));
    Ok(())
}

#[tokio::test]
async fn corrupt_client_version_header() -> eyre::Result<()> {
    let node = TestNode::start().await?;
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
    Ok(())
}

#[tokio::test]
async fn corrupt_client_version_query() -> eyre::Result<()> {
    let node = TestNode::start().await?;
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
    Ok(())
}

#[tokio::test]
async fn init_with_version_query_but_header_good() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    let response = node
        .server
        .get_websocket("/api/test/oprf?version=abc")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    response.assert_text("Failed to deserialize query string: version: expected semver version");
    Ok(())
}

#[tokio::test]
async fn init_with_version_query() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    let mut ws = node
        .server
        .get_websocket(&format!("/api/test/oprf?version={}", oprf_client::VERSION))
        .await
        .into_websocket()
        .await;
    // check that the init request works
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
async fn client_version_query_precedence() -> eyre::Result<()> {
    let node = TestNode::start().await?;
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
    // check that the init request works even if HTTP header is wrong
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
async fn no_protocol_version() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    let response = node.server.get_websocket("/api/test/oprf").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    response.assert_text("missing client version");
    Ok(())
}

#[tokio::test]
async fn session_timeout_no_message() -> eyre::Result<()> {
    let node = TestNode::start().await?;
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
    tokio::select! {
        () = tokio::time::sleep(Duration::from_secs(15)) => {
            panic!("should receive close frame within 10 seconds")
        }
        is_message = ws.receive_message() => {
            node_setup::assert_close_frame(is_message, &should_close_frame);
        }
    }
    Ok(())
}

/// Test that sending a message that exceeds the maximum allowed size returns the correct close code.
async fn message_too_large_inner(format: WireFormat) -> eyre::Result<()> {
    let node = TestNode::start().await?;
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
async fn happy_path_inner(format: WireFormat) -> eyre::Result<()> {
    let node = TestNode::start().await?;
    node.happy_path(format).await;
    Ok(())
}

/// Test that the session ID is dropped after successfully finished request
async fn drop_session_id_inner(format: WireFormat) -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let node = TestNode::start().await?;
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
    let node = TestNode::start().await?;
    let mut ws = node
        .send_success_init_request(format, &mut rand::thread_rng())
        .await;
    let should_close_frame = CloseFrame {
        code: oprf_error_codes::TIMEOUT.into(),
        reason: "timeout".into(),
    };
    tokio::select! {
        () = tokio::time::sleep(Duration::from_secs(15)) => {
            panic!("should receive close frame within 10 seconds")
        }
        is_message = ws.receive_message() => {
            node_setup::assert_close_frame(is_message, &should_close_frame);
        }
    }
    Ok(())
}

/// Switch encoding between first and second round
async fn switch_encoding_failed_inner(
    init_format: WireFormat,
    challenge_format: WireFormat,
) -> eyre::Result<()> {
    let node = TestNode::start().await?;
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

/// Test that checks that the happy path works
async fn auth_failed_inner(format: WireFormat) -> eyre::Result<()> {
    let node = TestNode::start().await?;
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

/// Tests that after a key is soft-deleted from the secret manager, the node returns the deleted-key error.
async fn delete_oprf_key_inner(format: WireFormat) -> eyre::Result<()> {
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

    node.init_expect_error(
        node_setup::request(&mut rand::thread_rng()),
        format,
        &should_close_frame,
    )
    .await;

    Ok(())
}

/// Tests that reusing the same session ID for multiple init requests results in an error.
async fn init_session_reuse_inner(format: WireFormat) -> eyre::Result<()> {
    let node = TestNode::start().await?;

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
async fn init_bad_blinded_query_inner(format: WireFormat) -> eyre::Result<()> {
    let node = TestNode::start().await?;

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
async fn init_bad_request_inner(format: WireFormat) -> eyre::Result<()> {
    let node = TestNode::start().await?;

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
async fn challenge_bad_request_inner(format: WireFormat) -> eyre::Result<()> {
    let node = TestNode::start().await?;

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
async fn challenge_bad_contributing_parties_inner(format: WireFormat) -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let node = TestNode::start().await?;
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
async fn challenge_challenge_not_contributing_party_inner(format: WireFormat) -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let node = TestNode::start().await?;
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
async fn challenge_contributing_parties_not_sorted_inner(format: WireFormat) -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let node = TestNode::start().await?;
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
async fn challenge_duplicate_contributions_inner(format: WireFormat) -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let node = TestNode::start().await?;
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

macro_rules! format_test_pair {
    ($json_name:ident, $cbor_name:ident, $inner:ident) => {
        #[tokio::test]
        async fn $json_name() -> eyre::Result<()> {
            $inner(WireFormat::Json).await
        }

        #[tokio::test]
        async fn $cbor_name() -> eyre::Result<()> {
            $inner(WireFormat::Cbor).await
        }
    };
}

format_test_pair!(happy_path_json, happy_path_cbor, happy_path_inner);
format_test_pair!(auth_failed_json, auth_failed_cbor, auth_failed_inner);
format_test_pair!(
    delete_oprf_key_json,
    delete_oprf_key_cbor,
    delete_oprf_key_inner
);
format_test_pair!(
    init_session_reuse_json,
    init_session_reuse_cbor,
    init_session_reuse_inner
);
format_test_pair!(
    init_bad_blinded_query_json,
    init_bad_blinded_query_cbor,
    init_bad_blinded_query_inner
);
format_test_pair!(
    init_bad_request_json,
    init_bad_request_cbor,
    init_bad_request_inner
);
format_test_pair!(
    challenge_bad_request_json,
    challenge_bad_request_cbor,
    challenge_bad_request_inner
);
format_test_pair!(
    challenge_bad_contributing_parties_json,
    challenge_bad_contributing_parties_cbor,
    challenge_bad_contributing_parties_inner
);
format_test_pair!(
    challenge_challenge_not_contributing_party_json,
    challenge_challenge_not_contributing_party_cbor,
    challenge_challenge_not_contributing_party_inner
);
format_test_pair!(
    challenge_contributing_parties_not_sorted_json,
    challenge_contributing_parties_not_sorted_cbor,
    challenge_contributing_parties_not_sorted_inner
);
format_test_pair!(
    challenge_duplicate_contributions_json,
    challenge_duplicate_contributions_cbor,
    challenge_duplicate_contributions_inner
);

#[tokio::test]
async fn session_timeout_after_init_json() -> eyre::Result<()> {
    session_timeout_after_init_inner(WireFormat::Json).await
}

format_test_pair!(
    drop_session_id_json,
    drop_session_id_cbor,
    drop_session_id_inner
);
format_test_pair!(
    message_too_large_json,
    message_too_large_cbor,
    message_too_large_inner
);

#[tokio::test]
async fn switch_encoding_failed_json_cbor() -> eyre::Result<()> {
    switch_encoding_failed_inner(WireFormat::Json, WireFormat::Cbor).await
}

#[tokio::test]
async fn switch_encoding_failed_cbor_json() -> eyre::Result<()> {
    switch_encoding_failed_inner(WireFormat::Cbor, WireFormat::Json).await
}

/// Tests that a delegate OPRF request against a real 2-of-3 cluster succeeds end to end.
#[tokio::test]
async fn delegate_happy_path() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let connection_string = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let nodes = node_setup::start_nodes_for_delegate(
        connection_string,
        &setup,
        node_setup::OPRF_KEY_ID.into(),
    )
    .await?;

    let node_urls = nodes
        .iter()
        .map(|n| n.server.server_address().expect("Server has address"))
        .collect::<Vec<_>>();
    let node_urls = oprf_client::to_oprf_pub_key_url_many(node_urls)?;
    let client = reqwest::Client::new();
    let should_key = oprf_client::fetch_oprf_public_key(
        &node_urls,
        u16::from(setup.setup.threshold()) as usize,
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

/// Tests that a delegate request with a wrong OPRF key id is rejected by every node in the
/// cluster, which the delegator aggregates into a `ThresholdServiceError` -> 400.
#[tokio::test]
async fn delegate_auth_failed() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let connection_string = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let nodes = node_setup::start_nodes_for_delegate(
        connection_string,
        &setup,
        node_setup::OPRF_KEY_ID.into(),
    )
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
    Ok(())
}

/// Tests that a delegate request where the number of reachable nodes drops below the
/// threshold surfaces as a `Networking` error -> 503.
#[tokio::test]
async fn delegate_not_enough_nodes() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let connection_string = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let mut nodes = node_setup::start_nodes_for_delegate(
        connection_string,
        &setup,
        node_setup::OPRF_KEY_ID.into(),
    )
    .await?;

    // drop all but one node so the (threshold-2) cluster can no longer reach consensus
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

/// Tests that a delegate request without a client version query param is rejected before any
/// node in the cluster is contacted.
#[tokio::test]
async fn delegate_missing_version() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let connection_string = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let nodes = node_setup::start_nodes_for_delegate(
        connection_string,
        &setup,
        node_setup::OPRF_KEY_ID.into(),
    )
    .await?;

    let response = nodes[0]
        .server
        .post("/api/test/delegate")
        .json(&node_setup::request(&mut rand::thread_rng()))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    response.assert_text("missing client version");
    Ok(())
}

/// Tests that a delegate request with a client version the node's `version_req` rejects gets a
/// 400 before any node in the cluster is contacted.
#[tokio::test]
async fn delegate_unsupported_version() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let connection_string = nodes_common::test_utils::shared_postgres_testcontainer().await?;
    let nodes = node_setup::start_nodes_for_delegate(
        connection_string,
        &setup,
        node_setup::OPRF_KEY_ID.into(),
    )
    .await?;

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
    Ok(())
}
