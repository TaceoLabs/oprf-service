#![allow(clippy::large_futures, reason = "doesnt matter for tests")]

use std::time::Duration;

use axum::extract::ws::close_code;
use http::StatusCode;
use oprf_core::ddlog_equality::shamir::DLogProofShareShamir;
use oprf_test_utils::{
    DeploySetup, OPRF_PEER_ADDRESS_0, OPRF_PEER_PRIVATE_KEY_0, TEST_TIMEOUT, TestSetup,
};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    api::{OprfResponse, oprf_error_codes},
};
use serde::{Deserialize, Serialize};
use tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
use uuid::Uuid;

use self::setup::{
    INVALID_AUTH_CODE, INVALID_AUTH_MSG, NodeTestSecretManager, TEST_PROTOCOL_VERSION, TestNode,
    WireFormat, wait_until_started,
};

mod setup;

#[derive(Default, Serialize, Deserialize)]
struct BadRequest {
    uuid: Uuid,
}

#[tokio::test]
async fn test_can_fetch_new_key() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start_with_secret_manager(
        0,
        &setup,
        NodeTestSecretManager::new(OPRF_PEER_PRIVATE_KEY_0),
    )
    .await?;
    let new_oprf_key_id = OprfKeyId::from(setup::OPRF_KEY_ID);
    node.doesnt_have_key(new_oprf_key_id).await?;
    let epoch = ShareEpoch::new(42);
    node.secret_manager.add_random_key_material_with_id_epoch(
        new_oprf_key_id,
        epoch,
        &mut rand::thread_rng(),
    );
    let should_key = node
        .secret_manager
        .get_key_material(new_oprf_key_id)
        .expect("Just inserted")
        .public_key();
    setup.finalize_keygen(new_oprf_key_id, epoch).await?;
    node.has_key(new_oprf_key_id, epoch, should_key).await?;
    node.happy_path(WireFormat::Json).await;
    node.happy_path(WireFormat::Cbor).await;
    Ok(())
}

#[tokio::test]
async fn shutdown_if_cancellation_token_cancelled() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    node.cancellation_token.cancel();
    tokio::time::timeout(TEST_TIMEOUT, node.key_event_watcher_task).await???;
    Ok(())
}

#[tokio::test]
async fn test_health_route() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    wait_until_started(&node.started_services).await?;
    let result = node.server.get("/health").expect_success().await;
    result.assert_status_ok();
    result.assert_text("healthy");
    Ok(())
}

#[tokio::test]
async fn test_health_route_not_ready() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let _not_started_service = node.started_services.new_service();
    let result = node.server.get("/health").expect_failure().await;
    result.assert_status_service_unavailable();
    result.assert_text("starting");
    Ok(())
}

#[tokio::test]
async fn test_wallet() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let result = node.server.get("/wallet").await;
    result.assert_status_ok();
    result.assert_text(OPRF_PEER_ADDRESS_0.to_string());
    Ok(())
}

#[tokio::test]
async fn test_version() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let result = node.server.get("/version").await;
    result.assert_status_ok();
    result.assert_text(nodes_common::version_info!());
    Ok(())
}

#[tokio::test]
async fn test_oprf_pub() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let should_public_key_with_epoch = node
        .secret_manager
        .get_key_material(OprfKeyId::from(setup::OPRF_KEY_ID))
        .expect("Is there")
        .public_key_with_epoch();
    let result = node
        .server
        .get(&format!("/oprf_pub/{}", setup::OPRF_KEY_ID))
        .await;
    result.assert_status_ok();
    result.assert_json(&should_public_key_with_epoch);
    Ok(())
}

#[tokio::test]
async fn test_oprf_pub_not_know() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let result = node.server.get("/oprf_pub/1234").await;
    result.assert_status_not_found();
    Ok(())
}

#[tokio::test]
async fn not_a_participant() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    // for this setup we only have three nodes so party 4 is not registered
    let error = TestNode::start(4, &setup)
        .await
        .expect_err("Should be an error");
    assert_eq!(error.to_string(), "while loading party id");
    Ok(())
}

#[tokio::test]
async fn wrong_client_version_header() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let response = node
        .server
        .get_websocket("/api/test/oprf")
        .add_header(
            oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
            "2.0.0",
        )
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    response.assert_text("invalid version, expected: ^1.0.0 got: 2.0.0");
    Ok(())
}

#[tokio::test]
async fn wrong_client_version_query() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let response = node
        .server
        .get_websocket("/api/test/oprf?version=2.0.0")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    response.assert_text("invalid version, expected: ^1.0.0 got: 2.0.0");
    Ok(())
}

#[tokio::test]
async fn corrupt_client_version_header() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
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
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let response = node
        .server
        .get_websocket("/api/test/oprf?version=abc")
        .add_header(
            oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
            TEST_PROTOCOL_VERSION,
        )
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    response.assert_text("Failed to deserialize query string: version: expected semver version");
    Ok(())
}

#[tokio::test]
async fn init_with_version_query_but_header_good() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
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
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let mut ws = node
        .server
        .get_websocket(&format!("/api/test/oprf?version={TEST_PROTOCOL_VERSION}"))
        .await
        .into_websocket()
        .await;
    // check that the init request works
    setup::ws_send(
        &mut ws,
        &setup::request(&mut rand::thread_rng()),
        WireFormat::Json,
    )
    .await;

    let _response = setup::ws_recv::<OprfResponse>(&mut ws, WireFormat::Json).await;
    Ok(())
}

#[tokio::test]
async fn client_version_query_precedence() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let mut ws = node
        .server
        .get_websocket(&format!("/api/test/oprf?version={TEST_PROTOCOL_VERSION}"))
        .add_header(
            oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
            "2.0.0",
        )
        .await
        .into_websocket()
        .await;
    // check that the init request works even if HTTP header is wrong
    setup::ws_send(
        &mut ws,
        &setup::request(&mut rand::thread_rng()),
        WireFormat::Json,
    )
    .await;

    let _response = setup::ws_recv::<OprfResponse>(&mut ws, WireFormat::Json).await;
    Ok(())
}

#[tokio::test]
async fn no_protocol_version() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let response = node.server.get_websocket("/api/test/oprf").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    response.assert_text("missing client version");
    Ok(())
}

#[tokio::test]
async fn session_timeout_no_message() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let mut ws = node
        .server
        .get_websocket("/api/test/oprf")
        .add_header(
            oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
            "1.0.0",
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
            setup::assert_close_frame(is_message, &should_close_frame);
        }
    }
    Ok(())
}

/// Test that sending a message that exceeds the maximum allowed size returns the correct close code.
async fn message_too_large_inner(format: WireFormat) -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let mut ws = node
        .server
        .get_websocket("/api/test/oprf")
        .add_header(
            oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
            setup::TEST_PROTOCOL_VERSION,
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
    setup::assert_close_frame(is_message, &should_close_frame);

    Ok(())
}

/// Test that checks that the happy path works
async fn happy_path_inner(format: WireFormat) -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    node.happy_path(format).await;
    Ok(())
}

/// Test that the session ID is dropped after successfully finished request
async fn drop_session_id_inner(format: WireFormat) -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let request0 = setup::request(&mut rng);
    let mut request1 = setup::request(&mut rng);
    request1.request_id = request0.request_id;

    let mut ws = node.send_request(request0, format).await;

    let _response = setup::ws_recv::<OprfResponse>(&mut ws, format).await;
    setup::ws_send(
        &mut ws,
        &setup::random_challenge(&mut rng, vec![1, 2]),
        format,
    )
    .await;

    // Can deserialize
    let _response = setup::ws_recv::<DLogProofShareShamir>(&mut ws, format).await;

    // can finish the second request now
    let mut ws = node.send_request(request1, format).await;

    let _response = setup::ws_recv::<OprfResponse>(&mut ws, format).await;
    setup::ws_send(
        &mut ws,
        &setup::random_challenge(&mut rng, vec![1, 2]),
        format,
    )
    .await;

    // Can deserialize
    let _response = setup::ws_recv::<DLogProofShareShamir>(&mut ws, format).await;

    Ok(())
}

/// Checks that successfully closes connection after first message is send if runs into timeout
async fn session_timeout_after_init_inner(format: WireFormat) -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
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
            setup::assert_close_frame(is_message, &should_close_frame);
        }
    }
    Ok(())
}

/// Switch encoding between first and second round
async fn switch_encoding_failed_inner(
    init_format: WireFormat,
    challenge_format: WireFormat,
) -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let mut ws = node
        .send_success_init_request(init_format, &mut rand::thread_rng())
        .await;

    let challenge = setup::random_challenge(&mut rand::thread_rng(), vec![42]);
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
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let mut request = setup::request(&mut rand::thread_rng());
    request.auth = setup::ConfigurableTestRequestAuth(OprfKeyId::from(123_usize));

    let should_close_frame = CloseFrame {
        code: CloseCode::from(INVALID_AUTH_CODE),
        reason: INVALID_AUTH_MSG.into(),
    };
    node.init_expect_error(&request, format, &should_close_frame)
        .await;
    Ok(())
}

/// Tests that after we observe an delete event by the key-event-watcher, we remove the share and can't serve it any longer
async fn delete_oprf_key_inner(format: WireFormat) -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;

    let key_id = OprfKeyId::from(setup::OPRF_KEY_ID);
    //delete the key
    setup.delete_oprf_key(key_id).await?;

    // check that we can't query the key any longer
    node.doesnt_have_key(key_id).await?;
    let should_close_frame = CloseFrame {
        code: oprf_error_codes::UNKNOWN_OPRF_KEY_ID.into(),
        reason: "unknown OPRF key id".into(),
    };

    node.init_expect_error(
        setup::request(&mut rand::thread_rng()),
        format,
        &should_close_frame,
    )
    .await;

    Ok(())
}

/// Tests that reusing the same session ID for multiple init requests results in an error.
async fn init_session_reuse_inner(format: WireFormat) -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;

    let request0 = setup::request(&mut rand::thread_rng());
    let mut request1 = setup::request(&mut rand::thread_rng());
    request1.request_id = request0.request_id;

    let mut ws0 = node.send_request(request0, format).await;
    // can deserialize success message
    let _ = setup::ws_recv::<OprfResponse>(&mut ws0, format).await;

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
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;

    let mut request = setup::request(&mut rand::thread_rng());
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
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;

    let mut ws = node
        .server
        .get_websocket("/api/test/oprf")
        .add_header(
            oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER.as_str(),
            "1.3.101",
        )
        .await
        .into_websocket()
        .await;
    setup::ws_send(&mut ws, &BadRequest::default(), format).await;
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
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;

    let mut ws = node
        .send_success_init_request(format, &mut rand::thread_rng())
        .await;

    setup::ws_send(&mut ws, &BadRequest::default(), format).await;
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
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let mut ws = node.send_success_init_request(format, &mut rng).await;

    let challenge = setup::random_challenge(&mut rng, vec![42]);

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
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let mut ws = node.send_success_init_request(format, &mut rng).await;

    let challenge = setup::random_challenge(&mut rng, vec![2, 3]);

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
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let mut ws = node.send_success_init_request(format, &mut rng).await;
    let challenge = setup::random_challenge(&mut rng, vec![3, 1]);

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
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let mut ws = node.send_success_init_request(format, &mut rng).await;
    let challenge = setup::random_challenge(&mut rng, vec![1, 1]);

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
