use std::{sync::Arc, time::Duration};

use axum::extract::ws::close_code;
use http::StatusCode;
use oprf_core::ddlog_equality::shamir::DLogProofShareShamir;
use oprf_test_utils::{
    DeploySetup, OPRF_PEER_ADDRESS_0, OPRF_PEER_PRIVATE_KEY_0, TEST_TIMEOUT, TestSetup,
    test_secret_manager::TestSecretManager,
};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    api::{OprfResponse, oprf_error_codes},
};
use serde::{Deserialize, Serialize};
use tungstenite::protocol::CloseFrame;
use uuid::Uuid;

use crate::setup::{TestNode, WireFormat};

mod setup;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_can_fetch_new_key() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start_with_secret_manager(
        0,
        &setup,
        Arc::new(TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_0)),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn shutdown_if_cancellation_token_cancelled() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    node.cancellation_token.cancel();
    tokio::time::timeout(TEST_TIMEOUT, node.key_event_watcher_task).await???;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_health_route() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let started_services = node.started_services.clone();
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if started_services.all_started() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    let result = node.server.get("/health").expect_success().await;
    result.assert_status_ok();
    result.assert_text("healthy");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
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
async fn wrong_client_version() -> eyre::Result<()> {
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
    response.assert_text("invalid version, expected: ^1.0.0");
    Ok(())
}

#[tokio::test]
async fn no_protocol_version() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let response = node.server.get_websocket("/api/test/oprf").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    response.assert_text(format!(
        "Header of type `{}` was missing",
        oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER
    ));
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
        _ = tokio::time::sleep(Duration::from_secs(15)) => {
            panic!("should receive close frame within 10 seconds")
        }
        is_message = ws.receive_message() => {
            setup::assert_close_frame(is_message, should_close_frame);
        }
    }
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
        _ = tokio::time::sleep(Duration::from_secs(15)) => {
            panic!("should receive close frame within 10 seconds")
        }
        is_message = ws.receive_message() => {
            setup::assert_close_frame(is_message, should_close_frame);
        }
    }
    Ok(())
}

/// Test that checks that the happy path works
async fn auth_failed_inner(format: WireFormat) -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;
    let mut request = setup::request(&mut rand::thread_rng());
    request.auth = setup::ConfigurableTestRequestAuth(OprfKeyId::from(123_usize));

    let should_close_frame = CloseFrame {
        code: close_code::POLICY.into(),
        reason: "invalid".into(),
    };
    node.init_expect_error(&request, format, should_close_frame)
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
        code: oprf_error_codes::BAD_REQUEST.into(),
        reason: "unknown OPRF key id: 42".into(),
    };

    node.init_expect_error(
        setup::request(&mut rand::thread_rng()),
        format,
        should_close_frame,
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
    let session = request0.request_id;

    let mut ws0 = node.send_request(request0, format).await;
    // can deserialize success message
    let _ = setup::ws_recv::<OprfResponse>(&mut ws0, format).await;

    let should_close_frame = CloseFrame {
        code: close_code::POLICY.into(),
        reason: format!("session {session} already exists").into(),
    };
    node.init_expect_error(request1, format, should_close_frame)
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
        code: oprf_error_codes::BAD_REQUEST.into(),
        reason: "blinded query must not be identity".into(),
    };

    node.init_expect_error(request, format, should_close_frame)
        .await;
    Ok(())
}

/// Tests that malformed init requests with missing required fields are rejected.
async fn init_bad_request_inner(format: WireFormat) -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;

    #[derive(Default, Serialize, Deserialize)]
    struct BadRequest {
        uuid: Uuid,
    }

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
    // slightly different error messages for json/cbor there we can't use oprf_expect_error
    match is_message {
        tungstenite::Message::Close(Some(is_close_frame)) => {
            assert_eq!(is_close_frame.code, oprf_error_codes::BAD_REQUEST.into());
            assert!(
                is_close_frame
                    .reason
                    .to_string()
                    .contains("missing field `request_id`")
            );
        }
        _ => panic!("unexpected message - expected CloseFrame"),
    }
    Ok(())
}

/// Tests that malformed challenge requests with missing required fields are rejected.
async fn challenge_bad_request_inner(format: WireFormat) -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let node = TestNode::start(0, &setup).await?;

    #[derive(Default, Serialize, Deserialize)]
    struct BadRequest {
        uuid: Uuid,
    }

    let mut ws = node
        .send_success_init_request(format, &mut rand::thread_rng())
        .await;

    setup::ws_send(&mut ws, &BadRequest::default(), format).await;
    let is_message = ws.receive_message().await;
    // slightly different error messages for json/cbor there we can't use oprf_expect_error
    match is_message {
        tungstenite::Message::Close(Some(is_close_frame)) => {
            assert_eq!(is_close_frame.code, oprf_error_codes::BAD_REQUEST.into());
            assert!(
                is_close_frame
                    .reason
                    .to_string()
                    .contains("missing field `c`")
            );
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
        code: oprf_error_codes::BAD_REQUEST.into(),
        reason: "expected 2 contributing parties but got 1".into(),
    };

    node.challenge_expect_error(&mut ws, challenge, format, should_close_frame)
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
        code: oprf_error_codes::BAD_REQUEST.into(),
        reason: "contributing parties does not contain my coefficient (1)".into(),
    };

    node.challenge_expect_error(&mut ws, challenge, format, should_close_frame)
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
        code: oprf_error_codes::BAD_REQUEST.into(),
        reason: "contributing parties are not sorted".into(),
    };

    node.challenge_expect_error(&mut ws, challenge, format, should_close_frame)
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
        code: oprf_error_codes::BAD_REQUEST.into(),
        reason: "contributing parties contains duplicate coefficients".into(),
    };

    node.challenge_expect_error(&mut ws, challenge, format, should_close_frame)
        .await;
    Ok(())
}

#[tokio::test]
async fn happy_path_json() -> eyre::Result<()> {
    happy_path_inner(WireFormat::Json).await
}

#[tokio::test]
async fn happy_path_cbor() -> eyre::Result<()> {
    happy_path_inner(WireFormat::Cbor).await
}

#[tokio::test]
async fn auth_failed_json() -> eyre::Result<()> {
    auth_failed_inner(WireFormat::Json).await
}

#[tokio::test]
async fn auth_failed_cbor() -> eyre::Result<()> {
    auth_failed_inner(WireFormat::Cbor).await
}

#[tokio::test]
async fn delete_oprf_key_json() -> eyre::Result<()> {
    delete_oprf_key_inner(WireFormat::Json).await
}

#[tokio::test]
async fn delete_oprf_key_cbor() -> eyre::Result<()> {
    delete_oprf_key_inner(WireFormat::Cbor).await
}

#[tokio::test]
async fn init_session_reuse_json() -> eyre::Result<()> {
    init_session_reuse_inner(WireFormat::Json).await
}

#[tokio::test]
async fn init_session_reuse_cbor() -> eyre::Result<()> {
    init_session_reuse_inner(WireFormat::Cbor).await
}

#[tokio::test]
async fn init_bad_blinded_query_json() -> eyre::Result<()> {
    init_bad_blinded_query_inner(WireFormat::Json).await
}

#[tokio::test]
async fn init_bad_blinded_query_cbor() -> eyre::Result<()> {
    init_bad_blinded_query_inner(WireFormat::Cbor).await
}

#[tokio::test]
async fn init_bad_request_json() -> eyre::Result<()> {
    init_bad_request_inner(WireFormat::Json).await
}

#[tokio::test]
async fn init_bad_request_cbor() -> eyre::Result<()> {
    init_bad_request_inner(WireFormat::Cbor).await
}

#[tokio::test]
async fn challenge_bad_request_json() -> eyre::Result<()> {
    challenge_bad_request_inner(WireFormat::Json).await
}

#[tokio::test]
async fn challenge_bad_request_cbor() -> eyre::Result<()> {
    challenge_bad_request_inner(WireFormat::Cbor).await
}

#[tokio::test]
async fn challenge_bad_contributing_parties_json() -> eyre::Result<()> {
    challenge_bad_contributing_parties_inner(WireFormat::Json).await
}

#[tokio::test]
async fn challenge_bad_contributing_parties_cbor() -> eyre::Result<()> {
    challenge_bad_contributing_parties_inner(WireFormat::Cbor).await
}

#[tokio::test]
async fn challenge_challenge_not_contributing_party_json() -> eyre::Result<()> {
    challenge_challenge_not_contributing_party_inner(WireFormat::Json).await
}

#[tokio::test]
async fn challenge_challenge_not_contributing_party_cbor() -> eyre::Result<()> {
    challenge_challenge_not_contributing_party_inner(WireFormat::Cbor).await
}

#[tokio::test]
async fn challenge_contributing_parties_not_sorted_json() -> eyre::Result<()> {
    challenge_contributing_parties_not_sorted_inner(WireFormat::Json).await
}

#[tokio::test]
async fn challenge_contributing_parties_not_sorted_cbor() -> eyre::Result<()> {
    challenge_contributing_parties_not_sorted_inner(WireFormat::Cbor).await
}

#[tokio::test]
async fn challenge_duplicate_contributions_json() -> eyre::Result<()> {
    challenge_duplicate_contributions_inner(WireFormat::Json).await
}

#[tokio::test]
async fn challenge_duplicate_contributions_cbor() -> eyre::Result<()> {
    challenge_duplicate_contributions_inner(WireFormat::Cbor).await
}

#[tokio::test]
async fn session_timeout_after_init_json() -> eyre::Result<()> {
    session_timeout_after_init_inner(WireFormat::Json).await
}

#[tokio::test]
async fn drop_session_id_cbor() -> eyre::Result<()> {
    drop_session_id_inner(WireFormat::Cbor).await
}

#[tokio::test]
async fn drop_session_id_json() -> eyre::Result<()> {
    drop_session_id_inner(WireFormat::Json).await
}
