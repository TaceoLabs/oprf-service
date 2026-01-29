use std::sync::Arc;

use oprf_test_utils::{
    DeploySetup, OPRF_PEER_PRIVATE_KEY_0, TestSetup, test_secret_manager::TestSecretManager,
};
use oprf_types::{ShareEpoch, api::ShareIdentifier};

use crate::setup::TestNode;

mod setup;

#[tokio::test]
async fn test_delete_oprf_key() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    let secret_manager = Arc::new(TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_0));
    let inserted_key = secret_manager.add_random_key_material(&mut rand::thread_rng());
    let node = TestNode::start_with_secret_manager(0, &setup, Arc::clone(&secret_manager)).await?;
    let should_key = node
        .secret_manager
        .get_key_material(inserted_key)
        .expect("Is there")
        .get_oprf_public_key();

    let share_identifier = ShareIdentifier {
        oprf_key_id: inserted_key,
        share_epoch: ShareEpoch::default(),
    };
    node.has_key(share_identifier, should_key).await?;
    // should just work
    let _response = node
        .init_request(share_identifier, &mut rand::thread_rng())
        .await;

    //delete the key
    setup.delete_oprf_key(inserted_key).await?;

    node.doesnt_have_key(inserted_key).await?;
    node.oprf_expect_error(
        share_identifier,
        format!("unknown OPRF key id: {inserted_key}"),
        &mut rand::thread_rng(),
    )
    .await;

    Ok(())
}

#[tokio::test]
async fn test_not_a_participant() -> eyre::Result<()> {
    let setup = TestSetup::new(DeploySetup::TwoThree).await?;
    // for this setup we only have three nodes so party 4 is not registered
    let error = TestNode::start(4, &setup)
        .await
        .expect_err("Should be an error");
    assert_eq!(error.to_string(), "while loading party id");
    Ok(())
}
