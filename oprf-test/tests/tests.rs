use alloy::node_bindings::Anvil;
use alloy::providers::{ProviderBuilder, WsConnect};
use ark_ff::UniformRand as _;
use eyre::Context as _;
use oprf_types::ShareEpoch;
use oprf_types::chain::OprfKeyRegistry;
use oprf_types::crypto::OprfPublicKey;
use std::time::Duration;
use taceo_oprf_test::oprf_key_registry_scripts::{self};
use taceo_oprf_test::{
    OPRF_PEER_ADDRESS_0, OPRF_PEER_ADDRESS_1, OPRF_PEER_ADDRESS_2, OPRF_PEER_ADDRESS_3,
    OPRF_PEER_ADDRESS_4, TACEO_ADMIN_ADDRESS, TACEO_ADMIN_PRIVATE_KEY, health_checks,
};
use tokio_tungstenite::Connector;

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[serial_test::file_serial]
async fn oprf_example_with_reshare_e2e_test_13() -> eyre::Result<()> {
    let anvil = Anvil::new().spawn();
    let mut rng = rand::thread_rng();

    println!("Deploying OprfKeyRegistry contract...");
    let oprf_key_registry_contract = oprf_key_registry_scripts::deploy_test_setup(
        &anvil.endpoint(),
        &TACEO_ADMIN_ADDRESS.to_string(),
        TACEO_ADMIN_PRIVATE_KEY,
        &format!("{OPRF_PEER_ADDRESS_0},{OPRF_PEER_ADDRESS_1},{OPRF_PEER_ADDRESS_2}"),
        2,
        3,
    );

    let secret_managers = taceo_oprf_test::create_3_secret_managers();
    println!("Starting OPRF key-gens...");
    let oprf_key_gens = taceo_oprf_test::start_3_key_gens(
        &anvil.ws_endpoint(),
        secret_managers.clone(),
        oprf_key_registry_contract,
    )
    .await;
    println!("Starting OPRF nodes...");
    let oprf_services = taceo_oprf_test::start_3_nodes(
        &anvil.ws_endpoint(),
        secret_managers,
        oprf_key_registry_contract,
    )
    .await;

    health_checks::services_health_check(&oprf_key_gens, Duration::from_secs(60)).await?;

    let oprf_key_id = oprf_key_registry_scripts::init_key_gen(
        &anvil.endpoint(),
        oprf_key_registry_contract,
        TACEO_ADMIN_PRIVATE_KEY,
    );
    println!("init key-gen with oprf key id: {oprf_key_id}");

    println!("Fetching OPRF public-key...");
    let start_epoch = ShareEpoch::default();
    let oprf_public_key = health_checks::oprf_public_key_from_services(
        oprf_key_id,
        start_epoch,
        &oprf_services,
        Duration::from_secs(120), // graceful timeout for CI
    )
    .await
    .context("while loading OPRF key-material from services")?;

    println!("Running OPRF client flow...");
    let action = ark_babyjubjub::Fq::rand(&mut rng);

    // The client example verifies the DLogEquality
    let _verifiable_oprf_output = oprf_client_example::distributed_oprf(
        oprf_services.as_slice(),
        2,
        oprf_public_key,
        oprf_key_id,
        start_epoch,
        action,
        Connector::Plain,
        &mut rng,
    )
    .await?;

    let next_epoch = start_epoch.next();
    oprf_key_registry_scripts::init_reshare(
        oprf_key_id,
        &anvil.endpoint(),
        oprf_key_registry_contract,
        TACEO_ADMIN_PRIVATE_KEY,
    );
    println!("init reshare with oprf key id: {oprf_key_id}");
    let oprf_public_key_reshare = health_checks::oprf_public_key_from_services(
        oprf_key_id,
        next_epoch,
        &oprf_services,
        Duration::from_secs(120), // graceful timeout for CI
    )
    .await
    .context("while loading OPRF key-material from services")?;
    assert_eq!(oprf_public_key, oprf_public_key_reshare);
    println!("finished reshare - computing one oprf with new and one with old share");
    let mut rng1 = &mut rand::thread_rng();
    let (old_share, new_share) = tokio::join!(
        oprf_client_example::distributed_oprf(
            oprf_services.as_slice(),
            2,
            oprf_public_key,
            oprf_key_id,
            start_epoch,
            action,
            Connector::Plain,
            &mut rng
        ),
        oprf_client_example::distributed_oprf(
            oprf_services.as_slice(),
            2,
            oprf_public_key,
            oprf_key_id,
            next_epoch,
            action,
            Connector::Plain,
            &mut rng1,
        )
    );
    old_share.context("could finish with old share")?;
    new_share.context("could finish with new share")?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[serial_test::file_serial]
async fn oprf_example_e2e_test_25() -> eyre::Result<()> {
    let anvil = Anvil::new().spawn();
    let mut rng = rand::thread_rng();

    println!("Deploying OprfKeyRegistry contract...");
    let oprf_key_registry_contract = oprf_key_registry_scripts::deploy_test_setup(
        &anvil.endpoint(),
        &TACEO_ADMIN_ADDRESS.to_string(),
        TACEO_ADMIN_PRIVATE_KEY,
        &format!(
            "{OPRF_PEER_ADDRESS_0},{OPRF_PEER_ADDRESS_1},{OPRF_PEER_ADDRESS_2},{OPRF_PEER_ADDRESS_3},{OPRF_PEER_ADDRESS_4}"
        ),
        3,
        5,
    );

    let secret_managers = taceo_oprf_test::create_5_secret_managers();
    println!("Starting OPRF key-gens...");
    let oprf_key_gens = taceo_oprf_test::start_5_key_gens(
        &anvil.ws_endpoint(),
        secret_managers.clone(),
        oprf_key_registry_contract,
    )
    .await;
    println!("Starting OPRF nodes...");
    let oprf_services = taceo_oprf_test::start_5_nodes(
        &anvil.ws_endpoint(),
        secret_managers,
        oprf_key_registry_contract,
    )
    .await;

    health_checks::services_health_check(&oprf_key_gens, Duration::from_secs(60)).await?;

    let oprf_key_id = oprf_key_registry_scripts::init_key_gen(
        &anvil.endpoint(),
        oprf_key_registry_contract,
        TACEO_ADMIN_PRIVATE_KEY,
    );
    println!("init key-gen with rp id: {oprf_key_id}");

    println!("Fetching OPRF public-key...");
    let oprf_public_key = health_checks::oprf_public_key_from_services(
        oprf_key_id,
        ShareEpoch::default(),
        &oprf_services,
        Duration::from_secs(120), // graceful timeout for CI
    )
    .await
    .context("while loading OPRF key-material from services")?;

    println!("Running OPRF client flow...");
    let action = ark_babyjubjub::Fq::rand(&mut rng);

    let _verifiable_oprf_output = oprf_client_example::distributed_oprf(
        oprf_services.as_slice(),
        3,
        oprf_public_key,
        oprf_key_id,
        ShareEpoch::default(),
        action,
        Connector::Plain,
        &mut rng,
    )
    .await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[serial_test::file_serial]
async fn test_delete_oprf_key() -> eyre::Result<()> {
    let anvil = Anvil::new().spawn();

    println!("Deploying OprfKeyRegistry contract...");
    let oprf_key_registry_contract = oprf_key_registry_scripts::deploy_test_setup(
        &anvil.endpoint(),
        &TACEO_ADMIN_ADDRESS.to_string(),
        TACEO_ADMIN_PRIVATE_KEY,
        &format!("{OPRF_PEER_ADDRESS_0},{OPRF_PEER_ADDRESS_1},{OPRF_PEER_ADDRESS_2}"),
        2,
        3,
    );

    let secret_managers = taceo_oprf_test::create_3_secret_managers();
    println!("Starting OPRF key-gens...");
    let oprf_key_gens = taceo_oprf_test::start_3_key_gens(
        &anvil.ws_endpoint(),
        secret_managers.clone(),
        oprf_key_registry_contract,
    )
    .await;
    println!("Starting OPRF nodes...");
    let oprf_services = taceo_oprf_test::start_3_nodes(
        &anvil.ws_endpoint(),
        secret_managers.clone(),
        oprf_key_registry_contract,
    )
    .await;

    health_checks::services_health_check(&oprf_key_gens, Duration::from_secs(60)).await?;

    let oprf_key_id = oprf_key_registry_scripts::init_key_gen(
        &anvil.endpoint(),
        oprf_key_registry_contract,
        TACEO_ADMIN_PRIVATE_KEY,
    );
    println!("init key-gen with oprf key id: {oprf_key_id}");

    println!("checking that key-material is registered at services..");
    let is_oprf_public_key = health_checks::oprf_public_key_from_services(
        oprf_key_id,
        ShareEpoch::default(),
        &oprf_services,
        Duration::from_secs(120), // graceful timeout for CI
    )
    .await
    .context("while loading OPRF key-material from services")?;

    let ws = WsConnect::new(anvil.ws_endpoint());
    let provider = ProviderBuilder::new()
        .connect_ws(ws)
        .await
        .context("while connecting to RPC")?;
    let contract = OprfKeyRegistry::new(oprf_key_registry_contract, provider.clone());
    let should_oprf_public_key = contract
        .getOprfPublicKey(oprf_key_id.into_inner())
        .call()
        .await?;
    let should_oprf_public_key = OprfPublicKey::new(should_oprf_public_key.try_into()?);
    assert_eq!(is_oprf_public_key, should_oprf_public_key);

    let secret_before_delete0 = secret_managers[0].load_key_ids();
    let secret_before_delete1 = secret_managers[1].load_key_ids();
    let secret_before_delete2 = secret_managers[2].load_key_ids();
    let should_key_ids = vec![oprf_key_id];
    assert_eq!(secret_before_delete0, should_key_ids);
    assert_eq!(secret_before_delete1, should_key_ids);
    assert_eq!(secret_before_delete2, should_key_ids);

    println!("deletion of OPRF key-material..");
    oprf_key_registry_scripts::delete_oprf_key_material(
        &anvil.endpoint(),
        oprf_key_registry_contract,
        oprf_key_id,
        TACEO_ADMIN_PRIVATE_KEY,
    );

    println!("check that services don't know key anymore...");
    health_checks::assert_key_id_unknown(oprf_key_id, &oprf_services, Duration::from_secs(5))
        .await?;
    println!("check that shares are not in localstack anymore...");

    let secrets_after_delete0 = secret_managers[0].load_key_ids();
    let secrets_after_delete1 = secret_managers[1].load_key_ids();
    let secrets_after_delete2 = secret_managers[2].load_key_ids();

    assert!(secrets_after_delete0.is_empty());
    assert!(secrets_after_delete1.is_empty());
    assert!(secrets_after_delete2.is_empty());

    Ok(())
}
