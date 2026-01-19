use ark_ff::UniformRand as _;
use eyre::Context as _;
use oprf_test_utils::test_secret_manager::TestSecretManager;
use oprf_test_utils::{health_checks, oprf_key_registry};
use oprf_types::chain::OprfKeyRegistry;
use oprf_types::crypto::OprfPublicKey;
use oprf_types::{OprfKeyId, ShareEpoch};
use rand::Rng;
use std::path::PathBuf;
use std::time::Duration;
use taceo_oprf_test::{
    OPRF_PEER_ADDRESS_0, OPRF_PEER_ADDRESS_1, OPRF_PEER_ADDRESS_2, OPRF_PEER_ADDRESS_3,
    OPRF_PEER_PRIVATE_KEY_3, TestSetup13, TestSetup25,
};
use tokio_tungstenite::Connector;

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[serial_test::file_serial]
async fn oprf_example_with_reshare_e2e_test_13() -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let setup = TestSetup13::new().await?;

    let oprf_key_id = OprfKeyId::new(rng.r#gen());
    println!("init key-gen with oprf key id: {oprf_key_id}");
    oprf_key_registry::init_key_gen(setup.provider.clone(), setup.oprf_key_registry, oprf_key_id)
        .await?;

    println!("Fetching OPRF public-key...");
    let start_epoch = ShareEpoch::default();
    let oprf_public_key = health_checks::oprf_public_key_from_services(
        oprf_key_id,
        start_epoch,
        &setup.nodes,
        Duration::from_secs(120), // graceful timeout for CI
    )
    .await
    .context("while loading OPRF key-material from services")?;

    println!("Running OPRF client flow...");
    let action = ark_babyjubjub::Fq::rand(&mut rng);

    // The client example verifies the DLogEquality
    let _verifiable_oprf_output = oprf_client_example::distributed_oprf(
        setup.nodes.as_slice(),
        2,
        oprf_key_id,
        start_epoch,
        action,
        Connector::Plain,
        &mut rng,
    )
    .await?;

    let next_epoch = start_epoch.next();
    println!("init reshare with oprf key id: {oprf_key_id}");
    oprf_key_registry::init_reshare(setup.provider, setup.oprf_key_registry, oprf_key_id).await?;
    let oprf_public_key_reshare = health_checks::oprf_public_key_from_services(
        oprf_key_id,
        next_epoch,
        &setup.nodes,
        Duration::from_secs(120), // graceful timeout for CI
    )
    .await
    .context("while loading OPRF key-material from services")?;
    assert_eq!(oprf_public_key, oprf_public_key_reshare);
    println!("finished reshare - computing one oprf with new and one with old share");

    let mut rng1 = &mut rand::thread_rng();
    let (old_share, new_share) = tokio::join!(
        oprf_client_example::distributed_oprf(
            setup.nodes.as_slice(),
            2,
            oprf_key_id,
            start_epoch,
            action,
            Connector::Plain,
            &mut rng
        ),
        oprf_client_example::distributed_oprf(
            setup.nodes.as_slice(),
            2,
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
    let mut rng = rand::thread_rng();
    let setup = TestSetup25::new().await?;

    let oprf_key_id = OprfKeyId::new(rng.r#gen());
    println!("init key-gen with oprf key id: {oprf_key_id}");
    oprf_key_registry::init_key_gen(setup.provider.clone(), setup.oprf_key_registry, oprf_key_id)
        .await?;

    println!("Fetching OPRF public-key...");
    let _oprf_public_key = health_checks::oprf_public_key_from_services(
        oprf_key_id,
        ShareEpoch::default(),
        &setup.nodes,
        Duration::from_secs(120), // graceful timeout for CI
    )
    .await
    .context("while loading OPRF key-material from services")?;

    println!("Running OPRF client flow...");
    let action = ark_babyjubjub::Fq::rand(&mut rng);

    let _verifiable_oprf_output = oprf_client_example::distributed_oprf(
        setup.nodes.as_slice(),
        3,
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
    let mut rng = rand::thread_rng();
    let setup = TestSetup13::new().await?;

    let oprf_key_id = OprfKeyId::new(rng.r#gen());
    println!("init key-gen with oprf key id: {oprf_key_id}");
    oprf_key_registry::init_key_gen(setup.provider.clone(), setup.oprf_key_registry, oprf_key_id)
        .await?;

    println!("Fetching OPRF public-key...");
    let start_epoch = ShareEpoch::default();
    let is_oprf_public_key = health_checks::oprf_public_key_from_services(
        oprf_key_id,
        start_epoch,
        &setup.nodes,
        Duration::from_secs(120), // graceful timeout for CI
    )
    .await
    .context("while loading OPRF key-material from services")?;

    let contract = OprfKeyRegistry::new(setup.oprf_key_registry, setup.provider.clone());
    let should_oprf_public_key = contract
        .getOprfPublicKey(oprf_key_id.into_inner())
        .call()
        .await?;
    let should_oprf_public_key = OprfPublicKey::new(should_oprf_public_key.try_into()?);
    assert_eq!(is_oprf_public_key, should_oprf_public_key);

    let secret_before_delete0 = setup.secret_managers[0].load_key_ids();
    let secret_before_delete1 = setup.secret_managers[1].load_key_ids();
    let secret_before_delete2 = setup.secret_managers[2].load_key_ids();
    let should_key_ids = vec![oprf_key_id];
    assert_eq!(secret_before_delete0, should_key_ids);
    assert_eq!(secret_before_delete1, should_key_ids);
    assert_eq!(secret_before_delete2, should_key_ids);

    println!("deletion of OPRF key-material..");
    oprf_key_registry::delete_oprf_key_material(
        setup.provider.clone(),
        setup.oprf_key_registry,
        oprf_key_id,
    )
    .await?;

    println!("check that services don't know key anymore...");
    health_checks::assert_key_id_unknown(oprf_key_id, &setup.nodes, Duration::from_secs(5)).await?;
    println!("check that shares are not in localstack anymore...");

    let secrets_after_delete0 = setup.secret_managers[0].load_key_ids();
    let secrets_after_delete1 = setup.secret_managers[1].load_key_ids();
    let secrets_after_delete2 = setup.secret_managers[2].load_key_ids();

    assert!(secrets_after_delete0.is_empty());
    assert!(secrets_after_delete1.is_empty());
    assert!(secrets_after_delete2.is_empty());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[serial_test::file_serial]
async fn oprf_example_reshare_with_consumer() -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let mut setup = TestSetup13::new().await?;

    let oprf_key_id = OprfKeyId::new(rng.r#gen());
    println!("init key-gen with oprf key id: {oprf_key_id}");
    oprf_key_registry::init_key_gen(setup.provider.clone(), setup.oprf_key_registry, oprf_key_id)
        .await?;

    println!("Fetching OPRF public-key...");
    let start_epoch = ShareEpoch::default();
    let oprf_public_key = health_checks::oprf_public_key_from_services(
        oprf_key_id,
        start_epoch,
        &setup.nodes,
        Duration::from_secs(120), // graceful timeout for CI
    )
    .await
    .context("while loading OPRF key-material from services")?;

    println!("Running OPRF client flow...");
    let action = ark_babyjubjub::Fq::rand(&mut rng);

    // The client example verifies the DLogEquality
    let _verifiable_oprf_output = oprf_client_example::distributed_oprf(
        setup.nodes.as_slice(),
        2,
        oprf_key_id,
        start_epoch,
        action,
        Connector::Plain,
        &mut rng,
    )
    .await?;

    // kill a random party
    let killed_party = rand::thread_rng().gen_range(0..3);
    println!("shutdown party {killed_party}");
    setup.key_gen_cancellation_tokens[killed_party].cancel();
    setup.node_cancellation_tokens[killed_party].cancel();
    let mut addresses = [
        OPRF_PEER_ADDRESS_0,
        OPRF_PEER_ADDRESS_1,
        OPRF_PEER_ADDRESS_2,
    ];
    addresses[killed_party] = OPRF_PEER_ADDRESS_3;

    println!("wait until party is down..");
    health_checks::service_down(&setup.nodes[killed_party], Duration::from_secs(60)).await?;

    println!("register new participants");
    oprf_key_registry::register_oprf_nodes(
        setup.provider.clone(),
        setup.oprf_key_registry,
        addresses.to_vec(),
    )
    .await?;

    let new_secret_manager = TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_3);

    println!("starting new node");
    // start a new party
    let (new_service, _) = taceo_oprf_test::start_node(
        killed_party,
        &setup.anvil.ws_endpoint(),
        new_secret_manager.clone(),
        setup.oprf_key_registry,
        OPRF_PEER_ADDRESS_3,
    )
    .await;

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let key_get_zkey_path = dir.join("../circom/main/key-gen/OPRFKeyGen.13.arks.zkey");
    let key_gen_witness_graph_path = dir.join("../circom/main/key-gen/OPRFKeyGenGraph.13.bin");
    let (new_key_gen, _) = taceo_oprf_test::start_key_gen(
        killed_party,
        &setup.anvil.ws_endpoint(),
        new_secret_manager.clone(),
        setup.oprf_key_registry,
        key_get_zkey_path,
        key_gen_witness_graph_path,
    )
    .await;
    setup.nodes[killed_party] = new_service;
    setup.key_gens[killed_party] = new_key_gen;

    println!("doing health check");
    health_checks::services_health_check(&setup.key_gens, Duration::from_secs(60)).await?;

    // do a reshare
    let next_epoch = start_epoch.next();
    println!("init reshare");
    oprf_key_registry::init_reshare(setup.provider.clone(), setup.oprf_key_registry, oprf_key_id)
        .await?;
    let oprf_public_key_reshare = health_checks::oprf_public_key_from_services(
        oprf_key_id,
        next_epoch,
        &setup.nodes,
        Duration::from_secs(120), // graceful timeout for CI
    )
    .await
    .context("while loading OPRF key-material from services")?;
    assert_eq!(oprf_public_key, oprf_public_key_reshare);
    println!("finished reshare - computing one oprf with new and one with old share");
    let mut rng1 = &mut rand::thread_rng();
    let mut services_with_new_one = setup.nodes.to_vec();
    // we remove one of the old parties to force the new party to produce am OPRF
    services_with_new_one.remove((killed_party + 1) % 3);
    let (old_share, new_share) = tokio::join!(
        oprf_client_example::distributed_oprf(
            setup.nodes.as_slice(),
            2,
            oprf_key_id,
            start_epoch,
            action,
            Connector::Plain,
            &mut rng
        ),
        oprf_client_example::distributed_oprf(
            services_with_new_one.as_slice(),
            2,
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
async fn oprf_example_abort_keygen() -> eyre::Result<()> {
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
    let (oprf_key_gens, _) = taceo_oprf_test::start_2_key_gens(
        &anvil.ws_endpoint(),
        [secret_managers[0].clone(), secret_managers[1].clone()],
        oprf_key_registry_contract,
    )
    .await;
    let last_secret_manager = secret_managers[2].clone();
    println!("Starting OPRF nodes...");
    let (oprf_services, _) = taceo_oprf_test::start_3_nodes(
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
    println!("now abort key-gen");

    oprf_key_registry_scripts::key_gen_abort(
        &anvil.endpoint(),
        oprf_key_registry_contract,
        TACEO_ADMIN_PRIVATE_KEY,
    );

    // start the third key-gen
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let key_get_zkey_path = dir.join("../circom/main/key-gen/OPRFKeyGen.13.arks.zkey");
    let key_gen_witness_graph_path = dir.join("../circom/main/key-gen/OPRFKeyGenGraph.13.bin");
    let (new_key_gen, _) = taceo_oprf_test::start_key_gen(
        2,
        &anvil.ws_endpoint(),
        last_secret_manager,
        oprf_key_registry_contract,
        key_get_zkey_path,
        key_gen_witness_graph_path,
    )
    .await;

    let [oprf_key_gen0, oprf_key_gen1] = oprf_key_gens;
    let oprf_key_gens = [oprf_key_gen0, oprf_key_gen1, new_key_gen];

    health_checks::services_health_check(&oprf_key_gens, Duration::from_secs(60)).await?;

    println!("redo key-gen with same id");
    let oprf_key_id = oprf_key_registry_scripts::init_key_gen(
        &anvil.endpoint(),
        oprf_key_registry_contract,
        TACEO_ADMIN_PRIVATE_KEY,
    );
    let _oprf_public_key = health_checks::oprf_public_key_from_services(
        oprf_key_id,
        ShareEpoch::default(),
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
        oprf_key_id,
        ShareEpoch::default(),
        action,
        Connector::Plain,
        &mut rng,
    )
    .await?;

    Ok(())
}
