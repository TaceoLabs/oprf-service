[private]
default:
    @just --justfile {{ justfile() }} --list --list-heading $'Project commands:\n'

[private]
prepare-localstack-secrets:
    AWS_ACCESS_KEY_ID=test \
    AWS_SECRET_ACCESS_KEY=test \
    aws --region us-east-1 --endpoint-url=http://localhost:4566 secretsmanager create-secret \
      --name oprf/eth/n0 \
      --secret-string '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356'
    AWS_ACCESS_KEY_ID=test \
    AWS_SECRET_ACCESS_KEY=test \
    aws --region us-east-1 --endpoint-url=http://localhost:4566 secretsmanager create-secret \
      --name oprf/eth/n1 \
      --secret-string '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97'
    AWS_ACCESS_KEY_ID=test \
    AWS_SECRET_ACCESS_KEY=test \
    aws --region us-east-1 --endpoint-url=http://localhost:4566 secretsmanager create-secret \
      --name oprf/eth/n2 \
      --secret-string '0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6'

[group('build')]
export-contract-abi:
    cd oprf-key-registry && forge build --silent && jq '.abi' out/OprfKeyRegistry.sol/OprfKeyRegistry.json > ../oprf-types/OprfKeyRegistry.json

[group('build')]
[working-directory('circom')]
print-constraints:
    #!/usr/bin/env bash
    key_gen13=$(circom main/OPRFKeyGenProof13.circom -l . --r1cs --O2 | grep -oP "non-linear constraints: \K[0-9]+")
    key_gen25=$(circom main/OPRFKeyGenProof25.circom -l . --r1cs --O2 | grep -oP "non-linear constraints: \K[0-9]+")
    key_gen37=$(circom main/OPRFKeyGenProof37.circom -l . --r1cs --O2 | grep -oP "non-linear constraints: \K[0-9]+")
    nullifier=$(circom main/OPRFNullifierProof.circom -l . --r1cs --O2 | grep -oP "non-linear constraints: \K[0-9]+")
    proof=$(circom main/OPRFQueryProof.circom -l . --r1cs --O2 | grep -oP "non-linear constraints: \K[0-9]+")
    eddsa_poseidon2=$(circom debug/eddsaposeidon2.circom -l . --r1cs --O2 | grep -oP "non-linear constraints: \K[0-9]+")
    verify_dlog=$(circom debug/verify_dlog.circom -l . --r1cs --O2 | grep -oP "non-linear constraints: \K[0-9]+")
    subgroup_check=$(circom debug/subgroup_check.circom -l . --r1cs --O2 | grep -oP "non-linear constraints: \K[0-9]+")
    printf "%-20s %s\n" "Circuit" "Constraints"
    printf "%-20s %s\n" "KeyGen(3-1)" "$key_gen13"
    printf "%-20s %s\n" "KeyGen(5-2)" "$key_gen25"
    printf "%-20s %s\n" "KeyGen(7-3)" "$key_gen37"
    printf "%-20s %s\n" "OPRFNullifier" "$nullifier"
    printf "%-20s %s\n" "QueryProof" "$proof"
    printf "%-20s %s\n" "EdDSA-Poseidon2" "$eddsa_poseidon2"
    printf "%-20s %s\n" "Verify DLog" "$verify_dlog"
    printf "%-20s %s\n" "Subgroup Checks" "$subgroup_check"
    rm OPRFKeyGenProof13.r1cs OPRFKeyGenProof25.r1cs OPRFKeyGenProof37.r1cs OPRFNullifierProof.r1cs OPRFQueryProof.r1cs eddsaposeidon2.r1cs subgroup_check.r1cs verify_dlog.r1cs

[group('build')]
[working-directory('circom/main/query')]
build-query-artifacts:
    circom --r1cs ../OPRFQueryProof.circom -l ../../ --O2 --output ../
    snarkjs groth16 setup ../OPRFQueryProof.r1cs ../../powersOfTau28_hez_final_17.ptau OPRFQuery.zkey
    snarkjs zkey contribute OPRFQuery.zkey OPRFQuery.zkey.new --name="TACEO" -v
    mv OPRFQuery.zkey.new OPRFQuery.zkey
    snarkjs zkey export verificationkey OPRFQuery.zkey OPRFQuery.vk.json
    convert-zkey-to-ark --zkey-path OPRFQuery.zkey --uncompressed
    mv arks.zkey OPRFQuery.arks.zkey

[group('build')]
[working-directory('circom/main/nullifier')]
build-nullifier-artifacts:
    circom --r1cs ../OPRFNullifierProof.circom -l ../../ --O2 --output ../
    snarkjs groth16 setup ../OPRFNullifierProof.r1cs ../../powersOfTau28_hez_final_17.ptau OPRFNullifier.zkey
    snarkjs zkey contribute OPRFNullifier.zkey OPRFNullifier.zkey.new --name="TACEO" -v
    mv OPRFNullifier.zkey.new OPRFNullifier.zkey
    snarkjs zkey export verificationkey OPRFNullifier.zkey OPRFNullifier.vk.json
    convert-zkey-to-ark --zkey-path OPRFNullifier.zkey --uncompressed
    mv arks.zkey OPRFNullifier.arks.zkey

[group('build')]
[working-directory('circom/main/key-gen')]
build-key-gen-artifacts degree-parties:
    circom --r1cs ../OPRFKeyGenProof{{ degree-parties }}.circom -l ../../ --O2 --output ../
    snarkjs groth16 setup ../OPRFKeyGenProof{{ degree-parties }}.r1cs ../../powersOfTau28_hez_final_17.ptau OPRFKeyGen.{{ degree-parties }}.zkey
    snarkjs zkey contribute OPRFKeyGen.{{ degree-parties }}.zkey OPRFKeyGen.{{ degree-parties }}.zkey.new --name="TACEO" -v
    mv OPRFKeyGen.{{ degree-parties }}.zkey.new OPRFKeyGen.{{ degree-parties }}.zkey
    snarkjs zkey export verificationkey OPRFKeyGen.{{ degree-parties }}.zkey OPRFKeyGen.{{ degree-parties }}.vk.json
    convert-zkey-to-ark --zkey-path OPRFKeyGen.{{ degree-parties }}.zkey --uncompressed
    mv arks.zkey OPRFKeyGen.{{ degree-parties }}.arks.zkey

[group('build')]
[working-directory('circom/main/query')]
build-query-graph:
    circom --r1cs ../OPRFQueryProof.circom -l ../../ --O2 --output ../
    cd ../../../../circom-witness-rs && WITNESS_CPP=../oprf-service/circom/main/OPRFQueryProof.circom CIRCOM_LIBRARY_PATH=../oprf-service/circom/ cargo run --bin generate-graph --features build-witness
    mv ../../../../circom-witness-rs/graph.bin ./OPRFQueryGraph.bin

[group('build')]
[working-directory('circom/main/nullifier')]
build-nullifier-graph:
    circom --r1cs ../OPRFNullifierProof.circom -l ../../ --O2 --output ../
    cd ../../../../circom-witness-rs && WITNESS_CPP=../oprf-service/circom/main/OPRFNullifierProof.circom CIRCOM_LIBRARY_PATH=../oprf-service/circom/ cargo run --bin generate-graph --features build-witness
    mv ../../../../circom-witness-rs/graph.bin ./OPRFNullifierGraph.bin

[group('build')]
[working-directory('circom/main/key-gen')]
build-key-gen-graph degree-parties:
    circom --r1cs ../OPRFKeyGenProof{{ degree-parties }}.circom -l ../../ --O2 --output ../
    cd ../../../../circom-witness-rs && WITNESS_CPP=../oprf-service/circom/main/OPRFKeyGenProof{{ degree-parties }}.circom CIRCOM_LIBRARY_PATH=../oprf-service/circom/ cargo run --bin generate-graph --features build-witness
    mv ../../../../circom-witness-rs/graph.bin ./OPRFKeyGenGraph.{{ degree-parties }}.bin

[group('test')]
unit-tests:
    cargo test --release --all-features --lib

[group('test')]
integration-tests:
    cargo test --release --package taceo-oprf-test

[group('test')]
all-rust-tests:
    cargo test --release --workspace --all-features

[group('test')]
circom-tests:
    cd circom/tests && npm ci && npm test

[group('test')]
contract-tests:
    cd oprf-key-registry && forge test

[group('test')]
all-tests: all-rust-tests circom-tests contract-tests

[group('ci')]
check-pr: lint all-rust-tests circom-tests contract-tests

[group('ci')]
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --tests --examples --benches --bins -q -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps --document-private-items
    cd oprf-key-registry && forge fmt

[group('local-setup')]
run-key-gen-instances:
    #!/usr/bin/env bash
    mkdir -p logs
    cargo build --workspace --release
    # anvil wallet 7
    RUST_LOG="taceo_oprf_key_gen=trace,warn" ./target/release/oprf-key-gen --bind-addr 127.0.0.1:20000 --rp-secret-id-prefix oprf/rp/n0 --environment dev --wallet-private-key-secret-id oprf/eth/n0 --key-gen-zkey-path ./circom/main/key-gen/OPRFKeyGen.13.arks.zkey --key-gen-witness-graph-path ./circom/main/key-gen/OPRFKeyGenGraph.13.bin  > logs/key-gen0.log 2>&1 &
    pid0=$!
    echo "started key-gen0 with PID $pid0"
    # anvil wallet 8
    RUST_LOG="taceo_oprf_key_gen=trace,warn" ./target/release/oprf-key-gen --bind-addr 127.0.0.1:20001 --rp-secret-id-prefix oprf/rp/n1 --environment dev --wallet-private-key-secret-id oprf/eth/n1 --key-gen-zkey-path ./circom/main/key-gen/OPRFKeyGen.13.arks.zkey --key-gen-witness-graph-path ./circom/main/key-gen/OPRFKeyGenGraph.13.bin  > logs/key-gen1.log 2>&1 &
    pid1=$!
    echo "started key-gen1 with PID $pid1"
    # anvil wallet 9
    RUST_LOG="taceo_oprf_key_gen=trace,warn" ./target/release/oprf-key-gen --bind-addr 127.0.0.1:20002 --rp-secret-id-prefix oprf/rp/n2 --environment dev --wallet-private-key-secret-id oprf/eth/n2 --key-gen-zkey-path ./circom/main/key-gen/OPRFKeyGen.13.arks.zkey --key-gen-witness-graph-path ./circom/main/key-gen/OPRFKeyGenGraph.13.bin  > logs/key-gen2.log 2>&1  &
    pid2=$!
    echo "started key-gen2 with PID $pid2"
    trap "kill $pid0 $pid1 $pid2" SIGINT SIGTERM
    wait $pid0 $pid1 $pid2

[group('local-setup')]
run-nodes:
    #!/usr/bin/env bash
    mkdir -p logs
    cargo build --workspace --release
    # anvil wallet 7
    RUST_LOG="taceo_oprf_service=trace,taceo_oprf_service_example=trace,oprf_service_example=trace,warn" ./target/release/oprf-service-example --bind-addr 127.0.0.1:10000 --rp-secret-id-prefix oprf/rp/n0 --environment dev --wallet-address 0x14dC79964da2C08b23698B3D3cc7Ca32193d9955 > logs/node0.log 2>&1 &
    pid0=$!
    echo "started node0 with PID $pid0"
    # anvil wallet 8
    RUST_LOG="taceo_oprf_service=trace,taceo_oprf_service_example=trace,oprf_service_example=trace,warn" ./target/release/oprf-service-example --bind-addr 127.0.0.1:10001 --rp-secret-id-prefix oprf/rp/n1 --environment dev --wallet-address 0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f > logs/node1.log 2>&1 &
    pid1=$!
    echo "started node1 with PID $pid1"
    # anvil wallet 9
    RUST_LOG="taceo_oprf_service=trace,taceo_oprf_service_example=trace,oprf_service_example=trace,warn" ./target/release/oprf-service-example --bind-addr 127.0.0.1:10002 --rp-secret-id-prefix oprf/rp/n2 --environment dev --wallet-address 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 > logs/node2.log 2>&1  &
    pid2=$!
    echo "started node2 with PID $pid2"
    trap "kill $pid0 $pid1 $pid2" SIGINT SIGTERM
    wait $pid0 $pid1 $pid2

[group('local-setup')]
run-setup:
    #!/usr/bin/env bash
    mkdir -p logs
    echo "starting localstack and anvil"
    docker compose -f ./oprf-service-example/deploy/docker-compose.yml up -d localstack anvil
    sleep 1
    echo "preparing localstack"
    just prepare-localstack-secrets
    echo "starting OprfKeyRegistry contract.."
    just deploy-oprf-key-registry-with-deps-anvil | tee logs/deploy_oprf_key_registry.log
    oprf_key_registry=$(grep -oP 'OprfKeyRegistry deployed to: \K0x[a-fA-F0-9]+' logs/deploy_oprf_key_registry.log)
    echo "register oprf-nodes..."
    OPRF_KEY_REGISTRY_PROXY=$oprf_key_registry just register-participants-anvil
    echo "starting OPRF nodes..."
    OPRF_NODE_OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry just run-nodes &
    echo "starting OPRF key-gen instances..."
    OPRF_NODE_OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry just run-key-gen-instances
    echo "stopping containers..."
    docker compose -f ./oprf-service-example/deploy/docker-compose.yml down

[group('dev-client')]
run-dev-client *args:
    cargo run --release --bin taceo-oprf-dev-client {{ args }}

[working-directory('oprf-key-registry')]
show-contract-errors:
    forge inspect src/OprfKeyRegistry.sol:OprfKeyRegistry errors

[working-directory('oprf-key-registry')]
show-contract-methods:
    forge inspect src/OprfKeyRegistry.sol:OprfKeyRegistry methodIdentifiers

[group('deploy')]
[working-directory('oprf-key-registry/script/deploy')]
deploy-oprf-key-registry-with-deps-dry-run *args:
    forge script OprfKeyRegistryWithDeps.s.sol -vvvvv {{ args }}

[group('deploy')]
[working-directory('oprf-key-registry/script/deploy')]
deploy-oprf-key-registry-with-deps *args:
    forge script OprfKeyRegistryWithDeps.s.sol --broadcast --interactives 1 -vvvvv {{ args }} --rpc-url $RPC_URL --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY

[group('deploy')]
[working-directory('oprf-key-registry/script/deploy')]
deploy-oprf-key-registry-dry-run *args:
    forge script OprfKeyRegistry.s.sol -vvvvv {{ args }}

[group('deploy')]
[working-directory('oprf-key-registry/script/deploy')]
deploy-oprf-key-registry *args:
    forge script OprfKeyRegistry.s.sol --broadcast --interactives 1 -vvvvv {{ args }} --rpc-url $RPC_URL --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY

[group('contract')]
[working-directory('oprf-key-registry/script')]
register-participants *args:
    forge script RegisterParticipants.s.sol --broadcast --interactives 1 -vvvvv {{ args }} --rpc-url $RPC_URL

[group('contract')]
[working-directory('oprf-key-registry/script')]
register-participants-dry-run *args:
    forge script RegisterParticipants.s.sol -vvvvv {{ args }}

[group('contract')]
[working-directory('oprf-key-registry/script')]
revoke-key-gen-admin-dry-run *args:
    forge script RevokeKeyGenAdmin.s.sol -vvvvv {{ args }}

[group('contract')]
[working-directory('oprf-key-registry/script')]
revoke-key-gen-admin *args:
    forge script RevokeKeyGenAdmin.s.sol -vvvvv --broadcast --interactives 1 {{ args }} --rpc-url $RPC_URL

[group('contract')]
[working-directory('oprf-key-registry/script')]
register-key-gen-admin-dry-run *args:
    forge script RegisterKeyGenAdmin.s.sol -vvvvv {{ args }}

[group('contract')]
[working-directory('oprf-key-registry/script')]
register-key-gen-admin *args:
    forge script RegisterKeyGenAdmin.s.sol -vvvvv --broadcast --interactives 1 {{ args }} --rpc-url $RPC_URL

[group('anvil')]
[working-directory('oprf-key-registry/script/deploy')]
deploy-oprf-key-registry-with-deps-anvil:
    TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 THRESHOLD=2 NUM_PEERS=3 forge script OprfKeyRegistryWithDeps.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('anvil')]
[working-directory('oprf-key-registry/script/deploy')]
deploy-oprf-key-registry-anvil:
    TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 THRESHOLD=2 NUM_PEERS=3 forge script OprfKeyRegistry.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('anvil')]
[working-directory('oprf-key-registry/script')]
register-participants-anvil:
    PARTICIPANT_ADDRESSES=0x14dC79964da2C08b23698B3D3cc7Ca32193d9955,0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f,0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 forge script RegisterParticipants.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('anvil')]
[working-directory('oprf-key-registry/script')]
revoke-key-gen-admin-anvil:
    forge script RevokeKeyGenAdmin.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('anvil')]
[working-directory('oprf-key-registry/script')]
register-key-gen-admin-anvil:
    forge script RegisterKeyGenAdmin.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('docker')]
build-push-docker-image-oprf-service-amd TAG:
    docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/oprf-service-example:{{ TAG }}-amd64 -f build/Dockerfile.oprf-service-example .
