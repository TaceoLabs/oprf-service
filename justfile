[private]
default:
    @just --justfile {{ justfile() }} --list --list-heading $'Project commands:\n'

[private]
[working-directory('logs')]
load-key-registry:
    grep -oP 'OprfKeyRegistry proxy deployed to: \K0x[a-fA-F0-9]+' deploy_oprf_key_registry.log

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
    groth16-sol-utils extract-verifier --vk OPRFKeyGen.{{ degree-parties }}.vk.json > ../../../contracts/src/VerifierKeyGen{{ degree-parties }}.sol
    cd ../../../contracts && forge fmt

[group('test')]
rust-tests:
    cargo test --release --workspace --all-features

[group('test')]
circom-tests:
    cd circom/tests && npm ci && npm test

[group('test')]
contract-tests:
    cd contracts && forge test

[group('test')]
e2e-test:
    @bash run-setup.sh e2e-test || { echo -e "\033[1;41m===== TEST FAILED =====\033[0m" ; exit 1; }

[group('test')]
all-tests: rust-tests circom-tests contract-tests e2e-test

[group('test')]
generate-contract-kats:
    cargo run --bin generate-test-transcript --features="generate-test-transcript" -- --key-gen-zkey-path circom/main/key-gen/OPRFKeyGen.13.arks.zkey --key-gen-witness-graph-path circom/main/key-gen/OPRFKeyGenGraph.13.bin --output contracts/test/Contributions.t.sol
    cd contracts && forge fmt

[group('local-setup')]
run-setup:
    @bash run-setup.sh sleep

[group('ci')]
check-pr: lint all-tests

[group('ci')]
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --tests --examples --benches --bins -q -- -D warnings
    cargo clippy --workspace --tests --examples --benches --bins -q --all-features -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps --document-private-items
    cd contracts && forge fmt

[group('dev-client')]
run-dev-client *args:
    OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT=$(just load-key-registry) cargo run --release --example dev-client-example {{ args }}

[group('docker')]
build-push-docker-image-oprf-service-amd TAG:
    docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/oprf-service-example:{{ TAG }}-amd64 -f build/Dockerfile.oprf-service-example .
