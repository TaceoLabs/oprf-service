[private]
default:
    @just --justfile {{ justfile() }} --list --list-heading $'Project commands:\n'

[private]
[working-directory('logs')]
load-key-registry:
    grep -oP 'OprfKeyRegistry proxy deployed to: \K0x[a-fA-F0-9]+' deploy_oprf_key_registry.log

[group('test')]
rust-tests:
    cargo test --release --workspace --all-features

[group('test')]
contract-tests:
    cd contracts && forge test

[group('test')]
e2e-test:
    @bash scripts/run-setup.sh e2e-test || { echo -e "\033[1;41m===== TEST FAILED =====\033[0m" ; exit 1; }

[group('test')]
backfill-monkey-test:
    @bash scripts/run-backfill-monkey-test.sh || { echo -e "\033[1;41m===== BACKFILL MONKEY TEST FAILED =====\033[0m" ; exit 1; }

[group('test')]
all-tests: rust-tests contract-tests e2e-test backfill-monkey-test

[group('test')]
generate-contract-kats:
    cargo run --bin generate-test-transcript --features="generate-test-transcript" -- --key-gen-zkey-path artifacts/OPRFKeyGen.13.arks.zkey --key-gen-witness-graph-path artifacts/OPRFKeyGenGraph.13.bin --output contracts/test/Contributions.t.sol
    cd contracts && forge fmt

[group('local-setup')]
run-setup:
    @bash scripts/run-setup.sh sleep

[group('ci')]
check-pr: lint all-tests

[group('ci')]
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --tests --examples --benches --bins -q -- -D warnings
    cargo clippy -p taceo-oprf-client --target wasm32-unknown-unknown -q -- -D warnings
    cargo clippy --workspace --tests --examples --benches --bins -q --all-features -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps --document-private-items
    cd contracts && forge fmt

[group('dev-client')]
run-dev-client *args:
    OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT=$(just load-key-registry) cargo run --release --example dev-client-example {{ args }}
