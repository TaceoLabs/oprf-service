#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

LOG_TAG="[setup]"
LOG_DIR="${LOG_DIR:-logs/setup}"

source "$SCRIPT_DIR/lib.sh"

RUN_MODE="${1:-sleep}"

run_deploy() {
    deploy_key_registry

    cargo clean --workspace
    cargo build --workspace --release --examples --bins

    log "starting keygen"
    # need to start key-gen before nodes because they run DB migrations
    start_keygens
    wait_for_health 20000 "$NUM_PEERS" "key-gen" 300

    log "starting nodes"
    start_oprf_service_nodes "$DEPLOYED_ADDRESS"
    wait_for_health 10000 "$NUM_PEERS" "oprf-service" 300
}

main() {
    require_setup_commands
    validate_peer_config
    reset_log_dir
    
    trap setup_teardown EXIT SIGINT SIGTERM

    compose_up_anvil_postgres
    run_deploy

    if [[ "$RUN_MODE" == "e2e-test" ]]; then
        log "Running dev-client tests"
        OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT=$DEPLOYED_ADDRESS \
            ./target/release/examples/dev-client-example reshare-test
        OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT=$DEPLOYED_ADDRESS \
            ./target/release/examples/dev-client-example stress-test-oprf
        OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT=$DEPLOYED_ADDRESS \
            ./target/release/examples/dev-client-example stress-test-key-gen
        OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT=$DEPLOYED_ADDRESS \
            ./target/release/examples/dev-client-example delete-test
        log "Dev-client tests completed successfully"
    else
        log "No dev-client tests requested, entering sleep mode. Press Ctrl+C to stop"
        while true; do sleep 3600; done
    fi
}

main "$@"
