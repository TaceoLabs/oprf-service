#!/usr/bin/env bash
set -Eeuo pipefail

export TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
export THRESHOLD=2
export NUM_PEERS=3

keygen_pids=()
nodes_pids=()
DEPLOYED_ADDRESS=""

RUN_MODE="${1:-sleep}"  # default to 'sleep' if no argument provided

create_secret() {
    local name="$1"
    local value="$2"

    AWS_ACCESS_KEY_ID=test \
    AWS_SECRET_ACCESS_KEY=test \
    aws \
        --region us-east-1 \
        --endpoint-url http://localhost:4566 \
        secretsmanager create-secret \
        --name "$name" \
        --secret-string "$value"
}

# -------------------------
# Deploy key registry and register participants
# -------------------------
run_deploy() {
    mkdir -p logs

    create_secret "oprf/eth/n0" "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356"
    create_secret "oprf/eth/n1" "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97"
    create_secret "oprf/eth/n2" "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"

    # deploy key registry
    (cd contracts/script/deploy && \
    TACEO_ADMIN_ADDRESS=$TACEO_ADMIN_ADDRESS THRESHOLD=$THRESHOLD NUM_PEERS=$NUM_PEERS \
    forge script OprfKeyRegistryWithDeps.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80) \
    2>&1 | tee logs/deploy_oprf_key_registry.log

    DEPLOYED_ADDRESS=$(grep -oP 'OprfKeyRegistry proxy deployed to: \K0x[a-fA-F0-9]+' logs/deploy_oprf_key_registry.log)
    echo "Deployed to $DEPLOYED_ADDRESS"

    # register participants
    (cd contracts/script && \
    PARTICIPANT_ADDRESSES=0x14dC79964da2C08b23698B3D3cc7Ca32193d9955,0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f,0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 \
    OPRF_KEY_REGISTRY_PROXY=$DEPLOYED_ADDRESS \
    forge script RegisterParticipants.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80)

    cargo clean --workspace 
    cargo build --workspace --release --examples --bins
    echo "starting keygen"
    # need to start key-gen before nodes because they run DB migrations
    start_keygen "$DEPLOYED_ADDRESS"
    wait_for_health 20000 3 "key-gen" 300

    echo "starting nodes"
    start_nodes "$DEPLOYED_ADDRESS"
    wait_for_health 10000 3 "oprf-service" 300
}

# -------------------------
# Health check helper
# -------------------------
wait_for_health() {
    local base_port=$1
    local count=$2
    local service_name=$3
    local timeout=${4:-60}

    for i in $(seq 0 $((count - 1))); do
        local port=$((base_port + i))
        local start_time=$(date +%s)
        echo "Waiting for $service_name node $i on port $port to be healthy..."

        while true; do
            http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$port/health" || echo "000")
            if [[ "$http_code" == "200" ]]; then
                echo "$service_name node $i is healthy!"
                break
            fi
            now=$(date +%s)
            if (( now - start_time >= timeout )); then
                echo "Error: $service_name node $i did not become healthy after $timeout seconds" >&2
                exit 1
            fi
            sleep 1
        done
    done
}

# -------------------------
# Start keygen nodes
# -------------------------
start_keygen() {
    local oprf_key_registry="$1"
    echo "Starting OPRF key-gen nodes..."
    mkdir -p logs

    for i in 0 1 2; do
        local port=$((20000 + i))
        local prefix="n$i"
        local db_port=$((5432 + i))
        local db_conn="postgres://postgres:postgres@localhost:$db_port/postgres"

        RUST_LOG="taceo_oprf_key_gen=trace,warn" \
        ./target/release/oprf-key-gen \
            --bind-addr 127.0.0.1:$port \
            --environment dev \
            --wallet-private-key-secret-id oprf/eth/$prefix \
            --key-gen-zkey-path ./circom/main/key-gen/OPRFKeyGen.13.arks.zkey \
            --key-gen-witness-graph-path ./circom/main/key-gen/OPRFKeyGenGraph.13.bin \
            --oprf-key-registry-contract $oprf_key_registry \
            --confirmations-for-transaction 1 \
            --db-connection-string $db_conn \
            --db-schema oprf \
            > logs/key-gen$i.log 2>&1 &
        keygen_pids+=($!)
        echo "started key-gen$i with PID ${keygen_pids[$i]}"
    done
}

# -------------------------
# Start OPRF service nodes
# -------------------------
start_nodes() {
    local oprf_key_registry="$1"
    echo "Starting OPRF service nodes..."
    mkdir -p logs

    for i in 0 1 2; do
        local port=$((10000 + i))
        local wallet
        case $i in
            0) wallet=0x14dC79964da2C08b23698B3D3cc7Ca32193d9955 ;;
            1) wallet=0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f ;;
            2) wallet=0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 ;;
        esac
        local db_port=$((5432 + i))
        local db_conn="postgres://postgres:postgres@localhost:$db_port/postgres"

        RUST_LOG="taceo_oprf_service=trace,taceo_oprf_service_example=trace,oprf_service_example=trace,warn" \
        ./target/release/examples/oprf-service-example \
            --bind-addr 127.0.0.1:$port \
            --environment dev \
            --version-req ">=0.0.0" \
            --oprf-key-registry-contract $oprf_key_registry \
            --db-connection-string $db_conn \
            --db-schema oprf \
            > logs/node$i.log 2>&1 &
        nodes_pids+=($!)
        echo "started node$i with PID ${nodes_pids[$i]}"
    done
}

# -------------------------
# Main
# -------------------------
main() {
    rm -rf logs/*
    docker compose -f ./oprf-service/examples/deploy/docker-compose.yml up -d localstack anvil postgres0 postgres1 postgres2

    # centralized teardown
    teardown() {
        echo "Tearing down..."
        docker compose -f ./oprf-service/examples/deploy/docker-compose.yml down

        for pid in "${keygen_pids[@]-}"; do kill "$pid" 2>/dev/null || true; done
        for pid in "${nodes_pids[@]-}"; do kill "$pid" 2>/dev/null || true; done
    }

    trap teardown EXIT SIGINT SIGTERM

    # Deploy everything
    run_deploy

    if [[ "$RUN_MODE" == "e2e-test" ]]; then
        echo "Running dev-client tests..."
        OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT=$DEPLOYED_ADDRESS \
            ./target/release/examples/dev-client-example reshare-test
        OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT=$DEPLOYED_ADDRESS \
            ./target/release/examples/dev-client-example stress-test
        echo "Dev-client tests completed successfully"
    else
        echo "No dev-client tests requested, entering sleep mode. Press Ctrl+C to stop..."
        while true; do sleep 3600; done
    fi
}

main "$@"

