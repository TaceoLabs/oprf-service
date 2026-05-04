#!/usr/bin/env bash
# Shared helpers for run-setup.sh and run-backfill-monkey-test.sh.
# Sourcing scripts should already have set `set -Eeuo pipefail` and changed to the repo root.

# -------------------------
# Defaults and peer config
# -------------------------
TACEO_ADMIN_ADDRESS="${TACEO_ADMIN_ADDRESS:-0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266}"
ADMIN_PRIVATE_KEY="${TACEO_ADMIN_PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
THRESHOLD="${THRESHOLD:-2}"
NUM_PEERS="${NUM_PEERS:-3}"
RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
WS_RPC_URL="${WS_RPC_URL:-ws://127.0.0.1:8545}"
POSTGRES_URL="${POSTGRES_URL:-postgres://postgres:postgres@localhost:5432/postgres}"
COMPOSE_FILE="${COMPOSE_FILE:-./oprf-service/examples/deploy/docker-compose.yml}"
LOG_TAG="${LOG_TAG:-[oprf]}"
LOG_DIR="${LOG_DIR:-logs}"

node_private_keys=(
    "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356"
    "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97"
    "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"
)

participant_addresses=(
    "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955"
    "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f"
    "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720"
)

schemas=("oprf0" "oprf1" "oprf2")

DEPLOYED_ADDRESS=""
ANVIL_LOG_PID=""
keygen_pids=()
nodes_pids=()

# -------------------------
# Generic helpers
# -------------------------
log() {
    printf '%s %s\n' "$LOG_TAG" "$*"
}

fail() {
    printf '%s %s\n' "$LOG_TAG" "$*" >&2
    exit 1
}

reset_log_dir() {
    rm -rf "$LOG_DIR"
    mkdir -p "$LOG_DIR"
}

array_contains() {
    local needle=$1
    local item
    shift

    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

peer_indices() {
    local i
    for ((i = 0; i < NUM_PEERS; i++)); do
        printf '%s\n' "$i"
    done
}

validate_peer_config() {
    [[ "$NUM_PEERS" =~ ^[0-9]+$ ]] || fail "NUM_PEERS must be a positive integer"
    ((NUM_PEERS > 0)) || fail "NUM_PEERS must be greater than zero"
    ((NUM_PEERS <= ${#node_private_keys[@]})) || fail "NUM_PEERS=${NUM_PEERS} exceeds configured node private keys"
    ((NUM_PEERS <= ${#participant_addresses[@]})) || fail "NUM_PEERS=${NUM_PEERS} exceeds configured participant addresses"
    ((NUM_PEERS <= ${#schemas[@]})) || fail "NUM_PEERS=${NUM_PEERS} exceeds configured postgres schemas"
}

require_commands() {
    local cmd
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || fail "Missing required command: $cmd"
    done
}

require_docker_compose() {
    docker compose version >/dev/null 2>&1 || fail "Missing required docker compose plugin"
}

require_setup_commands() {
    require_commands cargo cast curl docker forge
    require_docker_compose
}

require_keygen_test_commands() {
    require_commands cargo cast curl docker forge sqlx
    require_docker_compose
}

# -------------------------
# Process helpers
# -------------------------
kill_pid_array() {
    local pid
    for pid in "$@"; do
        [[ -n "${pid:-}" ]] && kill "$pid" 2>/dev/null || true
    done
}

terminate_pid_gracefully() {
    local label=$1
    local pid=$2
    local wait_status

    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid"
        wait_status=0
        wait "$pid" || wait_status=$?
        if ((wait_status == 0)); then
            log "${label} shutdown completed"
        else
            fail "${label} exited with status ${wait_status} during shutdown"
        fi
    fi
}

# -------------------------
# Docker lifecycle
# -------------------------
compose_up_anvil_postgres() {
    log "Starting local dependencies"
    mkdir -p "$LOG_DIR"
    docker compose -f "$COMPOSE_FILE" up -d anvil postgres >/dev/null
    docker logs -f anvil >"$LOG_DIR/anvil.log" 2>&1 &
    ANVIL_LOG_PID=$!
    wait_for_anvil
    wait_for_postgres
    if [[ -n "${ANVIL_ARGS:-}" ]]; then
        log "Anvil started with args: $ANVIL_ARGS"
    else
        log "Anvil started in auto-mine mode (no extra args)"
    fi
}

compose_down() {
    [[ -n "${ANVIL_LOG_PID:-}" ]] && kill "$ANVIL_LOG_PID" 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
}

wait_for_anvil() {
    local timeout_secs=60
    local start_time
    start_time=$(date +%s)

    while true; do
        local response
        response=$(curl -sS -X POST \
            --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}' \
            -H "Content-Type: application/json" \
            "$RPC_URL" || true)

        if [[ "$response" == *"anvil"* ]]; then
            log "Anvil is healthy"
            return 0
        fi

        if (($(date +%s) - start_time >= timeout_secs)); then
            fail "Anvil did not become healthy within ${timeout_secs}s"
        fi
        sleep 1
    done
}

wait_for_postgres() {
    local timeout_secs=60
    local start_time
    start_time=$(date +%s)

    while true; do
        if docker exec postgres pg_isready -U postgres -d postgres >/dev/null 2>&1; then
            log "Postgres is healthy"
            return 0
        fi
        if (($(date +%s) - start_time >= timeout_secs)); then
            fail "Postgres did not become healthy within ${timeout_secs}s"
        fi
        sleep 1
    done
}

# -------------------------
# Contract actions
# -------------------------
extract_deployed_address() {
    local log_file=$1
    DEPLOYED_ADDRESS=$(
        perl -pe 's/\e\[[0-9;]*[[:alpha:]]//g' "$log_file" \
            | sed -n 's/.*OprfKeyRegistry proxy deployed to:[[:space:]]*\(0x[0-9A-Fa-f]\{40\}\).*/\1/p' \
            | tail -n 1
    )
    if [[ -z "$DEPLOYED_ADDRESS" ]]; then
        tail -n 80 "$log_file" >&2 || true
        fail "Could not parse deployed key-registry address from $log_file"
    fi
}

deploy_key_registry() {
    local participant_csv
    participant_csv=$(IFS=,; printf '%s' "${participant_addresses[*]}")
    mkdir -p "$LOG_DIR"

    log "Deploying OprfKeyRegistry"
    (
        cd contracts/script/deploy
        env \
            TACEO_ADMIN_ADDRESS="$TACEO_ADMIN_ADDRESS" \
            THRESHOLD="$THRESHOLD" \
            NUM_PEERS="$NUM_PEERS" \
            forge script OprfKeyRegistryWithDeps.s.sol \
            --broadcast \
            --fork-url "$RPC_URL" \
            -vvvvv \
            --private-key "$ADMIN_PRIVATE_KEY"
    ) 2>&1 | tee "$LOG_DIR/deploy_oprf_key_registry.log"

    extract_deployed_address "$LOG_DIR/deploy_oprf_key_registry.log"
    log "Deployed to $DEPLOYED_ADDRESS"

    log "Registering participants on $DEPLOYED_ADDRESS"
    (
        cd contracts/script
        PARTICIPANT_ADDRESSES="$participant_csv" \
        OPRF_KEY_REGISTRY_PROXY="$DEPLOYED_ADDRESS" \
        forge script RegisterParticipants.s.sol \
            --broadcast \
            --fork-url "$RPC_URL" \
            -vvvvv \
            --private-key "$ADMIN_PRIVATE_KEY"
    ) 2>&1 | tee "$LOG_DIR/register_participants.log"
}

cast_send_contract() {
    local fn_sig=$1
    local key_id=$2
    local log_file=$3

    log "Sending ${fn_sig%%(*} for key ${key_id}"
    cast send "$DEPLOYED_ADDRESS" \
        "$fn_sig" "$key_id" \
        --rpc-url "$RPC_URL" \
        --private-key "$ADMIN_PRIVATE_KEY" >>"$LOG_DIR/${log_file}" 2>&1
}

send_init_keygen() { cast_send_contract "initKeyGen(uint160)" "$1" "${2:-init-keygens.log}"; }
send_init_reshare() { cast_send_contract "initReshare(uint160)" "$1" "${2:-reshares.log}"; }
send_delete_key() { cast_send_contract "deleteOprfPublicKey(uint160)" "$1" "${2:-deletes.log}"; }

key_registered() {
    local key_id=$1
    local call_data
    call_data=$(cast calldata "getOprfPublicKey(uint160)" "$key_id")
    cast call "$DEPLOYED_ADDRESS" --data "$call_data" --rpc-url "$RPC_URL" >/dev/null 2>&1
}

# -------------------------
# Service lifecycle
# -------------------------
wait_for_health() {
    local base_port=$1
    local count=$2
    local service_name=$3
    local timeout_secs=${4:-60}
    local i

    for ((i = 0; i < count; i++)); do
        local port=$((base_port + i))
        local start_time
        start_time=$(date +%s)
        log "Waiting for ${service_name} node ${i} on port ${port}"
        while true; do
            local http_code
            http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${port}/health" || printf '000')
            if [[ "$http_code" == "200" ]]; then
                break
            fi
            if (($(date +%s) - start_time >= timeout_secs)); then
                fail "${service_name} node ${i} did not become healthy within ${timeout_secs}s"
            fi
            sleep 1
        done
    done
}

start_keygen_node() {
    local i=$1
    local port=$((20000 + i))
    local schema="${schemas[$i]}"
    mkdir -p "$LOG_DIR"

    RUST_LOG="taceo=trace,warn" \
    TACEO_OPRF_KEY_GEN__BIND_ADDR="0.0.0.0:${port}" \
    TACEO_OPRF_KEY_GEN__SERVICE__WALLET_PRIVATE_KEY="${node_private_keys[$i]}" \
    TACEO_OPRF_KEY_GEN__SERVICE__ENVIRONMENT=dev \
    TACEO_OPRF_KEY_GEN__SERVICE__ZKEY_PATH=./artifacts/OPRFKeyGen.13.arks.zkey \
    TACEO_OPRF_KEY_GEN__SERVICE__WITNESS_GRAPH_PATH=./artifacts/OPRFKeyGenGraph.13.bin \
    TACEO_OPRF_KEY_GEN__SERVICE__OPRF_KEY_REGISTRY_CONTRACT="$DEPLOYED_ADDRESS" \
    TACEO_OPRF_KEY_GEN__SERVICE__CONFIRMATIONS_FOR_TRANSACTION=1 \
    TACEO_OPRF_KEY_GEN__SERVICE__EXPECTED_THRESHOLD="$THRESHOLD" \
    TACEO_OPRF_KEY_GEN__SERVICE__EXPECTED_NUM_PEERS="$NUM_PEERS" \
    TACEO_OPRF_KEY_GEN__SERVICE__WS_RPC_URL="$WS_RPC_URL" \
    TACEO_OPRF_KEY_GEN__SERVICE__RPC__HTTP_URLS="$RPC_URL" \
    TACEO_OPRF_KEY_GEN__SERVICE__RPC__CHAIN_ID=31337 \
    TACEO_OPRF_KEY_GEN__SERVICE__BACKFILL__SKIP_BACKFILL="no" \
    TACEO_OPRF_KEY_GEN__SERVICE__BACKFILL__CONFIRMATIONS_AFTER_SYNC_BLOCK=2 \
    TACEO_OPRF_KEY_GEN__SERVICE__BACKFILL__CHUNK_SIZE=2 \
    TACEO_OPRF_KEY_GEN__POSTGRES__CONNECTION_STRING="$POSTGRES_URL" \
    TACEO_OPRF_KEY_GEN__POSTGRES__SCHEMA="$schema" \
    ./target/release/taceo-oprf-key-gen >>"$LOG_DIR/key-gen${i}.log" 2>&1 &
    keygen_pids[$i]="$!"
    log "started key-gen${i} with PID ${keygen_pids[$i]}"
}

start_keygens() {
    local i
    validate_peer_config
    log "Starting OPRF key-gen nodes"
    mkdir -p "$LOG_DIR"

    for i in $(peer_indices); do
        start_keygen_node "$i"
    done
}

shutdown_keygens() {
    local i
    log "Gracefully shutting down all key-gen nodes"

    for i in "${!keygen_pids[@]}"; do
        terminate_pid_gracefully "key-gen${i}" "${keygen_pids[$i]}"
    done
    keygen_pids=()
}

start_oprf_service_nodes() {
    local oprf_key_registry=$1
    local i
    validate_peer_config
    log "Starting OPRF service nodes"
    mkdir -p "$LOG_DIR"

    for i in $(peer_indices); do
        local port=$((10000 + i))
        local wallet="${participant_addresses[$i]}"

        RUST_LOG="taceo=trace,warn" \
        TACEO_OPRF_NODE__POSTGRES__CONNECTION_STRING="$POSTGRES_URL" \
        TACEO_OPRF_NODE__POSTGRES__SCHEMA="${schemas[$i]}" \
        TACEO_OPRF_NODE__SERVICE__ENVIRONMENT=dev \
        TACEO_OPRF_NODE__SERVICE__OPRF_KEY_REGISTRY_CONTRACT="$oprf_key_registry" \
        TACEO_OPRF_NODE__SERVICE__WS_RPC_URL="$WS_RPC_URL" \
        TACEO_OPRF_NODE__RPC__HTTP_URLS="$RPC_URL" \
        TACEO_OPRF_NODE__RPC__CHAIN_ID=31337 \
        TACEO_OPRF_NODE__SERVICE__VERSION_REQ=">=0.0.0" \
        TACEO_OPRF_NODE__BIND_ADDR="0.0.0.0:${port}" \
        ./target/release/examples/taceo-oprf-service-example >"$LOG_DIR/node${i}.log" 2>&1 &
        nodes_pids[$i]="$!"
        log "started node${i} with PID ${nodes_pids[$i]} (wallet $wallet)"
    done
}

# -------------------------
# DB and verification helpers
# -------------------------
docker_psql() {
    local sql=$1
    docker exec -i postgres psql -U postgres -d postgres -v ON_ERROR_STOP=1 -Atqc "$sql"
}

build_keygen_binary() {
    log "Building taceo-oprf-key-gen"
    cargo build --release --bin taceo-oprf-key-gen >"$LOG_DIR/build-keygen.log" 2>&1
}

prepare_keygen_db() {
    local schema
    validate_peer_config

    for schema in "${schemas[@]}"; do
        local migration_url="${POSTGRES_URL}?options[search_path]=${schema}"
        log "Preparing schema ${schema}"
        docker_psql "CREATE SCHEMA IF NOT EXISTS \"${schema}\";"
        sqlx migrate run \
            --no-dotenv \
            --source oprf-key-gen/migrations \
            --database-url "$migration_url" >"$LOG_DIR/sqlx-${schema}.log" 2>&1
    done
}

verify_chain_cursors() {
    local schema
    local reference_row=""
    local reference_schema=""

    for schema in "${schemas[@]}"; do
        local row
        local block
        local idx

        row=$(docker_psql "SELECT block, idx FROM \"${schema}\".chain_cursor;")
        IFS='|' read -r block idx <<< "$row"

        [[ -n "$block" && -n "$idx" ]] || fail "Missing chain cursor row for schema ${schema}"
        if [[ -n "$reference_row" && "$row" != "$reference_row" ]]; then
            fail "Schema ${schema} cursor ${row} did not match schema ${reference_schema} cursor ${reference_row}"
        fi

        if [[ -z "$reference_row" ]]; then
            reference_row=$row
            reference_schema=$schema
        fi

        log "Schema ${schema} cursor advanced to block ${block}, idx ${idx}"
    done

    log "All schemas converged to the same final cursor ${reference_row}"
}

# -------------------------
# Teardown and debug
# -------------------------
setup_teardown() {
    log "Tearing down"
    kill_pid_array "${keygen_pids[@]-}"
    kill_pid_array "${nodes_pids[@]-}"
    compose_down
}

keygen_test_teardown() {
    local exit_code=$?
    set +e
    trap - EXIT
    kill_pid_array "${keygen_pids[@]-}"
    compose_down
    exit "$exit_code"
}

print_keygen_failure_debug() {
    local message=$1
    local i
    printf '%s %s\n' "$LOG_TAG" "$message" >&2
    for i in $(peer_indices); do
        printf '%s tail key-gen%s.log\n' "$LOG_TAG" "$i" >&2
        tail -n 80 "$LOG_DIR/key-gen${i}.log" >&2 || true
    done
}
