#!/usr/bin/env bash
# End-to-end test of converting a running deployment from `direct` (plaintext) storage to
# `envelopeV1` under local master keys, with the real binaries against Anvil and Postgres, the
# way a node operator rolls it out:
#
# 1. everything on the defaults (`direct`): keys are generated, reshared and deleted;
# 2. the nodes restart allowing `[direct, envelopeV1]` while the rows are still `direct`;
# 3. the key-gens restart writing `envelopeV1`, which upgrades every row while the nodes keep
#    running, and while a key generation and a reshare are in progress;
# 4. `direct` is removed from the allowed formats everywhere.
#
# After every step all live keys must still be served by every pair of nodes with an unchanged
# public key, and keys from before and after the upgrade are reshared and generated.
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

LOG_TAG="[storage-upgrade]"
LOG_DIR="${LOG_DIR:-logs/storage-upgrade}"
# A key-gen that was down while a round started catches up by backfilling, which needs blocks
# to be mined continuously.
export ANVIL_ARGS="${ANVIL_ARGS:-"--block-time 1"}"

source "$SCRIPT_DIR/lib.sh"

readonly WAIT_TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-120}"
# How long a service that must refuse to start may take to exit.
readonly REFUSE_TIMEOUT_SECS=60
readonly DEV_CLIENT=./target/release/examples/dev-client-example

# Keys generated while everything is `direct`.
readonly KEY_NEVER_RESHARED=1  # first reshared right after the upgrade
readonly KEY_RESHARED_ONCE=2   # reshared before and after the upgrade
readonly KEY_RESHARED_TWICE=3  # reshared twice before the upgrade, again after the lock-down
readonly KEY_UNTOUCHED=4       # not touched until the lock-down
readonly KEY_UNDER_LOAD=5      # reshared under OPRF load after the upgrade
readonly KEY_DELETED=6         # deleted before the upgrade
readonly KEY_RESHARE_IN_PROGRESS=11  # a reshare starts before the upgrade and ends after it
# Its generation starts before the upgrade and ends after it.
readonly KEY_GENERATION_IN_PROGRESS=12
# Keys generated while `direct` and `envelopeV1` are both allowed.
readonly KEY_MIXED=7
readonly KEY_MIXED_RESHARED=8
# Keys generated after the lock-down.
readonly KEY_LOCKED=9
readonly KEY_LOCKED_RESHARED=10

# Indexed by key id: the epoch and public key every node must report for a live key.
key_epoch=()
key_pub=()
live_keys=()
deleted_keys=()

# -------------------------
# Node queries
# -------------------------
node_url() {
    printf 'http://127.0.0.1:%s' "$((10000 + $1))"
}

# Prints the public key and epoch node `i` reports for `key`, or nothing if it has none.
node_key_json() {
    curl -fsS "$(node_url "$1")/oprf_pub/$2" 2>/dev/null || true
}

# Waits until every node reports `key` at `epoch`, then checks that all nodes report the same
# public key, and the one recorded for the key if there is one.
wait_for_key_at_epoch() {
    local key=$1
    local epoch=$2
    local deadline=$((SECONDS + WAIT_TIMEOUT_SECS))
    local i json reported

    while true; do
        reported=()
        for i in $(peer_indices); do
            json=$(node_key_json "$i" "$key")
            if [[ -n "$json" && "$(jq -r '.epoch' <<<"$json")" == "$epoch" ]]; then
                reported+=("$(jq -c '.key' <<<"$json")")
            fi
        done
        ((${#reported[@]} == NUM_PEERS)) && break
        if ((SECONDS >= deadline)); then
            fail "key ${key} did not reach epoch ${epoch} on all nodes within ${WAIT_TIMEOUT_SECS}s"
        fi
        sleep 1
    done

    for i in $(peer_indices); do
        [[ "${reported[$i]}" == "${reported[0]}" ]] \
            || fail "nodes report different public keys for key ${key}"
    done
    if [[ -n "${key_pub[$key]:-}" && "${key_pub[$key]}" != "${reported[0]}" ]]; then
        fail "public key of key ${key} changed: was ${key_pub[$key]}, now ${reported[0]}"
    fi
    key_pub[$key]="${reported[0]}"
    key_epoch[$key]=$epoch
}

wait_for_key_unknown() {
    local key=$1
    local deadline=$((SECONDS + WAIT_TIMEOUT_SECS))
    local i http_code unknown

    while true; do
        unknown=0
        for i in $(peer_indices); do
            http_code=$(curl -s -o /dev/null -w "%{http_code}" "$(node_url "$i")/oprf_pub/${key}" || printf '000')
            [[ "$http_code" == "404" ]] && unknown=$((unknown + 1))
        done
        ((unknown == NUM_PEERS)) && return 0
        if ((SECONDS >= deadline)); then
            fail "deleted key ${key} is still known to a node after ${WAIT_TIMEOUT_SECS}s"
        fi
        sleep 1
    done
}

# Runs a dev-client command for `key` against the given nodes.
dev_client() {
    local key=$1
    local nodes_csv=$2
    shift 2

    OPRF_DEV_CLIENT_NODES="$nodes_csv" \
    OPRF_DEV_CLIENT_OPRF_KEY_ID="$key" \
    OPRF_DEV_CLIENT_THRESHOLD="$THRESHOLD" \
    OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT="$DEPLOYED_ADDRESS" \
    OPRF_DEV_CLIENT_CHAIN_RPC_URL="$RPC_URL" \
    OPRF_DEV_CLIENT_WAIT_TIME="${WAIT_TIMEOUT_SECS}s" \
    RUST_LOG="taceo=debug,dev_client_example=debug,warn" \
    "$DEV_CLIENT" "$@" >>"$LOG_DIR/dev-client.log" 2>&1
}

all_nodes_csv() {
    local urls=()
    local i
    for i in $(peer_indices); do
        urls+=("$(node_url "$i")")
    done
    (IFS=,; printf '%s' "${urls[*]}")
}

# Runs a verified distributed OPRF for `key` with every pair of nodes, so that the share of
# every node is used and each pair reconstructs the public key.
assert_oprf_with_every_pair() {
    local key=$1
    local phase=$2
    local i j

    for ((i = 0; i < NUM_PEERS; i++)); do
        for ((j = i + 1; j < NUM_PEERS; j++)); do
            dev_client "$key" "$(node_url "$i"),$(node_url "$j")" test \
                || fail "${phase}: OPRF for key ${key} failed with nodes ${i} and ${j} (see ${LOG_DIR}/dev-client.log)"
        done
    done
}

# Every live key is reported by all nodes at its epoch with its public key and is usable by
# every pair of nodes; deleted keys stay unknown.
assert_all_keys_work() {
    local phase=$1
    local key

    log "${phase}: checking keys ${live_keys[*]} on all nodes"
    for key in "${live_keys[@]}"; do
        wait_for_key_at_epoch "$key" "${key_epoch[$key]}"
        assert_oprf_with_every_pair "$key" "$phase"
    done
    for key in "${deleted_keys[@]+"${deleted_keys[@]}"}"; do
        wait_for_key_unknown "$key"
    done
}

# -------------------------
# Chain actions
# -------------------------
generate_key() {
    local key=$1
    send_init_keygen "$key"
    wait_for_key_at_epoch "$key" 0
    live_keys+=("$key")
}

# Reshares `key` and waits for the next epoch; the public key must not change.
reshare_key() {
    local key=$1
    send_init_reshare "$key"
    wait_for_key_at_epoch "$key" "$((key_epoch[$key] + 1))"
}

# The id of `key` as stored in the database: 20 bytes, little endian, as hex.
key_id_hex() {
    printf '%02x%038d' "$1" 0
}

delete_key() {
    local key=$1
    local remaining=()
    local live

    send_delete_key "$key"
    wait_for_key_unknown "$key"
    for live in "${live_keys[@]}"; do
        [[ "$live" == "$key" ]] || remaining+=("$live")
    done
    live_keys=("${remaining[@]}")
    deleted_keys+=("$key")
}

# -------------------------
# DB assertions
# -------------------------
# Every row of `shares` and `in_progress_keygens` of every party is stored as `format`.
assert_rows_stored_as() {
    local format=$1
    local phase=$2
    local schema table total other

    for schema in "${schemas[@]}"; do
        total=$(docker_psql "SELECT COUNT(*) FROM \"${schema}\".shares;")
        ((total > 0)) || fail "${phase}: schema ${schema} has no shares"
        # Finished key generations delete their rows, so `in_progress_keygens` may be empty.
        for table in shares in_progress_keygens; do
            other=$(docker_psql "SELECT COUNT(*) FROM \"${schema}\".${table} WHERE storage_format <> '${format}';")
            [[ "$other" == "0" ]] \
                || fail "${phase}: schema ${schema} has ${other} rows in ${table} not stored as ${format}"
        done
    done
    log "${phase}: all rows are stored as ${format}"
}

# Every party has `expected` data keys. If it has any, they are wrapped under a local master
# key, every row references one of them, and no two parties wrap under the same master key.
assert_data_keys() {
    local expected=$1
    local phase=$2
    local schema count bad
    local wrapping_key_ids=""

    for schema in "${schemas[@]}"; do
        count=$(docker_psql "SELECT COUNT(*) FROM \"${schema}\".data_keys;")
        [[ "$count" == "$expected" ]] \
            || fail "${phase}: schema ${schema} has ${count} data keys, expected ${expected}"
        bad=$(docker_psql "SELECT COUNT(*) FROM \"${schema}\".data_keys WHERE wrapping <> 'localKeyV1';")
        [[ "$bad" == "0" ]] || fail "${phase}: schema ${schema} has data keys not wrapped as localKeyV1"
        wrapping_key_ids+="$(docker_psql "SELECT DISTINCT wrapping_key_id FROM \"${schema}\".data_keys;")"$'\n'
    done
    if ((expected > 0)); then
        count=$(printf '%s' "$wrapping_key_ids" | sort -u | wc -l)
        ((count == NUM_PEERS)) \
            || fail "${phase}: expected ${NUM_PEERS} different master keys, the data keys name ${count}"
    fi
    log "${phase}: every party has ${expected} data key(s)"
}

# Writes one line per live share of `schema` to `file`: id, epoch, public key and a digest of
# the stored share bytes. The keys with a protocol in progress are left out: their shares
# change for another reason than the upgrade.
snapshot_shares() {
    local schema=$1
    local file=$2
    docker_psql "SELECT encode(id, 'hex') || ' ' || epoch || ' ' || encode(public_key, 'hex') || ' ' || encode(sha256(share), 'hex')
                 FROM \"${schema}\".shares
                 WHERE share IS NOT NULL
                   AND encode(id, 'hex') NOT IN ('$(key_id_hex "$KEY_RESHARE_IN_PROGRESS")', '$(key_id_hex "$KEY_GENERATION_IN_PROGRESS")')
                 ORDER BY id;" >"$file"
}

snapshot_all_shares() {
    local dir=$1
    local schema
    mkdir -p "$dir"
    for schema in "${schemas[@]}"; do
        snapshot_shares "$schema" "$dir/${schema}.txt"
    done
}

# The upgrade rewrote the stored bytes of every share, and nothing else: ids, epochs and public
# keys are the same as before.
assert_upgrade_rewrote_shares() {
    local before=$1
    local after=$2
    local schema unchanged

    for schema in "${schemas[@]}"; do
        [[ -s "$before/${schema}.txt" ]] || fail "no shares of schema ${schema} were recorded before the upgrade"
        diff <(cut -d' ' -f1-3 "$before/${schema}.txt") <(cut -d' ' -f1-3 "$after/${schema}.txt") >/dev/null \
            || fail "the upgrade changed ids, epochs or public keys in schema ${schema}"
        unchanged=$(comm -12 <(cut -d' ' -f1,4 "$before/${schema}.txt" | sort) <(cut -d' ' -f1,4 "$after/${schema}.txt" | sort) | wc -l)
        ((unchanged == 0)) \
            || fail "${unchanged} shares of schema ${schema} have the same stored bytes after the upgrade"
    done
    log "the upgrade rewrote every stored share and kept ids, epochs and public keys"
}

wait_for_no_direct_rows() {
    local deadline=$((SECONDS + WAIT_TIMEOUT_SECS))
    local schema direct

    while true; do
        direct=0
        for schema in "${schemas[@]}"; do
            direct=$((direct + $(docker_psql "SELECT (SELECT COUNT(*) FROM \"${schema}\".shares WHERE storage_format = 'direct') + (SELECT COUNT(*) FROM \"${schema}\".in_progress_keygens WHERE storage_format = 'direct');")))
        done
        ((direct == 0)) && return 0
        if ((SECONDS >= deadline)); then
            fail "${direct} rows are still stored as direct ${WAIT_TIMEOUT_SECS}s after the key-gens restarted"
        fi
        sleep 1
    done
}

# Waits until party `party` has `expected` rows in `in_progress_keygens`, all stored as `format`.
wait_for_in_progress_rows() {
    local party=$1
    local expected=$2
    local format=$3
    local schema="${schemas[$party]}"
    local deadline=$((SECONDS + WAIT_TIMEOUT_SECS))
    local counts

    while true; do
        counts=$(docker_psql "SELECT COUNT(*) || ' ' || COUNT(*) FILTER (WHERE storage_format = '${format}') FROM \"${schema}\".in_progress_keygens;")
        [[ "$counts" == "${expected} ${expected}" ]] && return 0
        if ((SECONDS >= deadline)); then
            fail "schema ${schema} has '${counts}' (all, ${format}) rows in in_progress_keygens after ${WAIT_TIMEOUT_SECS}s, expected ${expected} ${format} rows"
        fi
        sleep 1
    done
}

# -------------------------
# Service lifecycle
# -------------------------
stop_keygen() {
    terminate_pid_gracefully "key-gen$1" "${keygen_pids[$1]}"
    unset "keygen_pids[$1]"
}

restart_keygens() {
    shutdown_keygens
    start_keygens
    wait_for_health 20000 "$NUM_PEERS" "key-gen" 300
}

restart_nodes() {
    shutdown_oprf_service_nodes
    start_oprf_service_nodes
    wait_for_health 10000 "$NUM_PEERS" "oprf-service" 300
}

# Waits for the service with `pid` to exit by itself with a failure.
expect_refuses_to_start() {
    local label=$1
    local pid=$2
    local deadline=$((SECONDS + REFUSE_TIMEOUT_SECS))
    local status=0

    while kill -0 "$pid" 2>/dev/null; do
        if ((SECONDS >= deadline)); then
            kill "$pid" 2>/dev/null || true
            fail "${label} is still running after ${REFUSE_TIMEOUT_SECS}s, expected it to refuse to start"
        fi
        sleep 1
    done
    wait "$pid" || status=$?
    ((status != 0)) || fail "${label} exited successfully, expected it to refuse to start"
    log "${label} refused to start (exit status ${status})"
}

# Starts `start_fn party` with the master key of another party and expects it to fail because
# the stored data key is wrapped under another master key. The service must have logged
# `expected_message`.
expect_wrong_master_key_refused() {
    local label=$1
    local start_fn=$2
    local pids_var=$3
    local expected_message=$4
    local party=1
    local log_file="${label}-wrong-master-key.log"
    local own_key="${storage_master_keys[$party]}"
    local pid

    log "starting ${label} of party ${party} with the master key of party 0"
    storage_master_keys[$party]="${storage_master_keys[0]}"
    "$start_fn" "$party" "$log_file"
    storage_master_keys[$party]="$own_key"
    eval "pid=\${${pids_var}[$party]}"
    expect_refuses_to_start "${label} with a wrong master key" "$pid"
    if ! grep -q "$expected_message" "$LOG_DIR/$log_file"; then
        fail "${label} did not report '${expected_message}' (see ${LOG_DIR}/${log_file})"
    fi
}

# -------------------------
# Phases
# -------------------------
phase_direct() {
    local phase="phase 1 (direct)"
    log "${phase}: generating, resharing and deleting keys"

    generate_key "$KEY_NEVER_RESHARED"
    generate_key "$KEY_RESHARED_ONCE"
    generate_key "$KEY_RESHARED_TWICE"
    generate_key "$KEY_UNTOUCHED"
    generate_key "$KEY_UNDER_LOAD"
    generate_key "$KEY_DELETED"
    generate_key "$KEY_RESHARE_IN_PROGRESS"

    reshare_key "$KEY_RESHARED_ONCE"
    reshare_key "$KEY_RESHARED_TWICE"
    reshare_key "$KEY_RESHARED_TWICE"
    delete_key "$KEY_DELETED"

    assert_all_keys_work "$phase"
    assert_rows_stored_as direct "$phase"
    assert_data_keys 0 "$phase"
}

phase_nodes_allow_envelope() {
    local phase="phase 2 (nodes allow envelopeV1)"
    log "${phase}: restarting the nodes with allowed = [direct, envelopeV1]"

    NODE_ALLOWED_STORAGE_FORMATS="direct,envelopeV1"
    restart_nodes

    # Nothing changed in the database; the nodes still read `direct` rows.
    assert_rows_stored_as direct "$phase"
    assert_data_keys 0 "$phase"
    assert_all_keys_work "$phase"
}

phase_upgrade() {
    local phase="phase 3 (key-gens write envelopeV1)"
    local snapshots="$LOG_DIR/snapshots"
    # The last party is down while a key generation and a reshare start, so both wait for it
    # after their first round.
    local late=$((NUM_PEERS - 1))
    local i

    log "${phase}: starting a key generation and a reshare that key-gen${late} does not take part in yet"
    stop_keygen "$late"
    send_init_keygen "$KEY_GENERATION_IN_PROGRESS"
    send_init_reshare "$KEY_RESHARE_IN_PROGRESS"
    for ((i = 0; i < late; i++)); do
        wait_for_in_progress_rows "$i" 2 direct
    done

    log "${phase}: restarting the key-gens with allowed = [direct, envelopeV1], write = envelopeV1"
    snapshot_all_shares "$snapshots/before"
    KEYGEN_ALLOWED_STORAGE_FORMATS="direct,envelopeV1"
    KEYGEN_STORAGE_WRITE_FORMAT="envelopeV1"
    shutdown_keygens
    for ((i = 0; i < late; i++)); do
        start_keygen_node "$i"
    done
    wait_for_health 20000 "$late" "key-gen" 300
    # The upgrade converted the state of the protocols in progress.
    for ((i = 0; i < late; i++)); do
        wait_for_in_progress_rows "$i" 2 envelopeV1
    done
    start_keygen_node "$late"
    wait_for_health "$((20000 + late))" 1 "key-gen" 300
    wait_for_no_direct_rows
    snapshot_all_shares "$snapshots/after"

    log "${phase}: waiting for the key generation and the reshare in progress to finish"
    wait_for_key_at_epoch "$KEY_GENERATION_IN_PROGRESS" 0
    live_keys+=("$KEY_GENERATION_IN_PROGRESS")
    wait_for_key_at_epoch "$KEY_RESHARE_IN_PROGRESS" "$((key_epoch[$KEY_RESHARE_IN_PROGRESS] + 1))"

    assert_upgrade_rewrote_shares "$snapshots/before" "$snapshots/after"
    assert_rows_stored_as envelopeV1 "${phase}, after the upgrade"
    assert_data_keys 1 "${phase}, after the upgrade"
    # The nodes kept running: they started without any data key and load the new one on demand.
    assert_all_keys_work "${phase}, after the upgrade"

    log "${phase}: resharing keys from before the upgrade"
    reshare_key "$KEY_NEVER_RESHARED"
    reshare_key "$KEY_RESHARED_ONCE"

    log "${phase}: generating and resharing new keys"
    generate_key "$KEY_MIXED"
    generate_key "$KEY_MIXED_RESHARED"
    reshare_key "$KEY_MIXED_RESHARED"

    log "${phase}: resharing key ${KEY_UNDER_LOAD} twice under OPRF load"
    dev_client "$KEY_UNDER_LOAD" "$(all_nodes_csv)" reshare-test --acceptance-num 20 \
        || fail "${phase}: reshare test for key ${KEY_UNDER_LOAD} failed (see ${LOG_DIR}/dev-client.log)"
    key_epoch[$KEY_UNDER_LOAD]=$((key_epoch[$KEY_UNDER_LOAD] + 2))

    log "${phase}: OPRF stress test on key ${KEY_RESHARED_TWICE}"
    dev_client "$KEY_RESHARED_TWICE" "$(all_nodes_csv)" stress-test-oprf --runs 50 \
        || fail "${phase}: stress test for key ${KEY_RESHARED_TWICE} failed (see ${LOG_DIR}/dev-client.log)"

    assert_all_keys_work "$phase"
    assert_rows_stored_as envelopeV1 "$phase"
    assert_data_keys 1 "$phase"
}

phase_lock_down() {
    local phase="phase 4 (envelopeV1 only)"
    log "${phase}: restarting everything with allowed = [envelopeV1]"

    KEYGEN_ALLOWED_STORAGE_FORMATS="envelopeV1"
    NODE_ALLOWED_STORAGE_FORMATS="envelopeV1"
    shutdown_oprf_service_nodes
    shutdown_keygens

    # A party whose services are configured with another master key must not come up, and
    # key-gen must not create a second data key under that master key.
    expect_wrong_master_key_refused "node" start_oprf_service_node nodes_pids "is wrapped with key"
    expect_wrong_master_key_refused "key-gen" start_keygen_node keygen_pids "is wrapped with key"
    assert_data_keys 1 "${phase}, after refusing a wrong master key"

    start_keygens
    wait_for_health 20000 "$NUM_PEERS" "key-gen" 300
    start_oprf_service_nodes
    wait_for_health 10000 "$NUM_PEERS" "oprf-service" 300

    assert_rows_stored_as envelopeV1 "${phase}, after the restart"
    assert_data_keys 1 "${phase}, after the restart"
    assert_all_keys_work "${phase}, after the restart"

    log "${phase}: resharing keys from before and after the upgrade"
    reshare_key "$KEY_UNTOUCHED"
    reshare_key "$KEY_RESHARED_TWICE"
    reshare_key "$KEY_UNDER_LOAD"
    reshare_key "$KEY_MIXED"

    log "${phase}: generating, resharing and deleting keys"
    generate_key "$KEY_LOCKED"
    generate_key "$KEY_LOCKED_RESHARED"
    reshare_key "$KEY_LOCKED_RESHARED"
    reshare_key "$KEY_LOCKED_RESHARED"
    delete_key "$KEY_RESHARED_ONCE"

    assert_all_keys_work "$phase"
    assert_rows_stored_as envelopeV1 "$phase"
    assert_data_keys 1 "$phase"
}

# -------------------------
# Setup and teardown
# -------------------------
teardown() {
    local exit_code=$?
    local file
    set +e
    trap - EXIT
    if ((exit_code != 0)); then
        for file in "$LOG_DIR"/key-gen*.log "$LOG_DIR"/node*.log "$LOG_DIR"/dev-client.log; do
            [[ -f "$file" ]] || continue
            printf '%s tail %s\n' "$LOG_TAG" "$file" >&2
            tail -n 40 "$file" >&2
        done
    fi
    kill_pid_array "${keygen_pids[@]-}"
    kill_pid_array "${nodes_pids[@]-}"
    compose_down
    exit "$exit_code"
}

generate_master_keys() {
    local i
    for i in $(peer_indices); do
        storage_master_keys[$i]=$(openssl rand -hex 32)
    done
}

build_binaries() {
    log "Building the node, the dev-client and key-gen"
    cargo build --release --example taceo-oprf-service-example --example dev-client-example \
        >"$LOG_DIR/build-examples.log" 2>&1 || fail "building the examples failed (see ${LOG_DIR}/build-examples.log)"
    build_keygen_binary || fail "building key-gen failed (see ${LOG_DIR}/build-keygen.log)"
}

main() {
    require_setup_commands
    require_commands jq openssl
    validate_peer_config
    # Every pair of nodes must be able to answer, and the wrong master key check needs party 1.
    ((NUM_PEERS == 3 && THRESHOLD == 2)) || fail "this test needs NUM_PEERS=3 and THRESHOLD=2"
    reset_log_dir
    generate_master_keys

    trap teardown EXIT
    trap 'exit 130' SIGINT SIGTERM

    compose_up_anvil_postgres
    deploy_key_registry
    build_binaries

    # need to start key-gen before nodes because they run DB migrations
    start_keygens
    wait_for_health 20000 "$NUM_PEERS" "key-gen" 300
    start_oprf_service_nodes
    wait_for_health 10000 "$NUM_PEERS" "oprf-service" 300

    phase_direct
    phase_nodes_allow_envelope
    phase_upgrade
    phase_lock_down

    log "Storage upgrade test completed successfully"
}

main "$@"
