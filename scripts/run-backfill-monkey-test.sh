#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

LOG_TAG="[backfill-monkey]"
LOG_DIR="${LOG_DIR:-logs/backfill-monkey}"
export ANVIL_ARGS="${ANVIL_ARGS:-"--block-time 1"}"

source "$SCRIPT_DIR/lib.sh"

readonly MONKEY_KEYGEN_RUNS="${MONKEY_KEYGEN_RUNS:-10}"
readonly MONKEY_BACKFILL_RUNS="${MONKEY_BACKFILL_RUNS:-10}"
readonly MONKEY_RESHARE_RUNS="${MONKEY_RESHARE_RUNS:-2}"
readonly MONKEY_RESTART_INTERVAL_SECS=10
readonly MONKEY_WAIT_TIMEOUT_SECS=600
readonly MONKEY_DELETE_EVERY=4

readonly BASELINE_KEY_ID=1
readonly FIRST_BACKFILL_KEY_ID=2
readonly FIRST_GENERATED_KEY_ID=$((FIRST_BACKFILL_KEY_ID + MONKEY_BACKFILL_RUNS))

reshare_key_ids=()
delete_key_ids=()

# -------------------------
# DB assertions
# -------------------------
key_id_to_db_hex() {
    local key_id=$1
    local value=$key_id
    local hex=""
    local byte
    local i

    for i in $(seq 1 20); do
        byte=$((value % 256))
        value=$((value / 256))
        hex="${hex}$(printf '%02x' "$byte")"
    done

    if (( value != 0 )); then
        fail "Key ID ${key_id} is too large for shell DB encoding helper"
    fi

    printf '%s' "$hex"
}

db_count() {
    local schema=$1
    local table=$2
    local key_id=$3
    shift 3
    local key_hex
    key_hex=$(key_id_to_db_hex "$key_id")
    docker_psql "SELECT COUNT(*) FROM \"${schema}\".${table} WHERE id = decode('${key_hex}', 'hex') $*;"
}

active_share_count() {
    db_count "$1" "shares" "$2" "AND epoch = $3 AND deleted = false AND share IS NOT NULL"
}

deleted_share_count() {
    db_count "$1" "shares" "$2" "AND deleted = true AND share IS NULL"
}

in_progress_count() {
    db_count "$1" "in_progress_keygens" "$2"
}

all_schemas_have_active_share() {
    local key_id=$1
    local epoch=$2
    local schema

    for schema in "${schemas[@]}"; do
        [[ "$(active_share_count "$schema" "$key_id" "$epoch")" == "1" ]] || return 1
    done
}

all_schemas_have_deleted_share() {
    local key_id=$1
    local schema

    for schema in "${schemas[@]}"; do
        [[ "$(deleted_share_count "$schema" "$key_id")" == "1" ]] || return 1
    done
}

# -------------------------
# Rolling restart and polling
# -------------------------
restart_keygen_node() {
    local node_index=$1
    local pid

    pid="${keygen_pids[$node_index]:-}"

    log "Gracefully killing key-gen${node_index}"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        terminate_pid_gracefully "key-gen${node_index}" "$pid"
    else
        log "key-gen${node_index} was not running; starting it again"
    fi

    start_keygen_node "$node_index"
    wait_for_health $((20000 + node_index)) 1 "key-gen" 300
}

rolling_restart_keygens_once() {
    local node_index

    log "Starting one rolling key-gen kill/restart pass with ${MONKEY_RESTART_INTERVAL_SECS}s spacing"
    for node_index in $(peer_indices); do
        restart_keygen_node "$node_index"
        if (( node_index < NUM_PEERS - 1 )); then
            sleep "$MONKEY_RESTART_INTERVAL_SECS"
        fi
    done
}

poll_until() {
    local description=$1
    local timeout_secs=$2
    local check_fn=$3
    shift 3
    local start_time
    start_time=$(date +%s)
    while true; do
        if "$check_fn" "$@"; then
            log "$description"
            return 0
        fi
        if (( $(date +%s) - start_time >= timeout_secs )); then
            print_keygen_failure_debug "Timed out: $description"
            fail "$description - did not complete within ${timeout_secs}s"
        fi
        sleep 1
    done
}

key_fully_deleted()  { all_schemas_have_deleted_share "$1" && ! key_registered "$1"; }

wait_for_key_registered()   { poll_until "Key $1 is registered on-chain" "$2" key_registered "$1"; }
wait_for_key_stored()       { poll_until "All schemas stored key $1 at epoch $2" "$3" all_schemas_have_active_share "$1" "$2"; }
wait_for_key_deleted()      { poll_until "All schemas deleted key $1" "$2" key_fully_deleted "$1"; }

# -------------------------
# Backfill target selection
# -------------------------
is_delete_candidate() {
    local key_id=$1
    (( key_id != BASELINE_KEY_ID && (key_id - 1) % MONKEY_DELETE_EVERY == 0 ))
}

select_backfilled_reshare_and_delete_targets() {
    local backfill_end_key_id=$((FIRST_BACKFILL_KEY_ID + MONKEY_BACKFILL_RUNS - 1))
    local reshare_limit=$MONKEY_RESHARE_RUNS
    local key_id

    if (( reshare_limit > MONKEY_BACKFILL_RUNS )); then
        reshare_limit=$MONKEY_BACKFILL_RUNS
    fi

    reshare_key_ids=()
    delete_key_ids=()

    if (( reshare_limit > 0 )); then
        for key_id in $(seq "$FIRST_BACKFILL_KEY_ID" $((FIRST_BACKFILL_KEY_ID + reshare_limit - 1))); do
            reshare_key_ids+=("$key_id")
        done
    fi

    for key_id in $(seq "$FIRST_BACKFILL_KEY_ID" "$backfill_end_key_id"); do
        if array_contains "$key_id" "${reshare_key_ids[@]}"; then
            continue
        fi
        if is_delete_candidate "$key_id"; then
            delete_key_ids+=("$key_id")
        fi
    done

    log "Backfilled reshare key IDs: ${reshare_key_ids[*]-none}"
    log "Backfilled delete key IDs: ${delete_key_ids[*]-none}"
}

# -------------------------
# Scenario phases
# -------------------------
wait_for_generated_keygens() {
    local end_key_id=$((FIRST_GENERATED_KEY_ID + MONKEY_KEYGEN_RUNS - 1))
    local key_id

    for key_id in $(seq "$FIRST_GENERATED_KEY_ID" "$end_key_id"); do
        wait_for_key_registered "$key_id" "$MONKEY_WAIT_TIMEOUT_SECS"
        wait_for_key_stored "$key_id" 0 "$MONKEY_WAIT_TIMEOUT_SECS"
    done
}

wait_for_backfilled_target_outcomes() {
    local key_id

    for key_id in "${reshare_key_ids[@]}"; do
        wait_for_key_stored "$key_id" 1 "$MONKEY_WAIT_TIMEOUT_SECS"
    done

    for key_id in "${delete_key_ids[@]}"; do
        wait_for_key_deleted "$key_id" "$MONKEY_WAIT_TIMEOUT_SECS"
    done
}

# -------------------------
# Final verification
# -------------------------
verify_no_in_progress_rows() {
    local end_key_id=$((FIRST_GENERATED_KEY_ID + MONKEY_KEYGEN_RUNS - 1))
    local key_id
    local schema
    local count

    for key_id in $(seq "$BASELINE_KEY_ID" "$end_key_id"); do
        for schema in "${schemas[@]}"; do
            count=$(in_progress_count "$schema" "$key_id")
            [[ "$count" == "0" ]] || fail "Schema ${schema} still has ${count} in-progress rows for key ${key_id}"
        done
    done
    log "No tracked key has leftover in-progress rows"
}

verify_untouched_backfilled_keys() {
    local end_key_id=$((FIRST_BACKFILL_KEY_ID + MONKEY_BACKFILL_RUNS - 1))
    local key_id

    for key_id in $(seq "$FIRST_BACKFILL_KEY_ID" "$end_key_id"); do
        if array_contains "$key_id" "${reshare_key_ids[@]}" || array_contains "$key_id" "${delete_key_ids[@]}"; then
            continue
        fi
        wait_for_key_stored "$key_id" 0 "$MONKEY_WAIT_TIMEOUT_SECS"
    done
}

queue_backfill_keygens() {
    local end_key_id=$((FIRST_BACKFILL_KEY_ID + MONKEY_BACKFILL_RUNS - 1))
    local key_id

    log "Queuing ${MONKEY_BACKFILL_RUNS} initKeyGen transactions while nodes are down (key IDs ${FIRST_BACKFILL_KEY_ID}..${end_key_id})"
    for key_id in $(seq "$FIRST_BACKFILL_KEY_ID" "$end_key_id"); do
        send_init_keygen "$key_id"
    done
}

wait_for_backfilled_keys_registered() {
    local end_key_id=$((FIRST_BACKFILL_KEY_ID + MONKEY_BACKFILL_RUNS - 1))
    local key_id

    log "Waiting for backfilled keys ${FIRST_BACKFILL_KEY_ID}..${end_key_id} to register on-chain"
    for key_id in $(seq "$FIRST_BACKFILL_KEY_ID" "$end_key_id"); do
        wait_for_key_registered "$key_id" "$MONKEY_WAIT_TIMEOUT_SECS"
    done
}

wait_for_backfilled_reshare_sources_stored() {
    local key_id

    for key_id in "${reshare_key_ids[@]}"; do
        wait_for_key_stored "$key_id" 0 "$MONKEY_WAIT_TIMEOUT_SECS"
    done
}

submit_post_backfill_burst() {
    local end_key_id=$((FIRST_GENERATED_KEY_ID + MONKEY_KEYGEN_RUNS - 1))
    local key_id

    log "Submitting generated keygens ${FIRST_GENERATED_KEY_ID}..${end_key_id}"
    for key_id in $(seq "$FIRST_GENERATED_KEY_ID" "$end_key_id"); do
        send_init_keygen "$key_id"
    done

    for key_id in "${reshare_key_ids[@]}"; do
        send_init_reshare "$key_id"
    done

    for key_id in "${delete_key_ids[@]}"; do
        send_delete_key "$key_id"
    done
}

main() {
    require_keygen_test_commands
    validate_peer_config
    reset_log_dir

    trap keygen_test_teardown EXIT

    compose_up_anvil_postgres
    deploy_key_registry
    build_keygen_binary
    prepare_keygen_db
    start_keygens
    wait_for_health 20000 "$NUM_PEERS" "key-gen" 300

    send_init_keygen "$BASELINE_KEY_ID"
    wait_for_key_registered "$BASELINE_KEY_ID" "$MONKEY_WAIT_TIMEOUT_SECS"
    wait_for_key_stored "$BASELINE_KEY_ID" 0 "$MONKEY_WAIT_TIMEOUT_SECS"

    shutdown_keygens
    queue_backfill_keygens
    start_keygens
    wait_for_health 20000 "$NUM_PEERS" "key-gen" 300
    wait_for_backfilled_keys_registered

    select_backfilled_reshare_and_delete_targets
    wait_for_backfilled_reshare_sources_stored
    submit_post_backfill_burst
    rolling_restart_keygens_once

    wait_for_generated_keygens
    wait_for_backfilled_target_outcomes
    verify_untouched_backfilled_keys
    wait_for_key_stored "$BASELINE_KEY_ID" 0 "$MONKEY_WAIT_TIMEOUT_SECS"
    verify_no_in_progress_rows
    verify_chain_cursors

    log "Backfill monkey test succeeded"
    log "Baseline key ${BASELINE_KEY_ID} stayed at epoch 0"
    log "Backfilled key IDs: ${FIRST_BACKFILL_KEY_ID}..$((FIRST_BACKFILL_KEY_ID + MONKEY_BACKFILL_RUNS - 1))"
    log "Generated key IDs: ${FIRST_GENERATED_KEY_ID}..$((FIRST_GENERATED_KEY_ID + MONKEY_KEYGEN_RUNS - 1))"
    log "Reshared backfilled key IDs: ${reshare_key_ids[*]-none}"
    log "Deleted backfilled key IDs: ${delete_key_ids[*]-none}"
}

main "$@"
