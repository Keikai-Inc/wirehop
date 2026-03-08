#!/usr/bin/env bash
set -euo pipefail

source /scripts/test-functions.sh

echo "========================================="
echo "  hop E2E Test Suite"
echo "========================================="
echo ""

# Create config directory for test runner
mkdir -p "$HOP_CONFIG_DIR"
CONFIG_DIR="$HOP_CONFIG_DIR"
export CONFIG_DIR

# Wait for both hosts to be ready (max 180s)
echo "Waiting for hosts to be ready..."
ELAPSED=0
while [ ! -f /shared/ready-a ] || [ ! -f /shared/ready-b ]; do
    if [ "$ELAPSED" -ge 180 ]; then
        echo "ERROR: timed out waiting for hosts (180s)"
        [ ! -f /shared/ready-a ] && echo "  - host-a not ready"
        [ ! -f /shared/ready-b ] && echo "  - host-b not ready"
        exit 1
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done
echo "Both hosts ready after ${ELAPSED}s"
echo ""

# Read invite tokens and node IDs
INVITE_A=$(cat /shared/invite-a)
INVITE_B=$(cat /shared/invite-b)
NODE_ID_A=$(cat /shared/invite-a.nodeid)
NODE_ID_B=$(cat /shared/invite-b.nodeid)
export INVITE_A INVITE_B NODE_ID_A NODE_ID_B

echo "Host A node ID: $NODE_ID_A"
echo "Host B node ID: $NODE_ID_B"
echo ""

# ── Connection & Auth ──
echo "--- Connection & Auth ---"
run_test test_auth_via_invite_a
run_test test_auth_via_invite_b

# ── Remote Exec ──
echo ""
echo "--- Remote Exec ---"
run_test test_exec_echo
run_test test_exec_uname
run_test test_exec_exit_code
run_test test_exec_multiword
run_test test_exec_on_host_b

# ── MCP Protocol ──
echo ""
echo "--- MCP Protocol ---"
run_test test_mcp_initialize
run_test test_mcp_tools_list
run_test test_mcp_hop_exec_js

# ── Datastore via MCP ──
echo ""
echo "--- Datastore via MCP ---"
run_test test_mcp_kv_set
run_test test_mcp_kv_get
run_test test_mcp_kv_list
run_test test_mcp_kv_delete
run_test test_mcp_ts_insert
run_test test_mcp_ts_query
run_test test_mcp_ts_latest
run_test test_mcp_cron_create
run_test test_mcp_cron_list
run_test test_mcp_cron_delete

# ── File Transfer ──
echo ""
echo "--- File Transfer ---"
run_test test_cp_push
run_test test_cp_pull

# ── Results ──
echo ""
echo "========================================="
print_results
