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

# Start a local hop host so hop mcp can access the datastore (daemon.sock).
# The test runner doesn't serve connections — it only needs the datastore
# for MCP data/cron tool tests.
hop --config "$CONFIG_DIR" host --quiet &
HOP_HOST_PID=$!

# Wait for the daemon socket to appear (max 30s)
ELAPSED=0
while [ ! -S "$CONFIG_DIR/daemon.sock" ]; do
    if [ "$ELAPSED" -ge 30 ]; then
        echo "WARNING: timed out waiting for local daemon.sock (30s)"
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

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

# Populate fleet.json so hop.fleet.list() / hop.fleet.exec() work.
# hop fleet add uses resolve_host_config_dir(None) which targets the system
# config dir, but hop mcp reads from --config $CONFIG_DIR. Write directly.
cat > "$CONFIG_DIR/fleet.json" <<FLEET
{
  "members": [
    {
      "node_id": "$NODE_ID_A",
      "hostname": "host-a",
      "tags": [],
      "registered_at": "0",
      "last_heartbeat": null,
      "relay_url": null,
      "online": true
    },
    {
      "node_id": "$NODE_ID_B",
      "hostname": "host-b",
      "tags": [],
      "registered_at": "0",
      "last_heartbeat": null,
      "relay_url": null,
      "online": true
    }
  ]
}
FLEET
echo "Fleet configured with host-a and host-b"

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

# ── Cron Catalog / Dedup ──
echo ""
echo "--- Cron Catalog / Dedup ---"
run_test test_cron_ensure_creates
run_test test_cron_ensure_dedup
run_test test_cron_catalog_in_list

# ── Cron Execution ──
echo ""
echo "--- Cron Execution ---"
run_test test_cron_execution

# ── File Transfer ──
echo ""
echo "--- File Transfer ---"
run_test test_cp_push
run_test test_cp_pull
run_test test_cp_push_recursive
run_test test_cp_push_trailing_slash
run_test test_cp_pull_recursive
run_test test_cp_pull_trailing_slash

# ── JS Bindings (hop.exec / hop.fleet) ──
echo ""
echo "--- JS Bindings ---"
run_test test_js_exec_on_host
run_test test_js_fleet_list
run_test test_js_fleet_exec

# ── Monitoring Pipeline ──
echo ""
echo "--- Monitoring Pipeline ---"
run_test test_monitor_collect_and_query
run_test test_monitor_cron_with_exec

# ── Results ──
echo ""
echo "========================================="
print_results
