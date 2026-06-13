#!/usr/bin/env bash
# test-functions.sh — Test helper library for hop E2E tests
#
# Provides: run_test, assert_contains, assert_equals, assert_json_field,
#           mcp_call, and all individual test_* functions.

# ── Counters ──
TEST_NUM=0
PASS_COUNT=0
FAIL_COUNT=0
FAILURES=""

# ── Test Runner ──

run_test() {
    local test_fn="$1"
    TEST_NUM=$((TEST_NUM + 1))
    local label="${test_fn#test_}"

    # Capture output and exit code
    local output
    output=$("$test_fn" 2>&1) && local rc=0 || local rc=$?

    if [ "$rc" -eq 0 ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        printf "  [%2d] %-30s ... PASS\n" "$TEST_NUM" "$label"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        printf "  [%2d] %-30s ... FAIL\n" "$TEST_NUM" "$label"
        FAILURES="${FAILURES}\n  [${TEST_NUM}] ${label}: ${output}"
    fi
}

print_results() {
    local total=$((PASS_COUNT + FAIL_COUNT))
    echo ""
    echo "  RESULTS: ${PASS_COUNT}/${total} passed, ${FAIL_COUNT} failed"

    if [ "$FAIL_COUNT" -gt 0 ]; then
        echo ""
        echo "  FAILURES:"
        printf '%b\n' "$FAILURES"
        echo ""
        exit 1
    fi

    echo ""
    exit 0
}

# ── Assertion Helpers ──

assert_contains() {
    local haystack="$1"
    local needle="$2"
    if ! echo "$haystack" | grep -qF "$needle"; then
        echo "Expected output to contain '$needle', got: $haystack"
        return 1
    fi
}

assert_equals() {
    local actual="$1"
    local expected="$2"
    if [ "$actual" != "$expected" ]; then
        echo "Expected '$expected', got '$actual'"
        return 1
    fi
}

assert_json_field() {
    local json="$1"
    local field="$2"
    local expected="$3"
    local actual
    actual=$(echo "$json" | jq -r "$field" 2>/dev/null)
    if [ "$actual" != "$expected" ]; then
        echo "JSON field $field: expected '$expected', got '$actual' (json: $json)"
        return 1
    fi
}

# ── MCP Helper ──
# Each `hop mcp` invocation is a fresh process. We must send:
#   1. initialize (has id → produces response line 1)
#   2. notifications/initialized (no id → no response)
#   3. actual request (has id → produces response line 2)
# So we grab the 2nd line of output.

mcp_call() {
    local request="$1"
    local init='{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e-test","version":"1.0"}}}'
    local notif='{"jsonrpc":"2.0","method":"notifications/initialized"}'

    printf '%s\n%s\n%s\n' "$init" "$notif" "$request" | \
        hop --config "$CONFIG_DIR" mcp 2>/dev/null | \
        grep '^{' | \
        sed -n '2p'
}

# Extract the text content from a tools/call MCP response
mcp_result_text() {
    local response="$1"
    echo "$response" | jq -r '.result.content[0].text' 2>/dev/null
}

# ── Connection & Auth Tests ──

test_auth_via_invite_a() {
    local output
    output=$(hop --config "$CONFIG_DIR" exec "$INVITE_A" -- echo auth-ok 2>&1)
    assert_contains "$output" "auth-ok"
}

test_auth_via_invite_b() {
    local output
    output=$(hop --config "$CONFIG_DIR" exec "$INVITE_B" -- echo auth-ok 2>&1)
    assert_contains "$output" "auth-ok"
}

# ── Interactive (persistent) shell ──

test_interactive_shell() {
    # `hop <host>` (no `exec`) opens the persistent PTY shell. The client enters
    # raw mode, so it needs a tty — `script` allocates one and forwards our piped
    # input. Under HOP_PRIVSEP_DROP this exercises the monitor SpawnSession path.
    # The reliable signal is the round-trip: our typed line echoes back through
    # the server's VtScreen render. (Asserting *command output* through the
    # rendered grid is escape-sequence- and timing-fragile; the round-trip proves
    # connect→shell-spawn→input→render works and didn't crash — exactly what a
    # persistent-path regression would break, including under HOP_PRIVSEP_DROP.)
    local output
    output=$( { printf 'echo MARKER-roundtrip-7f3\n'; sleep 5; } \
        | timeout 30 script -qec "hop --config $CONFIG_DIR host-a" /dev/null 2>&1 || true)
    assert_contains "$output" "MARKER-roundtrip-7f3"
}

# ── Remote Exec Tests ──

test_exec_echo() {
    local output
    output=$(hop --config "$CONFIG_DIR" exec host-a -- echo hello 2>&1)
    assert_contains "$output" "hello"
}

test_exec_uname() {
    local output
    output=$(hop --config "$CONFIG_DIR" exec host-a -- uname -s 2>&1)
    assert_contains "$output" "Linux"
}

test_exec_exit_code() {
    # hop exec joins command args with spaces, so sh -c "exit 42" loses quoting.
    # Use `false` which reliably exits with code 1.
    local rc=0
    hop --config "$CONFIG_DIR" exec host-a -- false 2>&1 || rc=$?
    assert_equals "$rc" "1"
}

test_exec_multiword() {
    # hop exec joins args with spaces, so avoid sh -c quoting.
    # "echo hello world" works because join produces "echo hello world".
    local output
    output=$(hop --config "$CONFIG_DIR" exec host-a -- echo hello world 2>&1)
    assert_contains "$output" "hello world"
}

test_exec_on_host_b() {
    local output
    output=$(hop --config "$CONFIG_DIR" exec host-b -- echo hello 2>&1)
    assert_contains "$output" "hello"
}

# ── MCP Protocol Tests ──

test_mcp_initialize() {
    local init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e-test","version":"1.0"}}}'
    local response
    response=$(printf '%s\n' "$init" | hop --config "$CONFIG_DIR" mcp 2>/dev/null | grep '^{' | head -1)

    assert_json_field "$response" '.result.protocolVersion' "2024-11-05"
    assert_json_field "$response" '.result.serverInfo.name' "hop-mcp"
}

test_mcp_tools_list() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
    local response
    response=$(mcp_call "$request")

    # Should have 4 tools when datastore is available: hop_exec, hop_skills, hop_data, hop_cron
    local tool_count
    tool_count=$(echo "$response" | jq '.result.tools | length' 2>/dev/null)
    assert_equals "$tool_count" "4"

    # Verify tool names exist
    local tool_names
    tool_names=$(echo "$response" | jq -r '.result.tools[].name' 2>/dev/null | sort | tr '\n' ',')
    assert_contains "$tool_names" "hop_exec"
    assert_contains "$tool_names" "hop_data"
    assert_contains "$tool_names" "hop_cron"
    assert_contains "$tool_names" "hop_skills"
}

test_mcp_hop_exec_js() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_exec","arguments":{"code":"return 1+1"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "2"
}

# ── Datastore KV Tests ──

test_mcp_kv_set() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_data","arguments":{"action":"kv_set","namespace":"e2e","key":"greeting","value":"hello"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" '"ok":true'
}

test_mcp_kv_get() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_data","arguments":{"action":"kv_get","namespace":"e2e","key":"greeting"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "hello"
}

test_mcp_kv_list() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_data","arguments":{"action":"kv_list","namespace":"e2e"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "greeting"
}

test_mcp_kv_delete() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_data","arguments":{"action":"kv_delete","namespace":"e2e","key":"greeting"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" '"deleted":true'
}

# ── Datastore Time-Series Tests ──

test_mcp_ts_insert() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_data","arguments":{"action":"ts_insert","metric":"cpu.temp","value":72.5,"tags":{"host":"test"}}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" '"ok":true'
}

test_mcp_ts_query() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_data","arguments":{"action":"ts_query","metric":"cpu.temp"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "72.5"
}

test_mcp_ts_latest() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_data","arguments":{"action":"ts_latest","metric":"cpu.temp"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "72.5"
    assert_contains "$text" "test"
}

# ── Cron Tests ──
# We store the job_id in a file so subsequent tests can reference it.
CRON_JOB_ID_FILE="/tmp/e2e_cron_job_id"

test_mcp_cron_create() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_cron","arguments":{"action":"create","name":"test-job","schedule":"0 0 * * * *","script":"return 1"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "job_id"

    # Save job_id for later tests
    local job_id
    job_id=$(echo "$text" | jq -r '.job_id' 2>/dev/null)
    echo "$job_id" > "$CRON_JOB_ID_FILE"
}

test_mcp_cron_list() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_cron","arguments":{"action":"list"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "test-job"
}

test_mcp_cron_delete() {
    local job_id
    job_id=$(cat "$CRON_JOB_ID_FILE" 2>/dev/null)
    if [ -z "$job_id" ]; then
        echo "No job_id found from cron_create test"
        return 1
    fi

    local request
    request=$(printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_cron","arguments":{"action":"delete","job_id":"%s"}}}' "$job_id")
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" '"deleted":true'
}

# ── Cron Execution Test ──

test_cron_execution() {
    # Create a cron job that fires every second (so it's always due within 15s poll)
    local create_req='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_cron","arguments":{"action":"create","name":"e2e-cron-exec","schedule":"* * * * * *","script":"hop.kv.set(\"cron_e2e\", \"proof\", \"executed\")"}}}'
    local response
    response=$(mcp_call "$create_req")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "job_id"

    # Wait for hop host's scheduler to pick it up (15s poll interval + execution time)
    sleep 20

    # Read KV to verify the cron job executed
    local kv_req='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_data","arguments":{"action":"kv_get","namespace":"cron_e2e","key":"proof"}}}'
    local kv_response
    kv_response=$(mcp_call "$kv_req")

    local kv_text
    kv_text=$(mcp_result_text "$kv_response")
    assert_contains "$kv_text" "executed"
}

# ── File Transfer Tests ──

test_cp_push() {
    # Write a local file
    echo "e2e-push-test-content" > /tmp/e2e-push.txt

    # Push to host-a's /tmp/ directory (not a specific filename —
    # hop cp treats non-existing dest paths as directories)
    hop --config "$CONFIG_DIR" cp /tmp/e2e-push.txt host-a:/tmp/ 2>&1

    # Verify by reading it back via exec
    local output
    output=$(hop --config "$CONFIG_DIR" exec host-a -- cat /tmp/e2e-push.txt 2>&1)
    assert_contains "$output" "e2e-push-test-content"
}

test_cp_pull() {
    # The push test already placed e2e-push.txt on host-a.
    # Remove local copy and pull it back.
    rm -f /tmp/e2e-push.txt

    # Pull from host-a to local /tmp/
    hop --config "$CONFIG_DIR" cp host-a:/tmp/e2e-push.txt /tmp/ 2>&1

    # Verify local content
    local content
    content=$(cat /tmp/e2e-push.txt)
    assert_contains "$content" "e2e-push-test-content"
}

test_cp_push_recursive() {
    # Create a local directory structure
    rm -rf /tmp/e2e-pushdir
    mkdir -p /tmp/e2e-pushdir/sub
    echo "file-a" > /tmp/e2e-pushdir/a.txt
    echo "file-b" > /tmp/e2e-pushdir/sub/b.txt

    # Clean remote destination
    hop --config "$CONFIG_DIR" exec host-a -- rm -rf /tmp/e2e-pushdir 2>&1 || true

    # Push directory (no trailing slash) — should create /tmp/e2e-pushdir/ on remote
    hop --config "$CONFIG_DIR" cp -r /tmp/e2e-pushdir host-a:/tmp/ 2>&1

    # Verify structure
    local output
    output=$(hop --config "$CONFIG_DIR" exec host-a -- cat /tmp/e2e-pushdir/a.txt 2>&1)
    assert_contains "$output" "file-a"
    output=$(hop --config "$CONFIG_DIR" exec host-a -- cat /tmp/e2e-pushdir/sub/b.txt 2>&1)
    assert_contains "$output" "file-b"
}

test_cp_push_trailing_slash() {
    # Push directory CONTENTS (trailing slash) into a new remote dir
    hop --config "$CONFIG_DIR" exec host-a -- rm -rf /tmp/e2e-contents 2>&1 || true
    hop --config "$CONFIG_DIR" exec host-a -- mkdir -p /tmp/e2e-contents 2>&1

    # Trailing slash = contents only, no nesting
    hop --config "$CONFIG_DIR" cp -r /tmp/e2e-pushdir/ host-a:/tmp/e2e-contents 2>&1

    # Verify: a.txt should be directly in /tmp/e2e-contents/, NOT in /tmp/e2e-contents/e2e-pushdir/
    local output
    output=$(hop --config "$CONFIG_DIR" exec host-a -- cat /tmp/e2e-contents/a.txt 2>&1)
    assert_contains "$output" "file-a"
    output=$(hop --config "$CONFIG_DIR" exec host-a -- cat /tmp/e2e-contents/sub/b.txt 2>&1)
    assert_contains "$output" "file-b"
}

test_cp_pull_recursive() {
    # Pull a directory from host-a into an existing local dir
    rm -rf /tmp/e2e-pulldir
    mkdir -p /tmp/e2e-pulldir

    hop --config "$CONFIG_DIR" cp -r host-a:/tmp/e2e-pushdir /tmp/e2e-pulldir 2>&1

    # Verify nesting: should be /tmp/e2e-pulldir/e2e-pushdir/a.txt
    assert_contains "$(cat /tmp/e2e-pulldir/e2e-pushdir/a.txt)" "file-a"
    assert_contains "$(cat /tmp/e2e-pulldir/e2e-pushdir/sub/b.txt)" "file-b"
}

test_cp_pull_trailing_slash() {
    # Pull directory CONTENTS (trailing slash) into local dir
    rm -rf /tmp/e2e-pullcontents
    mkdir -p /tmp/e2e-pullcontents

    hop --config "$CONFIG_DIR" cp -r host-a:/tmp/e2e-pushdir/ /tmp/e2e-pullcontents 2>&1

    # Verify: contents directly in /tmp/e2e-pullcontents/, no nesting
    assert_contains "$(cat /tmp/e2e-pullcontents/a.txt)" "file-a"
    assert_contains "$(cat /tmp/e2e-pullcontents/sub/b.txt)" "file-b"
    # Negative: no nested dir name
    [ ! -d /tmp/e2e-pullcontents/e2e-pushdir ] || { echo "FAIL: unexpected nesting (e2e-pushdir/ exists)"; return 1; }
}

# ── Sync Tests ──

test_sync_push() {
    # Create a local directory with known content
    rm -rf /tmp/e2e-syncdir
    mkdir -p /tmp/e2e-syncdir/sub
    echo "sync-a" > /tmp/e2e-syncdir/a.txt
    echo "sync-b" > /tmp/e2e-syncdir/sub/b.txt

    # Clean remote destination
    hop --config "$CONFIG_DIR" exec host-a -- rm -rf /tmp/e2e-syncdest 2>&1 || true
    hop --config "$CONFIG_DIR" exec host-a -- mkdir -p /tmp/e2e-syncdest 2>&1

    # Sync push (local → remote)
    hop --config "$CONFIG_DIR" sync /tmp/e2e-syncdir/ host-a:/tmp/e2e-syncdest 2>&1

    # Verify files arrived
    local output
    output=$(hop --config "$CONFIG_DIR" exec host-a -- cat /tmp/e2e-syncdest/a.txt 2>&1)
    assert_contains "$output" "sync-a"
    output=$(hop --config "$CONFIG_DIR" exec host-a -- cat /tmp/e2e-syncdest/sub/b.txt 2>&1)
    assert_contains "$output" "sync-b"

    # Modify locally and re-sync — should update
    echo "sync-a-updated" > /tmp/e2e-syncdir/a.txt
    hop --config "$CONFIG_DIR" sync /tmp/e2e-syncdir/ host-a:/tmp/e2e-syncdest 2>&1

    output=$(hop --config "$CONFIG_DIR" exec host-a -- cat /tmp/e2e-syncdest/a.txt 2>&1)
    assert_contains "$output" "sync-a-updated"
}

test_sync_pull() {
    # Sync pull: pull the files that sync_push placed on host-a back to local
    rm -rf /tmp/e2e-syncpull
    mkdir -p /tmp/e2e-syncpull
    hop --config "$CONFIG_DIR" sync host-a:/tmp/e2e-syncdest/ /tmp/e2e-syncpull 2>&1

    # Verify the files from sync_push arrived
    assert_contains "$(cat /tmp/e2e-syncpull/a.txt)" "sync-a-updated"
    assert_contains "$(cat /tmp/e2e-syncpull/sub/b.txt)" "sync-b"
}

test_cp_ownership() {
    # When daemon runs as root with a username-bound peer, transferred files
    # should be owned by the bound user, not root.
    # The e2e hosts run as root with creator invites that bind to user 'hop'.

    # Push a file
    echo "ownership-test" > /tmp/e2e-own.txt
    hop --config "$CONFIG_DIR" cp /tmp/e2e-own.txt host-a:/tmp/e2e-own.txt 2>&1

    # Check ownership on remote
    local owner
    owner=$(hop --config "$CONFIG_DIR" exec host-a -- stat -c '%U' /tmp/e2e-own.txt 2>&1)
    # On root daemon with username binding, files should be owned by the bound user
    # On non-root daemon, files are owned by the daemon's user
    # Either way, should NOT be root (unless daemon itself is not root, which is fine)
    if [ "$owner" = "root" ]; then
        # Check if daemon is running as root — if so, this is a bug
        local euid
        euid=$(hop --config "$CONFIG_DIR" exec host-a -- id -u 2>&1)
        if [ "$euid" = "0" ]; then
            echo "FAIL: file owned by root but daemon runs as root with user binding"
            return 1
        fi
    fi
}

# ── JS Bindings Tests (hop.exec / hop.fleet) ──

test_js_exec_on_host() {
    # Verify hop.exec() in JS runtime reaches a real host and returns stdout
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_exec","arguments":{"code":"var r = hop.exec(\"host-a\", \"echo hi-from-js\"); return r.stdout.trim();"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "hi-from-js"
}

test_js_fleet_list() {
    # Verify hop.fleet.list() returns a valid JSON array with at least one host
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_exec","arguments":{"code":"var hosts = hop.fleet.list(); return JSON.stringify(hosts);"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    # Should be a JSON array
    assert_contains "$text" "["
    # Should contain a host name
    assert_contains "$text" "name"
}

test_js_fleet_exec() {
    # Verify hop.fleet.exec() returns results from multiple hosts
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_exec","arguments":{"code":"var results = hop.fleet.exec(\"*\", \"echo fleet-ok\"); return JSON.stringify(results);"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "fleet-ok"
    assert_contains "$text" "host"
}

# ── Monitoring Pipeline Tests ──

test_monitor_collect_and_query() {
    # Verify the full pipeline: exec → ts_insert → ts_latest
    local request
    request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_exec","arguments":{"code":"var r = hop.exec(\"host-a\", \"echo 42.5\"); var val = parseFloat(r.stdout.trim()); hop.ts.insert(\"e2e.test.metric\", val, {host: \"host-a\"}); var latest = hop.ts.latest(\"e2e.test.metric\"); return String(latest.value);"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "42.5"
}

# ── Cron Catalog / Dedup Tests ──

test_cron_ensure_creates() {
    # First ensure should create the job
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_cron","arguments":{"action":"ensure","catalog_id":"e2e-catalog-test","name":"E2E Catalog Test","schedule":"0 0 * * * *","script":"return 1"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" '"status":"created"'
    assert_contains "$text" '"catalog_id":"e2e-catalog-test"'
}

test_cron_ensure_dedup() {
    # Second ensure with same catalog_id should return "exists"
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_cron","arguments":{"action":"ensure","catalog_id":"e2e-catalog-test","name":"E2E Catalog Test","schedule":"0 0 * * * *","script":"return 1"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" '"status":"exists"'
    assert_contains "$text" '"catalog_id":"e2e-catalog-test"'
}

test_cron_catalog_in_list() {
    # Verify catalog_id appears in list output
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_cron","arguments":{"action":"list"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "e2e-catalog-test"
}

test_monitor_cron_with_exec() {
    # Create a cron job that uses hop.exec + ts_insert, verify after 20s
    local create_req='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_cron","arguments":{"action":"create","name":"e2e-monitor-cron","schedule":"* * * * * *","script":"var r = hop.exec(\"host-a\", \"echo 99.1\"); hop.ts.insert(\"e2e.cron.metric\", parseFloat(r.stdout.trim()), {host: \"host-a\"});"}}}'
    local response
    response=$(mcp_call "$create_req")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "job_id"

    # Wait for scheduler to pick it up
    sleep 20

    # Read ts_latest to verify the cron job stored the metric
    local ts_req='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_data","arguments":{"action":"ts_latest","metric":"e2e.cron.metric"}}}'
    local ts_response
    ts_response=$(mcp_call "$ts_req")

    local ts_text
    ts_text=$(mcp_result_text "$ts_response")
    assert_contains "$ts_text" "99.1"
}

# ── Secrets via Remote Peer Ops (CLI) ──

test_secrets_set_get() {
    # Set a secret on host-a via remote peer op, then retrieve it
    hop --config "$CONFIG_DIR" host-a secrets set e2e-secret-key e2e-secret-value 2>&1
    local output
    output=$(hop --config "$CONFIG_DIR" host-a secrets get e2e-secret-key 2>&1)
    assert_contains "$output" "e2e-secret-value"
}

test_secrets_list() {
    local output
    output=$(hop --config "$CONFIG_DIR" host-a secrets list 2>&1)
    assert_contains "$output" "e2e-secret-key"
}

test_secrets_delete() {
    hop --config "$CONFIG_DIR" host-a secrets delete e2e-secret-key 2>&1
    local output
    output=$(hop --config "$CONFIG_DIR" host-a secrets get e2e-secret-key 2>&1)
    assert_contains "$output" "(not found)"
}

# ── Secrets from JS Tests ──

test_js_secrets_roundtrip() {
    # Set and get a secret via JS runtime (hop.secrets.set / hop.secrets.get)
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_exec","arguments":{"code":"hop.secrets.set(\"js-test-key\", \"js-test-value\"); return hop.secrets.get(\"js-test-key\");"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "js-test-value"
}

test_js_secrets_list() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_exec","arguments":{"code":"return JSON.stringify(hop.secrets.list());"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "js-test-key"
}

# ── Secrets via MCP hop_data tool ──

test_mcp_secrets_set() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_data","arguments":{"action":"secrets_set","name":"mcp-secret","value":"mcp-secret-val"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "ok"
}

test_mcp_secrets_get() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_data","arguments":{"action":"secrets_get","name":"mcp-secret"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "mcp-secret-val"
}

test_mcp_secrets_list() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_data","arguments":{"action":"secrets_list"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "mcp-secret"
}

test_mcp_secrets_delete() {
    local request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hop_data","arguments":{"action":"secrets_delete","name":"mcp-secret"}}}'
    local response
    response=$(mcp_call "$request")

    local text
    text=$(mcp_result_text "$response")
    assert_contains "$text" "deleted"
}

# ── Capabilities Tests ──

test_cap_list() {
    local output
    output=$(hop --config "$CONFIG_DIR" exec host-a -- hop cap list 2>&1)
    assert_contains "$output" "health"
    assert_contains "$output" "email-monitor"
}

test_cap_enable_disable() {
    # Enable health capability
    hop --config "$CONFIG_DIR" exec host-a -- hop cap enable health 2>&1
    local status
    status=$(hop --config "$CONFIG_DIR" exec host-a -- hop cap status 2>&1)
    assert_contains "$status" "cap:health"

    # Disable it
    hop --config "$CONFIG_DIR" exec host-a -- hop cap disable health 2>&1
    status=$(hop --config "$CONFIG_DIR" exec host-a -- hop cap status 2>&1)
    # Should not contain health anymore (or say "No capabilities")
    if echo "$status" | grep -q "cap:health"; then
        echo "FAIL: health still enabled after disable"
        return 1
    fi
}

# ── Remote Peer Ops Tests ──

test_remote_secrets_roundtrip() {
    # Set a secret on host-a from the test runner (remote peer op)
    hop --config "$CONFIG_DIR" host-a secrets set remote-test-key "remote-test-val" 2>&1
    local output
    output=$(hop --config "$CONFIG_DIR" host-a secrets get remote-test-key 2>&1)
    assert_contains "$output" "remote-test-val"
}

test_remote_secrets_list() {
    local output
    output=$(hop --config "$CONFIG_DIR" host-a secrets list 2>&1)
    assert_contains "$output" "remote-test-key"
}

test_remote_cap_status() {
    local output
    output=$(hop --config "$CONFIG_DIR" host-a cap status 2>&1)
    # Should succeed (may say "No capabilities enabled" — that's fine)
    if [ $? -ne 0 ]; then
        echo "FAIL: remote cap status failed: $output"
        return 1
    fi
}

test_remote_cron_list() {
    local output
    output=$(hop --config "$CONFIG_DIR" host-a cron list 2>&1)
    # Should succeed
    if [ $? -ne 0 ]; then
        echo "FAIL: remote cron list failed: $output"
        return 1
    fi
}
