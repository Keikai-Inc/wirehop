#!/usr/bin/env bash
#
# warren-switch-e2e.sh — proves the multi-warren REPLACE/switch flow: a node on
# warren A consumes an invite for warren B and switches to it (the new Phase 3
# conflict resolution + `hop warren leave` teardown + re-join). VPN is OFF (no
# TUN) — this exercises the namespace switch, not the data plane, so it runs in
# a single container with no special caps.
#
# Single container, three configs (founder A, founder B, node). Usage:
#   bash tests/e2e/warren-switch-e2e.sh        (REBUILD=1 to force a rebuild)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE="hop-warren-switch-e2e"

cleanup() {
    docker rmi "$IMAGE" >/dev/null 2>&1 || true
    rm -f "$SCRIPT_DIR/hop"
}
trap cleanup EXIT

echo "hop warren switch (multi-warren replace) E2E"
echo "============================================"

TARGET="target/aarch64-unknown-linux-gnu/release/hop"
if [ ! -f "$PROJECT_ROOT/$TARGET" ] || [ "${REBUILD:-0}" = "1" ]; then
    echo "Building hop for aarch64-unknown-linux-gnu..."
    cd "$PROJECT_ROOT"
    AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release \
        --target aarch64-unknown-linux-gnu -p hop-cli
else
    echo "Using existing binary: $TARGET"
fi
cp "$PROJECT_ROOT/$TARGET" "$SCRIPT_DIR/hop"

cd "$SCRIPT_DIR"
docker build -q -t "$IMAGE" . >/dev/null

# VPN off (no -e HOP_VPN); no NET_ADMIN/TUN needed.
docker run --rm --user root -e RUST_LOG=hop=info,hop_core=info "$IMAGE" -c '
set -euo pipefail
export HOME=/root
fail() { echo "FAIL: $*"; exit 1; }
ns_of() { hop --config "$1" warren status 2>/dev/null | awk "/warren namespace/{print \$3}"; }
wait_aug() { for _ in $(seq 1 60); do grep -q "creator invite augmented" "$1" 2>/dev/null && return 0; sleep 1; done; tail -20 "$1"; fail "$2 never augmented invite"; }
wait_ns() { for _ in $(seq 1 60); do grep -qE "netdoc ready \(namespace $2" "$1" 2>/dev/null && return 0; sleep 1; done; tail -20 "$1"; fail "node never opened namespace $2"; }

echo "--- start founder A and founder B (vpn off) ---"
hop --config /cfgA host --quiet >/cfgA.log 2>&1 &  A_PID=$!
hop --config /cfgB host --quiet >/cfgB.log 2>&1 &  B_PID=$!
wait_aug /cfgA.log "founder A"
wait_aug /cfgB.log "founder B"
INVITE_A=$(cat /cfgA/creator_invite); NS_A=$(ns_of /cfgA)
INVITE_B=$(cat /cfgB/creator_invite); NS_B=$(ns_of /cfgB)
echo "warren A namespace: $NS_A"
echo "warren B namespace: $NS_B"
[ -n "$NS_A" ] && [ -n "$NS_B" ] || fail "could not read founder namespaces"
[ "$NS_A" != "$NS_B" ] || fail "founders minted the same namespace"

echo "--- node joins warren A, then hosts (imports A) ---"
hop --config /node warren join "$INVITE_A" >/node-join-a.log 2>&1 || true
hop --config /node host --quiet >/node.log 2>&1 &  NODE_PID=$!
wait_ns /node.log "$NS_A"
kill "$NODE_PID" 2>/dev/null || true; sleep 2
[ "$(ns_of /node)" = "$NS_A" ] || fail "node not on warren A after join+host (got $(ns_of /node))"
echo "  ok: node is on warren A"

# --- Safe auto-switch on invite consumption (member-count gated) ---
# The decision reads the daemon-exported warren-members.json snapshot. We seed it
# directly (the daemon is stopped) to drive the two branches deterministically;
# real snapshot population is covered by hop-core unit tests.
echo "--- least-surprise: a POPULATED warren is NOT auto-switched without a flag ---"
cat >/node/warren-members.json <<JSON
{"namespace":"$NS_A","members":[{"node_id":"self","name":"self","role":"admin"},{"node_id":"peer","name":"peer","role":"node"}],"roles":[],"updated_at":1}
JSON
if hop --config /node warren join "$INVITE_B" >/node-noflag.log 2>&1; then
  cat /node-noflag.log; fail "populated warren switched without an explicit flag"
fi
grep -qiE "on-warren-conflict|won.t be switched" /node-noflag.log || { cat /node-noflag.log; fail "expected a refusal asking for --on-warren-conflict"; }
test -f /node/netdoc.json || fail "netdoc.json must remain — no switch should have happened"
[ "$(ns_of /node)" = "$NS_A" ] || fail "node must still be on warren A after refusal"
echo "  ok: populated warren kept; explicit choice required"

echo "--- solo auto-adopt: a warren with no other members is adopted with no flag ---"
cat >/node/warren-members.json <<JSON
{"namespace":"$NS_A","members":[{"node_id":"self","name":"self","role":"admin"}],"roles":[],"updated_at":1}
JSON
hop --config /node warren join "$INVITE_B" >/node-solo.log 2>&1 || true
cat /node-solo.log
grep -qi "no other members" /node-solo.log || { cat /node-solo.log; fail "expected the solo auto-adopt message"; }
ls -d /node/.warren-backup-* >/dev/null 2>&1 || fail "auto-adopt should back up the empty warren"
test ! -f /node/netdoc.json || fail "netdoc.json should be cleared after auto-adopt (re-imports B on next host)"
echo "  ok: solo warren auto-adopted warren B with no flag"

# Re-stage the node on warren A to exercise the explicit-flag switch below.
echo "--- re-stage node on warren A (for the explicit-flag switch test) ---"
rm -rf /node && hop --config /node warren join "$INVITE_A" >/node-rejoin.log 2>&1 || true
hop --config /node host --quiet >/node-r.log 2>&1 &  NODE_PID=$!
wait_ns /node-r.log "$NS_A"
kill "$NODE_PID" 2>/dev/null || true; sleep 2

echo "--- switch: consume warren B invite while on A (--on-warren-conflict replace) ---"
hop --config /node warren join "$INVITE_B" --on-warren-conflict replace --yes >/node-switch.log 2>&1 || true
cat /node-switch.log
# After replace: A is backed up, netdoc.json removed, B ticket written.
ls -d /node/.warren-backup-* >/dev/null 2>&1 || fail "no warren backup created on replace"
test -f /node/.warren-backup-*/netdoc.json || fail "old warren A netdoc.json not in backup"
test ! -f /node/netdoc.json || fail "netdoc.json should be removed after leave (re-imports on next host)"
echo "  ok: warren A backed up, state cleared"

echo "--- node hosts again (imports B) ---"
hop --config /node host --quiet >/node2.log 2>&1 &  NODE_PID=$!
wait_ns /node2.log "$NS_B"
kill "$NODE_PID" 2>/dev/null || true; sleep 2
FINAL=$(ns_of /node)
[ "$FINAL" = "$NS_B" ] || fail "node not on warren B after switch (got $FINAL)"
echo "  ok: node switched to warren B ($NS_B)"

kill "$A_PID" "$B_PID" 2>/dev/null || true
echo ""
echo "ALL WARREN-SWITCH ASSERTIONS PASSED"
'
echo ""
echo "warren-switch-e2e: OK"
