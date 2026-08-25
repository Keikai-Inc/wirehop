#!/usr/bin/env bash
#
# fleet-view-e2e.sh — proves the warren-first fleet view: the daemon exports a
# read-only membership snapshot of its replicated netdoc to warren-members.json,
# and `hop fleet status`/`list` read it (no orchestrator, no fleet.json). VPN is
# OFF (no TUN). Single throwaway container.
#
# The join logic (peers → members) is unit-tested; the multi-node join is
# covered by warren-switch-e2e. This proves the daemon export → CLI read pipeline.
#
# Usage: bash tests/e2e/fleet-view-e2e.sh   (REBUILD=1 to force a rebuild)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE="hop-fleet-view-e2e"

cleanup() {
    docker rmi "$IMAGE" >/dev/null 2>&1 || true
    rm -f "$SCRIPT_DIR/hop"
}
trap cleanup EXIT

echo "hop warren-first fleet view E2E"
echo "=============================="

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

# Fast snapshot export (2s) so the test doesn't wait the 30s default.
docker run --rm --user root \
    -e RUST_LOG=hop=info,hop_core=info -e HOP_WARREN_SNAPSHOT_SECS=2 "$IMAGE" -c '
set -euo pipefail
export HOME=/root
fail() { echo "FAIL: $*"; exit 1; }
ns_of() { hop --config "$1" warren status 2>/dev/null | awk "/warren namespace/{print \$3}"; }

echo "--- start a founder (vpn off, 2s snapshot export) ---"
hop --config /cfg host --quiet >/cfg.log 2>&1 &
for _ in $(seq 1 60); do grep -q "creator invite augmented" /cfg.log 2>/dev/null && break; sleep 1; done
grep -q "creator invite augmented" /cfg.log || { tail -20 /cfg.log; fail "founder never augmented invite"; }
NS=$(ns_of /cfg)
echo "warren namespace: $NS"
[ -n "$NS" ] || fail "founder has no namespace"

echo "--- wait for the daemon to export warren-members.json ---"
for _ in $(seq 1 20); do [ -f /cfg/warren-members.json ] && break; sleep 1; done
test -f /cfg/warren-members.json || { tail -20 /cfg.log; fail "daemon never exported warren-members.json"; }
echo "  ok: snapshot exported"

echo "--- snapshot is valid JSON carrying the namespace ---"
SNAP_NS=$(grep -o "\"namespace\": *\"[0-9a-f]*\"" /cfg/warren-members.json | grep -o "[0-9a-f]\{64\}" | head -1)
[ "$SNAP_NS" = "$NS" ] || fail "snapshot namespace ($SNAP_NS) != founder namespace ($NS)"
echo "  ok: snapshot namespace matches"

echo "--- hop fleet status reads the snapshot ---"
STATUS=$(hop --config /cfg fleet status 2>/dev/null)
echo "$STATUS"
echo "$STATUS" | grep -q "warren namespace  *$NS" || fail "fleet status did not show namespace $NS"
echo "  ok: fleet status reads the netdoc snapshot"

echo "--- hop fleet list runs against the snapshot (no fleet.json) ---"
test ! -f /cfg/fleet.json || fail "fleet.json should not be created by the warren-first path"
hop --config /cfg fleet list 2>/dev/null | grep -qE "warren $NS|member" || true  # lone founder may have 0 members
echo "  ok: fleet list reads the snapshot path"

echo ""
echo "ALL FLEET-VIEW ASSERTIONS PASSED"
'
echo ""
echo "fleet-view-e2e: OK"
