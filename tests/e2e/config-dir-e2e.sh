#!/usr/bin/env bash
#
# config-dir-e2e.sh — proves host-side commands resolve the *daemon* config dir
# (the system dir, /etc/hop) when run WITHOUT --config, rather than the per-user
# client dir. This is the regression that made `hop warren status` report
# "not on a warren" on a machine whose daemon was actually on one.
#
# Single throwaway root container; no relay/VPN/second host needed — this is a
# pure config-path resolution test.
#
# Usage: bash tests/e2e/config-dir-e2e.sh   (set REBUILD=1 to force a rebuild)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE="hop-config-dir-e2e"

cleanup() {
    docker rmi "$IMAGE" >/dev/null 2>&1 || true
    rm -f "$SCRIPT_DIR/hop"
}
trap cleanup EXIT

echo "hop config-dir resolution E2E"
echo "============================="

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

# Run the assertions as root (the daemon scenario) inside the container.
docker run --rm --user root "$IMAGE" -c '
set -euo pipefail
export HOME=/root

echo "--- mint the daemon identity at the system dir (/etc/hop) ---"
mkdir -p /etc/hop
# Extract just the 64-char hex id (the first run also logs "Generated new identity").
HOST_ID=$(hop id --config /etc/hop 2>/dev/null | grep -oE "[0-9a-f]{64}" | tail -1)
echo "host id (/etc/hop): $HOST_ID"
test -f /etc/hop/identity.json || { echo "FAIL: /etc/hop/identity.json not created"; exit 1; }

echo "--- hop id WITHOUT --config must resolve to the daemon dir ---"
rm -rf /root/.config/hop          # ensure no stale client identity
NOCONFIG_ID=$(hop id 2>/dev/null | grep -oE "[0-9a-f]{64}" | tail -1)
echo "host id (no --config):  $NOCONFIG_ID"
if [ "$HOST_ID" != "$NOCONFIG_ID" ]; then
    echo "FAIL: no-config id ($NOCONFIG_ID) != daemon id ($HOST_ID) — resolved the wrong dir"
    exit 1
fi
# And it must NOT have minted a separate per-user identity.
if [ -f /root/.config/hop/identity.json ]; then
    echo "FAIL: hop id (no --config) created a client identity at ~/.config/hop"
    exit 1
fi
echo "PASS: hop id resolves to the daemon dir"

echo "--- hop config path WITHOUT --config must report the daemon dir ---"
PATH_NOCONFIG=$(hop config path)
echo "config path (no --config): $PATH_NOCONFIG"
if [ "$PATH_NOCONFIG" != "/etc/hop" ]; then
    echo "FAIL: hop config path resolved \"$PATH_NOCONFIG\", expected /etc/hop"
    exit 1
fi

echo "--- hop config WITHOUT --config must read the daemon config ---"
hop config set vpn on --config /etc/hop >/dev/null
# The no-config read must match the explicit one, proving the same dir is read.
CFG_EXPLICIT=$(hop config --config /etc/hop 2>/dev/null)
CFG_NOCONFIG=$(hop config 2>/dev/null)
if [ "$CFG_EXPLICIT" != "$CFG_NOCONFIG" ]; then
    echo "FAIL: hop config differs with/without --config:"
    echo "  explicit:  $CFG_EXPLICIT"
    echo "  no-config: $CFG_NOCONFIG"
    exit 1
fi
echo "PASS: hop config resolves to the daemon dir"

echo "--- warren status WITHOUT --config reads the daemon dir (no spurious mint) ---"
hop warren status >/dev/null 2>&1 || true   # must not error or create a client id
if [ -f /root/.config/hop/identity.json ]; then
    echo "FAIL: hop warren status (no --config) created a client identity"
    exit 1
fi
echo "PASS: warren status resolves to the daemon dir"

echo ""
echo "ALL CONFIG-DIR RESOLUTION ASSERTIONS PASSED"
'
echo ""
echo "config-dir-e2e: OK"
