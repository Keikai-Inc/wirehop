#!/usr/bin/env bash
#
# macOS daemon-install e2e — proves the NATIVE `hop __install-daemon` privileged
# path end to end on a real Mac (launchd), the gate that blocked wiring the
# native installer into the self-upgrade flow (install-and-invite-tiers.md §10).
#
# It mints a throwaway founder warren on a temp --config, stages that warren's
# join ticket, then runs the native installer under sudo and asserts:
#   - /usr/local/bin/hop is promoted root:wheel 0755 (the root-owned invariant)
#   - the LaunchDaemon plist is written and the service is loaded/running
#   - the staged primers landed in the system config dir
#   - the daemon actually joined the warren namespace
# Teardown is snapshot-guarded: it removes ONLY what this run created, and
# refuses to run at all if a real hop daemon is already installed/loaded.
#
# This is NOT a CI test (it installs a system service). Run it deliberately:
#   HOP_MACOS_DAEMON_E2E=1 tests/e2e/macos-daemon-install.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PLIST_PATH="/Library/LaunchDaemons/com.hop.daemon.plist"
SYS_CONFIG_DIR="/Library/Application Support/hop"
DAEMON_BIN="/usr/local/bin/hop"
SERVICE="system/com.hop.daemon"

# ---- guards -----------------------------------------------------------------
[[ "$(uname -s)" == "Darwin" ]] || { echo "SKIP: macOS only"; exit 0; }
if [[ "${HOP_MACOS_DAEMON_E2E:-}" != "1" ]]; then
  echo "REFUSING: set HOP_MACOS_DAEMON_E2E=1 to run (installs+removes a real LaunchDaemon)."
  exit 2
fi
# Never clobber an existing real hop daemon (e.g. a founder running on this box).
if sudo launchctl print "$SERVICE" >/dev/null 2>&1; then
  echo "REFUSING: com.hop.daemon is already loaded on this machine."
  echo "  This harness would disrupt it. Run on a clean Mac/VM with no hop daemon."
  exit 2
fi

# ---- snapshot what pre-exists so teardown removes ONLY what we create --------
PLIST_PREEXISTED=0;  [[ -e "$PLIST_PATH" ]]      && PLIST_PREEXISTED=1
SYSDIR_PREEXISTED=0; [[ -e "$SYS_CONFIG_DIR" ]]  && SYSDIR_PREEXISTED=1
BIN_PREEXISTED=0;    [[ -e "$DAEMON_BIN" ]]      && BIN_PREEXISTED=1
if [[ $PLIST_PREEXISTED -eq 1 || $SYSDIR_PREEXISTED -eq 1 ]]; then
  echo "REFUSING: $PLIST_PATH or $SYS_CONFIG_DIR already exists (a real install?)."
  echo "  This harness only runs on a machine with no prior hop daemon state."
  exit 2
fi

WORK="$(mktemp -d)"
FOUNDER_CFG="$WORK/founder"
STAGE="$WORK/stage"
mkdir -p "$FOUNDER_CFG" "$STAGE"
FOUNDER_PID=""

cleanup() {
  echo "--- teardown ---"
  sudo launchctl bootout "$SERVICE" 2>/dev/null || true
  [[ $PLIST_PREEXISTED  -eq 0 ]] && sudo rm -f "$PLIST_PATH" 2>/dev/null || true
  [[ $SYSDIR_PREEXISTED -eq 0 ]] && sudo rm -rf "$SYS_CONFIG_DIR" 2>/dev/null || true
  [[ $BIN_PREEXISTED    -eq 0 ]] && sudo rm -f "$DAEMON_BIN" 2>/dev/null || true
  [[ -n "$FOUNDER_PID" ]] && kill "$FOUNDER_PID" 2>/dev/null || true
  rm -rf "$WORK"
  echo "--- teardown done ---"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

# ---- obtain the test binary -------------------------------------------------
# HOP_TEST_BIN lets a clean VM run a binary you already built on the host (an
# Apple-Silicon `cargo build --release` arm64 `hop`), so the VM needs no Rust
# toolchain and no source tree — just this script + the binary.
if [[ -n "${HOP_TEST_BIN:-}" ]]; then
  HOP="$HOP_TEST_BIN"
  [[ -x "$HOP" ]] || fail "HOP_TEST_BIN='$HOP' is not an executable"
  echo "=== using prebuilt binary: $HOP ==="
else
  echo "=== building hop (release) ==="
  ( cd "$PROJECT_ROOT" && cargo build --release -p hop-cli >/dev/null )
  HOP="$PROJECT_ROOT/target/release/hop"
  [[ -x "$HOP" ]] || fail "release binary missing at $HOP"
fi

# ---- mint a throwaway founder warren + its invite ---------------------------
echo "=== starting throwaway founder ==="
"$HOP" --config "$FOUNDER_CFG" host --quiet >"$FOUNDER_CFG/log" 2>&1 &
FOUNDER_PID=$!
for _ in $(seq 1 60); do
  grep -q "creator invite augmented" "$FOUNDER_CFG/log" 2>/dev/null && break
  sleep 1
done
grep -q "creator invite augmented" "$FOUNDER_CFG/log" || { tail -30 "$FOUNDER_CFG/log"; fail "founder never augmented its invite with the warren ticket"; }
INVITE="$(cat "$FOUNDER_CFG/creator_invite")"
FOUNDER_NS="$("$HOP" --config "$FOUNDER_CFG" warren status 2>/dev/null | awk '/warren namespace/{print $3}')"
echo "founder namespace: $FOUNDER_NS"

# ---- stage the join ticket into a user-owned stage dir ----------------------
# `warren join --config <stage>` writes netdoc-join.ticket + netdoc-founder.*
echo "=== staging join ticket ==="
"$HOP" --config "$STAGE" connect "$INVITE" --warren >"$WORK/join.log" 2>&1 || true
[[ -s "$STAGE/netdoc-join.ticket" ]] || { cat "$WORK/join.log"; fail "no netdoc-join.ticket staged"; }

# ---- run the native installer under sudo ------------------------------------
echo "=== sudo hop __install-daemon (native) ==="
sudo "$HOP" __install-daemon \
  --promote-from "$HOP" \
  --stage "$STAGE" \
  --vpn on \
  --tier node \
  --default-role member

# ---- assertions -------------------------------------------------------------
echo "=== assertions ==="
# 1. promoted binary is root-owned root:wheel 0755 (the invariant)
[[ -e "$DAEMON_BIN" ]] || fail "$DAEMON_BIN not promoted"
OWN="$(stat -f '%Su:%Sg %Lp' "$DAEMON_BIN")"
[[ "$OWN" == "root:wheel 755" ]] || fail "binary perms = '$OWN', want 'root:wheel 755'"
echo "  ok: binary $DAEMON_BIN is root:wheel 0755"

# 2. plist written
[[ -e "$PLIST_PATH" ]] || fail "plist not written"
echo "  ok: plist written"

# 3. service loaded/running
sudo launchctl print "$SERVICE" >/dev/null 2>&1 || fail "service not loaded"
echo "  ok: service loaded"

# 4. primers landed in the system dir
[[ -s "$SYS_CONFIG_DIR/netdoc-join.ticket" ]] || fail "join ticket not in system dir"
grep -q '"vpn_enabled": *true' "$SYS_CONFIG_DIR/host_config.json" 2>/dev/null \
  || fail "vpn_enabled not set in system host_config.json"
echo "  ok: primers in system dir, vpn enabled"

# 5. daemon joined the warren namespace
JOINED=""
for _ in $(seq 1 60); do
  if sudo grep -qo "namespace $FOUNDER_NS" /var/log/hop-stderr.log 2>/dev/null; then JOINED=1; break; fi
  sleep 1
done
[[ -n "$JOINED" ]] || { sudo tail -40 /var/log/hop-stderr.log 2>/dev/null || true; fail "daemon never joined namespace $FOUNDER_NS"; }
echo "  ok: daemon joined warren namespace $FOUNDER_NS"

echo ""
echo "PASS: native macOS daemon install joined the warren end-to-end."
