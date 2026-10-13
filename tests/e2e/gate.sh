#!/usr/bin/env bash
# The merge gate: every e2e suite a networking / session / VPN change must pass.
#
#   run.sh                 core connection/auth/exec/transfer/fleet surface (55 tests)
#   vpn-e2e.sh             the only suite with a real TUN: routing, reboot,
#                          read-ticket members, VPN self-repair
#   session-resilience.sh  interactive-session recovery SLA, through the
#                          member daemon's mux
#   privsep-e2e.sh         privilege split, TUN handoff, operator IPC, the
#                          monitor's crash-loop fallback
#   embedded-profile.sh    hop as an unsupervised PID 1 in a constrained container:
#                          re-exec restarts, VPN self-repair, short-lived members
#
# vpn-e2e.sh's REBOOT stage failed on every build up to 0.9.40 and nothing
# noticed, because only run.sh was in the documented gate (2026-10-12). Run this
# instead of run.sh alone. REBUILD=1 rebuilds the binary once, up front.
#
# Usage: REBUILD=1 ./tests/e2e/gate.sh        (HOP_DUMP_LOGS=<dir> keeps logs)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAIL=()

run() {
    local name="$1"; shift
    echo ""
    echo "################ $name ################"
    if "$@"; then
        echo "################ $name: PASS ################"
    else
        echo "################ $name: FAIL ################"
        FAIL+=("$name")
    fi
}

# run.sh honours REBUILD; the other two reuse the binary it built.
run "run.sh" env REBUILD="${REBUILD:-0}" "$SCRIPT_DIR/run.sh"
run "vpn-e2e.sh" env HOP_DUMP_LOGS="${HOP_DUMP_LOGS:+$HOP_DUMP_LOGS/vpn}" "$SCRIPT_DIR/vpn-e2e.sh"
run "session-resilience.sh" env HOP_DUMP_LOGS="${HOP_DUMP_LOGS:+$HOP_DUMP_LOGS/session}" "$SCRIPT_DIR/session-resilience.sh"
run "privsep-e2e.sh" env REBUILD=0 HOP_DUMP_LOGS="${HOP_DUMP_LOGS:+$HOP_DUMP_LOGS/privsep}" "$SCRIPT_DIR/privsep-e2e.sh"
run "embedded-profile.sh" env HOP_DUMP_LOGS="${HOP_DUMP_LOGS:+$HOP_DUMP_LOGS/embedded}" "$SCRIPT_DIR/embedded-profile.sh"

echo ""
if [ "${#FAIL[@]}" -eq 0 ]; then
    echo "GATE: PASS (run.sh, vpn-e2e.sh, session-resilience.sh, privsep-e2e.sh, embedded-profile.sh)"
    exit 0
fi
echo "GATE: FAIL — ${FAIL[*]}"
exit 1
