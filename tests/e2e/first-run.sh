#!/usr/bin/env bash
# First-run acceptance — proves the three core jobs each complete within a
# step/time budget for a NO-DOCS first-timer, so "each job in ~60s" can't silently
# regress. The tutorials ARE the tests. Gates releases (scripts/release.sh).
#
#   A1  reach a machine     host -> invite -> connect -> run a command over the shell
#   A2  private network     founder -> invite -> node joins (the PAGE'S DEFAULT node
#                           command: bare `--host`, no HOP_VPN) -> reaches founder
#                           BY NAME over the VPN. Proves VPN-on-by-default + MagicDNS.
#   A3  expose a device     (added in a later milestone: subnet route + `hop tunnel`)
#   GUARD                   the default CLIENT install (no daemon, no VPN) still does
#                           hop/exec/cp with no local daemon and no VPN.
#
# Deterministic Linux Docker (the macOS path is covered by the Tart harness).
# Usage:  ./tests/e2e/first-run.sh        (REBUILD=1 to force a cross-build)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMG=hop-firstrun-e2e
NET=hop-firstrun-net
BIN="$ROOT/target/aarch64-unknown-linux-gnu/release/hop"

# Per-job budgets (seconds). A first-timer target is ~60s/job; these are the CI
# ceilings (cold Docker, relay handshake). A regression past budget fails the gate.
A1_BUDGET="${A1_BUDGET:-40}"
A2_BUDGET="${A2_BUDGET:-60}"
GUARD_BUDGET="${GUARD_BUDGET:-40}"

PASS=0; FAIL=0; REPORT=""
say() { echo "=== $* ==="; }
record() { # name ok secs budget detail
  local name="$1" ok="$2" secs="$3" budget="$4" detail="$5" status
  if [ "$ok" = 1 ] && [ "$secs" -le "$budget" ] 2>/dev/null; then
    status="PASS"; PASS=$((PASS+1))
  else
    status="FAIL"; FAIL=$((FAIL+1))
  fi
  printf "  %-22s %s  (%ss / %ss budget)  %s\n" "$name" "$status" "$secs" "$budget" "$detail"
  REPORT="${REPORT}| ${name} | ${secs}s | ${budget}s | ${status} | ${detail} |\n"
}

CONTAINERS=()
trap cleanup EXIT
cleanup() {
  say "cleanup"
  for c in "${CONTAINERS[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -f "$SCRIPT_DIR/hop"
}

# --- build + image --------------------------------------------------------
if [ "${REBUILD:-0}" = 1 ] || [ ! -x "$BIN" ]; then
  say "cross-building aarch64 linux binary"
  AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target aarch64-unknown-linux-gnu -p hop-cli
fi
cp "$BIN" "$SCRIPT_DIR/hop"
say "building image"
docker build -t "$IMG" -f - "$SCRIPT_DIR" >/dev/null <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates jq iputils-ping iproute2 dnsutils && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash hop
COPY hop /usr/local/bin/hop
RUN chmod +x /usr/local/bin/hop
DOCKERFILE
docker network create "$NET" >/dev/null 2>&1 || true

# A node (warren host) needs the TUN + NET_ADMIN. Deliberately NO HOP_VPN env:
# A2 must prove the VPN comes up from the config DEFAULT (the bare `--host` the
# web builder emits), not a forced override.
NODE_ENV=(--cap-add=NET_ADMIN --device /dev/net/tun -e HOP_PRIVSEP=1 -e HOP_PRIVSEP_DROP=1
          -e RUST_LOG="${FR_LOG:-hop=info,hop_core=warn}" --user root)
# A pure client needs neither.
CLIENT_ENV=(-e RUST_LOG="${FR_LOG:-hop=info,hop_core=warn}" --user root)

# run_node <name> <hostname> — a warren node (TUN + NET_ADMIN, VPN from default).
run_node()   { local n="$1" h="$2"; CONTAINERS+=("$n"); docker run -d --name "$n" --hostname "$h" --network "$NET" "${NODE_ENV[@]}"   "$IMG" sleep infinity >/dev/null; docker exec "$n" mkdir -p /cfg; }
# run_client <name> <hostname> — a pure client (no TUN, no NET_ADMIN, no VPN).
run_client() { local n="$1" h="$2"; CONTAINERS+=("$n"); docker run -d --name "$n" --hostname "$h" --network "$NET" "${CLIENT_ENV[@]}" "$IMG" sleep infinity >/dev/null; docker exec "$n" mkdir -p /cfg; }
# run_session_host <name> <hostname> — a reach target WITHOUT the warren VPN
# (HOP_VPN=0): "reach a machine" is just sessions, no private network.
run_session_host() { local n="$1" h="$2"; CONTAINERS+=("$n"); docker run -d --name "$n" --hostname "$h" --network "$NET" -e HOP_VPN=0 "${CLIENT_ENV[@]}" "$IMG" sleep infinity >/dev/null; docker exec "$n" mkdir -p /cfg; }
nsec() { date +%s; }

#############################################################################
say "A1 — reach a machine (host -> invite -> connect -> run a command)"
#############################################################################
SRV_HOST=myserver
run_session_host fr-srv "$SRV_HOST"
docker exec -d fr-srv bash -lc 'hop --config /cfg host --quiet >>/cfg/log 2>&1'
for _ in $(seq 1 120); do docker exec fr-srv test -f /cfg/creator_invite && break; sleep 1; done
A1_OK=0; A1_DETAIL="no invite"
if docker exec fr-srv test -f /cfg/creator_invite; then
  # Documented first-timer invite: a client-tier token (reach this host, no warren),
  # reusable so the GUARD can redeem it too. The token is the eyJ... base64 line.
  TOKEN=$(docker exec fr-srv hop --config /cfg invite --user hop --tier client --max-uses 5 2>/dev/null | grep -oE 'eyJ[A-Za-z0-9_=-]+' | head -1)
  if [ -n "$TOKEN" ]; then
    A1_INVITE_CMD="hop invite ok"
    run_client fr-cli client-a
    t0=$(nsec)
    # `hop exec <token>` redeems the invite, runs the command, and saves the host
    # under its name — the non-interactive form of "connect and reach by name".
    if docker exec fr-cli bash -lc "hop --config /cfg exec '$TOKEN' -- echo FIRSTRUN_OK 2>/cfg/e.log" | grep -q FIRSTRUN_OK; then
      A1_OK=1
    fi
    A1_SECS=$(( $(nsec) - t0 ))
    A1_DETAIL="$A1_INVITE_CMD"
  else
    A1_DETAIL="hop invite produced no token"; A1_SECS=$A1_BUDGET
  fi
else
  A1_SECS=$A1_BUDGET
fi
record "A1 reach-a-machine" "$A1_OK" "${A1_SECS:-$A1_BUDGET}" "$A1_BUDGET" "$A1_DETAIL"

#############################################################################
say "A2 — private network (node joins with bare --host -> reach founder BY NAME over VPN)"
#############################################################################
run_node fr-founder founder
docker exec -d fr-founder bash -lc 'hop --config /cfg host --quiet >>/cfg/log 2>&1'
# Founder brings up the VPN from the DEFAULT (no HOP_VPN). Wait for it.
F_VIP=""; for _ in $(seq 1 90); do
  F_VIP=$(docker exec fr-founder sh -c "grep -aoE 'vpn: enabled, virtual IP [0-9.]+' /cfg/log | grep -oE '[0-9.]+$' | head -1" 2>/dev/null)
  [ -n "$F_VIP" ] && break; sleep 1
done
F_NAME=$(docker exec fr-founder hostname | tr 'A-Z' 'a-z' | cut -d. -f1)
INVITE=$(docker exec fr-founder cat /cfg/creator_invite 2>/dev/null)
A2_OK=0; A2_DETAIL="founder vpn never came up (default)"
if [ -n "$F_VIP" ] && [ -n "$INVITE" ]; then
  A2_DETAIL="founder=${F_NAME}/${F_VIP}"
  run_node fr-member member
  t0=$(nsec)
  # The page's default node command: join the warren, then `hop host` (VPN on by
  # default — NO HOP_VPN, NO --no-vpn).
  docker exec fr-member sh -c "hop --config /cfg connect '$INVITE' --warren >/cfg/join.log 2>&1" || true
  docker exec -d fr-member bash -lc 'hop --config /cfg host --quiet >>/cfg/log 2>&1'
  M_VIP=""; for _ in $(seq 1 90); do
    M_VIP=$(docker exec fr-member sh -c "grep -aoE 'vpn: enabled, virtual IP [0-9.]+' /cfg/log | grep -oE '[0-9.]+$' | head -1" 2>/dev/null)
    [ -n "$M_VIP" ] && break; sleep 1
  done
  if [ -n "$M_VIP" ]; then
    # Reach the founder BY NAME: resolve <founder>.hop via the member's own MagicDNS
    # (served on its vIP), then reach that address over the tunnel.
    for _ in $(seq 1 90); do
      R=$(docker exec fr-member dig +short +time=2 +tries=1 "@${M_VIP}" "${F_NAME}.hop" 2>/dev/null | head -1)
      if [ "$R" = "$F_VIP" ] && docker exec fr-member ping -c1 -W2 "$F_VIP" >/dev/null 2>&1; then
        A2_OK=1; A2_DETAIL="${F_NAME}.hop -> ${F_VIP} reached"; break
      fi
      sleep 1
    done
    [ "$A2_OK" = 0 ] && A2_DETAIL="member=${M_VIP} but ${F_NAME}.hop never resolved+reached"
  else
    A2_DETAIL="member VPN never came up (default)"
  fi
  A2_SECS=$(( $(nsec) - t0 ))
else
  A2_SECS=$A2_BUDGET
fi
record "A2 private-network" "$A2_OK" "${A2_SECS:-$A2_BUDGET}" "$A2_BUDGET" "$A2_DETAIL"

#############################################################################
say "GUARD — default client install (no daemon, no VPN) still reaches + transfers"
#############################################################################
# Reuse the A1 server. A pure client (no NET_ADMIN, no TUN, no daemon) must still
# hop/exec/cp — the VPN-free tier the install page offers must survive the flip.
GUARD_OK=0; GUARD_DETAIL="A1 server unavailable"
if [ "$A1_OK" = 1 ]; then
  run_client fr-guard client-guard
  t0=$(nsec)
  docker exec fr-guard sh -c "echo guard-payload > /cfg/g.txt"
  # Redeem the reusable client invite (saves the alias), then exec + cp via the
  # saved alias — exactly the default client tier with no daemon and no VPN.
  docker exec fr-guard bash -lc "hop --config /cfg exec '$TOKEN' -- true 2>/cfg/c.log" || true
  if docker exec fr-guard bash -lc "hop --config /cfg exec '$SRV_HOST' -- echo GUARD_EXEC 2>/dev/null" | grep -q GUARD_EXEC \
     && docker exec fr-guard bash -lc "hop --config /cfg cp /cfg/g.txt '$SRV_HOST':/tmp/ 2>/dev/null; hop --config /cfg exec '$SRV_HOST' -- cat /tmp/g.txt 2>/dev/null" | grep -q guard-payload; then
    # confirm this client truly has NO VPN/daemon: no TUN, no hop host process.
    if ! docker exec fr-guard sh -c "ip link show 2>/dev/null | grep -q 'hop\\|tun'" \
       && ! docker exec fr-guard pgrep -f 'hop .*host' >/dev/null 2>&1; then
      GUARD_OK=1; GUARD_DETAIL="exec+cp ok, no daemon/VPN"
    else
      GUARD_DETAIL="client unexpectedly ran a daemon/VPN"
    fi
  else
    GUARD_DETAIL="exec/cp failed on a pure client"
  fi
  GUARD_SECS=$(( $(nsec) - t0 ))
else
  GUARD_SECS=$GUARD_BUDGET
fi
record "GUARD client-no-vpn" "$GUARD_OK" "${GUARD_SECS:-$GUARD_BUDGET}" "$GUARD_BUDGET" "$GUARD_DETAIL"

# --- report ---------------------------------------------------------------
ART="${HOP_FIRSTRUN_ARTIFACT:-$SCRIPT_DIR/first-run-results.md}"
STAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
{
  echo "# First-run acceptance results"
  echo
  echo "Generated by \`tests/e2e/first-run.sh\` on ${STAMP} (Linux Docker). Each core"
  echo "job is run COLD end-to-end and must finish within its step/time budget."
  echo
  echo "| job | time | budget | result | detail |"
  echo "|---|---|---|---|---|"
  printf '%b' "$REPORT"
} > "$ART"
echo "artifact: $ART"
echo
if [ "$FAIL" -eq 0 ]; then echo "FIRST-RUN PASSED (${PASS} jobs within budget)"; exit 0
else echo "FIRST-RUN FAILED (${FAIL} job(s) over budget or broken)"; exit 1; fi
