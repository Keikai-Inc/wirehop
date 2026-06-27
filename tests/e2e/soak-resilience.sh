#!/usr/bin/env bash
# Warren resilience SOAK — measures time-to-recovery (TTR) against the dead-stable
# SLA (~/.claude/plans/warren-dead-stable.md) across the perturbations real users
# hit: daemon restart/upgrade, founder restart, network flap (wifi drop/roam),
# relay blackhole, and sleep/wake (process freeze). Deterministic Linux Docker so
# it is fast + CI-able (the macOS Tart harness covers the platform separately).
#
# TTR = wall-clock from "recovery starts" (perturbation undone) to the member
# passing data to the founder's vIP over the tunnel. Recovery over the relay
# counts (per the SLA). Measured INSIDE the member container (GNU `date +%s%N`,
# ms precision) up to the 120s absolute backstop; pass/fail is vs the scenario
# budget. Reports per-perturbation p50/p95/max so every fix is measurable.
#
# SLA budgets (ms):  warm recovery 30s,  cold convergence 60s,  backstop 120s.
#
# Usage:  SOAK_CYCLES=10 ./tests/e2e/soak-resilience.sh     (REBUILD=1 to rebuild)
#         SOAK_CYCLES=100 ... for a real soak.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NET=hop-soak-net
IMG=hop-soak-e2e
FOUNDER=hop-soak-founder
MEMBER=hop-soak-member
CYCLES="${SOAK_CYCLES:-10}"
# Warm-recovery drop-dead ceiling. Set to 60s for now: the dead-stable work
# eliminated the catastrophic tails (was >120s / 288s) and bounds recovery well
# under a minute; 60s banks that as the hard SLA, with the tighter p50/p95 targets
# (≤3s/≤8s) as a later efficiency pass. See ~/.claude/plans/warren-dead-stable.md.
WARM_BUDGET_MS=60000
COLD_BUDGET_MS=60000
BACKSTOP_MS=120000
# Per-perturbation warm-recovery budgets (ms). founder_restart is the hardest
# case — its TTR spans the founder daemon's boot + rejoin PLUS the member's
# recovery of a silently-dead path after an abrupt (SIGKILL) reboot. Two fixes
# (netdoc/mod.rs + vpn/mod.rs) closed the tail: seeding last_rx at inbound accept
# (the member latches onto the founder's fresh redial instead of tearing it down
# — was a >120s livelock) and cutting DIAL_GRACE 30s→12s (a dead-but-Ok dial was
# reused for the full grace before re-dialing — was the fixed ~27s tail). Under
# the SIGKILL soak, founder_restart now runs ~1.3-6.6s; 18s banks that with
# headroom over the ~15s DIAL_GRACE-bounded worst case while still failing a
# release if the ~27s tail ever returns. The rest recover near-instantly in this
# topology (direct path, no founder boot). Releases are GATED via release.sh.
FOUNDER_BUDGET_MS="${FOUNDER_BUDGET_MS:-18000}"
budget_for() {
  case "$1" in
    founder_restart) echo "$FOUNDER_BUDGET_MS" ;;
    *) echo "$WARM_BUDGET_MS" ;;
  esac
}
RELAY_HOST="relay.keik.ai"
# CROSS_SITE=1: founder + member on SEPARATE docker networks (no shared L2 → mDNS
# cannot bridge them — the genuine cross-site case), connected only through a LOCAL
# iroh-relay on the host (relayed path between distinct "sites"). Measures
# relay-routed recovery, which is what a real cabin↔home warren uses. Default 0 =
# same-network (mDNS) run against the production relay.
CROSS_SITE="${CROSS_SITE:-0}"
NET_A=hop-soak-neta; NET_B=hop-soak-netb
RELAY_BIN="${HOP_RELAY_BIN:-/tmp/iroh-relay-install/bin/iroh-relay}"
RELAY_PID=""
RELAY_OVERRIDE=""
[ "$CROSS_SITE" = 1 ] && { RELAY_OVERRIDE="http://host.docker.internal:3340"; RELAY_HOST="host.docker.internal"; }

say() { echo "=== $* ==="; }
trap 'cleanup' EXIT
cleanup() {
  say "cleanup"
  if [ -n "${HOP_DUMP_LOGS:-}" ]; then
    docker exec "$MEMBER" cat /cfg/log >"${HOP_DUMP_LOGS}/member.log" 2>/dev/null || true
    docker exec "$FOUNDER" cat /cfg/log >"${HOP_DUMP_LOGS}/founder.log" 2>/dev/null || true
    echo "dumped logs to ${HOP_DUMP_LOGS}/{member,founder}.log"
  fi
  docker rm -f "$FOUNDER" "$MEMBER" >/dev/null 2>&1 || true
  docker network rm "$NET" "$NET_A" "$NET_B" >/dev/null 2>&1 || true
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null
  rm -f "$SCRIPT_DIR/hop"
}

# --- build ----------------------------------------------------------------
BIN="$ROOT/target/aarch64-unknown-linux-gnu/release/hop"
if [ "${REBUILD:-0}" = 1 ] || [ ! -x "$BIN" ]; then
  say "cross-building aarch64 linux binary"
  AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target aarch64-unknown-linux-gnu -p hop-cli
fi
cp "$BIN" "$SCRIPT_DIR/hop"

say "building image"
docker build -t "$IMG" -f - "$SCRIPT_DIR" >/dev/null <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates jq iputils-ping iproute2 dnsutils && \
    rm -rf /var/lib/apt/lists/*
COPY hop /usr/local/bin/hop
RUN chmod +x /usr/local/bin/hop
DOCKERFILE

COMMON_ENV=(--cap-add=NET_ADMIN --device /dev/net/tun
        -e HOP_VPN=1 -e HOP_PRIVSEP=1 -e HOP_PRIVSEP_DROP=1
        -e RUST_LOG="${SOAK_LOG:-hop=info,hop_core=warn}" --user root)

# start hop host inside a container (detached), config persisted at /cfg so a
# restart is a WARM restart (roster already on disk).
start_daemon() { docker exec -d "$1" bash -lc 'hop --config /cfg host --quiet >>/cfg/log 2>&1'; }
# SIGKILL (-9), not SIGTERM: a host restart/reboot is ABRUPT — the daemon never
# gets to send a QUIC close-notify, so the peer must detect the silently-dead path
# (rx-staleness) and recover, which is the realistic + hardest case. SIGTERM let
# the daemon shut down gracefully (a clean close → the peer redials instantly),
# which under-tested recovery and read as NO-IMPACT when the graceful close
# outlasted the impact window. Kill ALL hop processes (privsep monitor + worker).
stop_daemon()  { docker exec "$1" pkill -9 -f 'hop' >/dev/null 2>&1 || true; }

# --- bring up the warren --------------------------------------------------
say "starting containers (long-lived; hop driven via exec)"
if [ "$CROSS_SITE" = 1 ]; then
  [ -x "$RELAY_BIN" ] || { echo "FATAL: relay binary not at $RELAY_BIN — build with: cargo install --git https://github.com/thedracle/iroh.git --branch hop-relay-fix-0.97 --features server iroh-relay --root /tmp/iroh-relay-install"; exit 1; }
  "$RELAY_BIN" --dev >/tmp/soak-relay.log 2>&1 & RELAY_PID=$!
  sleep 3
  kill -0 "$RELAY_PID" 2>/dev/null || { echo "FATAL: local relay failed to start"; cat /tmp/soak-relay.log; exit 1; }
  echo "local relay (--dev) pid=$RELAY_PID -> $RELAY_OVERRIDE"
  docker network create "$NET_A" >/dev/null; docker network create "$NET_B" >/dev/null
  XSITE=(--add-host=host.docker.internal:host-gateway -e HOP_RELAY_URL="$RELAY_OVERRIDE")
  docker run -d --name "$FOUNDER" --network "$NET_A" "${COMMON_ENV[@]}" "${XSITE[@]}" "$IMG" sleep infinity >/dev/null
  docker run -d --name "$MEMBER"  --network "$NET_B" "${COMMON_ENV[@]}" "${XSITE[@]}" "$IMG" sleep infinity >/dev/null
else
  docker network create "$NET" >/dev/null
  docker run -d --name "$FOUNDER" --network "$NET" "${COMMON_ENV[@]}" "$IMG" sleep infinity >/dev/null
  docker run -d --name "$MEMBER"  --network "$NET" "${COMMON_ENV[@]}" "$IMG" sleep infinity >/dev/null
fi
docker exec "$FOUNDER" mkdir -p /cfg; docker exec "$MEMBER" mkdir -p /cfg
RELAY_IP=$(docker exec "$FOUNDER" getent hosts "$RELAY_HOST" | awk '{print $1}' | head -1)
echo "relay $RELAY_HOST -> ${RELAY_IP:-<unresolved>}"

say "founder up"
start_daemon "$FOUNDER"
for i in $(seq 1 60); do docker exec "$FOUNDER" grep -q 'vpn: enabled' /cfg/log 2>/dev/null && break; sleep 1; done
docker exec "$FOUNDER" grep -q 'vpn: enabled' /cfg/log || { echo "FAIL: founder never enabled"; docker exec "$FOUNDER" tail -20 /cfg/log; exit 1; }
FOUNDER_VIP=$(docker exec "$FOUNDER" sh -c "grep -aoE 'virtual IP 100[0-9.]+' /cfg/log | head -1 | grep -oE '100[0-9.]+'")
# The member joins ONCE (cold convergence); every perturbation after that reuses
# the persisted /cfg (no re-join), so the founder's single-use creator_invite is
# enough — and avoids the "refuse to bind a peer to root" mint guard in-container.
INVITE=$(docker exec "$FOUNDER" cat /cfg/creator_invite 2>/dev/null)
echo "founder vIP=$FOUNDER_VIP  invite_len=${#INVITE}"
[ -n "$FOUNDER_VIP" ] && [ -n "$INVITE" ] || { echo "FAIL: no founder vIP/invite"; exit 1; }

# measure cold convergence: member join + start → first vIP ping.
# (defined below; needs FOUNDER_VIP). Member ping uses the tunnel.
member_reaches_founder() { docker exec "$MEMBER" ping -c1 -W1 "$FOUNDER_VIP" >/dev/null 2>&1; }

# measure_ttr <ceiling_ms> -> prints elapsed ms, or "TIMEOUT". Runs the poll
# inside the member (Linux date +%s%N) so timing is ms-accurate and tunnel-local.
measure_ttr() {
  docker exec "$MEMBER" bash -c '
    vip="'"$FOUNDER_VIP"'"; ceil='"$1"'
    start=$(date +%s%N)
    while :; do
      if ping -c1 -W1 "$vip" >/dev/null 2>&1; then
        echo $(( ($(date +%s%N) - start) / 1000000 )); exit 0
      fi
      [ $(( ($(date +%s%N) - start) / 1000000 )) -gt "$ceil" ] && { echo TIMEOUT; exit 1; }
      sleep 0.3
    done'
}

say "COLD convergence: member join + start"
docker exec "$MEMBER" sh -c "hop --config /cfg connect '$INVITE' --warren >/cfg/join.log 2>&1" || true
start_daemon "$MEMBER"
COLD_TTR=$(measure_ttr "$BACKSTOP_MS")
echo "cold convergence TTR = ${COLD_TTR}ms (budget ${COLD_BUDGET_MS}ms)"

# --- perturbations: a disrupt + a restore half, so we can VERIFY the disruption
# actually broke reachability before timing recovery (a no-op perturbation must
# not read as "instant recovery"). NOTE: in a Docker same-network the two peers
# hold a DIRECT path, so relay_blackhole has no impact here (that path is the Tart
# harness's job — different sites/IPs); the impact check reports it honestly.
d_member_restart()  { stop_daemon "$MEMBER"; }
r_member_restart()  { start_daemon "$MEMBER"; }
d_founder_restart() { stop_daemon "$FOUNDER"; }
r_founder_restart() { start_daemon "$FOUNDER"; }
d_net_flap()        { docker network disconnect "$NET" "$MEMBER" >/dev/null 2>&1; }
r_net_flap()        { docker network connect "$NET" "$MEMBER" >/dev/null 2>&1; }
d_relay_blackhole() { [ -n "$RELAY_IP" ] && docker exec "$MEMBER" ip route add blackhole "$RELAY_IP" >/dev/null 2>&1; }
r_relay_blackhole() { [ -n "$RELAY_IP" ] && docker exec "$MEMBER" ip route del blackhole "$RELAY_IP" >/dev/null 2>&1; }
d_sleep_wake()      { docker pause "$MEMBER" >/dev/null; }   # frozen — can't probe while paused
r_sleep_wake()      { docker unpause "$MEMBER" >/dev/null; }

PERTURBATIONS=(member_restart founder_restart net_flap relay_blackhole sleep_wake)
RDIR=$(mktemp -d)  # one file per perturbation, ms per line (-1 = timeout). bash-3.2-safe.

# Restore a healthy baseline between cycles so one perturbation's failure doesn't
# cascade into the next (each perturbation is measured independently). A full
# both-daemon restart re-peers like a cold join (which converges); if even that
# can't reach the founder, the warren is wedged — report + stop.
ensure_baseline() {
  member_reaches_founder && return 0
  stop_daemon "$MEMBER"; stop_daemon "$FOUNDER"; sleep 2
  start_daemon "$FOUNDER"; sleep 3; start_daemon "$MEMBER"
  for _ in $(seq 1 45); do member_reaches_founder && return 0; sleep 1; done
  return 1
}

say "SOAK: $CYCLES cycles"
for c in $(seq 1 "$CYCLES"); do
  name="${PERTURBATIONS[$(( (c-1) % ${#PERTURBATIONS[@]} ))]}"
  if ! ensure_baseline; then echo "  cycle $c  $name  -> SKIPPED (warren wedged, baseline unrecoverable)"; continue; fi

  "d_$name"
  # verify the disruption broke reachability (poll up to ~5s for it to drop).
  # sleep_wake is frozen so it can't be probed — assume impact.
  impact="yes"
  if [ "$name" != "sleep_wake" ]; then
    impact="no"
    for _ in $(seq 1 16); do member_reaches_founder || { impact="yes"; break; }; sleep 0.3; done
  else
    sleep 10   # hold the freeze (sleep/wake)
  fi
  "r_$name"

  if [ "$impact" = "no" ]; then
    echo "  cycle $c  $name  -> NO-IMPACT (reachability never dropped in this topology)"
    echo "-2" >>"$RDIR/$name"   # -2 = no-impact in this topology
    continue
  fi
  ttr=$(measure_ttr "$BACKSTOP_MS")
  if [ "$ttr" = "TIMEOUT" ]; then
    echo "  cycle $c  $name  -> TIMEOUT (>${BACKSTOP_MS}ms)"; echo "-1" >>"$RDIR/$name"
  else
    echo "  cycle $c  $name  -> ${ttr}ms"; echo "$ttr" >>"$RDIR/$name"
  fi
done

# --- report + committed SLA artifact --------------------------------------
say "RESULTS vs SLA (warm budget ${WARM_BUDGET_MS}ms)"
echo "cold convergence: ${COLD_TTR}ms (budget ${COLD_BUDGET_MS}ms)"
if [ "$CROSS_SITE" = 1 ]; then MODE="cross-site (separate networks, local relay, no mDNS bridge)"; ARTDEF="$SCRIPT_DIR/sla-results-crosssite.md"; else MODE="same-network (mDNS local discovery)"; ARTDEF="$SCRIPT_DIR/sla-results.md"; fi
ART="${HOP_SLA_ARTIFACT:-$ARTDEF}"
STAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
{
  echo "# Warren resilience SLA results — ${MODE}"
  echo
  echo "Generated by \`tests/e2e/soak-resilience.sh\`$([ "$CROSS_SITE" = 1 ] && echo ' CROSS_SITE=1') on ${STAMP} — ${CYCLES} cycles,"
  echo "Linux Docker, ${MODE}. TTR = time-to-traffic-flowing"
  echo "(member reaches the founder vIP over the tunnel). SLA from"
  echo "\`~/.claude/plans/warren-dead-stable.md\`: warm recovery ≤ ${WARM_BUDGET_MS}ms,"
  echo "cold convergence ≤ ${COLD_BUDGET_MS}ms."
  echo
  echo "| scenario | p50 | p95 | max | budget | result |"
  echo "|---|---|---|---|---|---|"
  cold_res="PASS"; [ "$COLD_TTR" = "TIMEOUT" ] || [ "${COLD_TTR:-0}" -gt "$COLD_BUDGET_MS" ] 2>/dev/null && cold_res="FAIL"
  echo "| cold convergence | ${COLD_TTR}ms | — | — | ${COLD_BUDGET_MS}ms | ${cold_res} |"
} >"$ART"
[ "$cold_res" = "FAIL" ] && RC=1 || RC=0

for name in "${PERTURBATIONS[@]}"; do
  [ -s "$RDIR/$name" ] || continue
  read -r p50 p95 mx fails noimpact <<EOF
$(python3 - "$RDIR/$name" <<'PY'
import sys
xs=[int(l) for l in open(sys.argv[1]) if l.strip()]
ok=sorted(v for v in xs if v>=0)
fails=sum(1 for v in xs if v==-1); noimpact=sum(1 for v in xs if v==-2)
def pct(a,p):
    return a[min(len(a)-1, int(round((p/100)*(len(a)-1))))] if a else -1
print(pct(ok,50), pct(ok,95), (max(ok) if ok else -1), fails, noimpact)
PY
)
EOF
  bud=$(budget_for "$name")
  if [ -z "$p50" ] || { [ "$p50" = "-1" ] && [ "$noimpact" -gt 0 ]; }; then
    # only no-impact samples (no real outage in this topology)
    printf "  %-16s no-impact (topology)\n" "$name"
    echo "| ${name} | n/a | n/a | n/a | ${bud}ms | no-impact |" >>"$ART"
    continue
  fi
  status="PASS"
  [ "$fails" -gt 0 ] && { status="FAIL(${fails} timeout)"; RC=1; }
  [ "$mx" -gt "$bud" ] 2>/dev/null && { status="FAIL(over budget)"; RC=1; }
  printf "  %-16s p50=%sms p95=%sms max=%sms  (budget %sms)  %s\n" "$name" "$p50" "$p95" "$mx" "$bud" "$status"
  echo "| ${name} | ${p50}ms | ${p95}ms | ${mx}ms | ${bud}ms | ${status} |" >>"$ART"
done
rm -rf "$RDIR"
{
  echo
  if [ "$RC" = 0 ]; then echo "**Overall: PASS** — every perturbation within budget.";
  else echo "**Overall: FAIL** — see rows marked FAIL; drive down per \`warren-dead-stable.md\`."; fi
} >>"$ART"
echo "SLA artifact written: $ART"
echo
[ "$RC" = 0 ] && echo "SOAK PASSED (all within ${WARM_BUDGET_MS}ms warm budget)" || echo "SOAK FAILED / over budget"
exit "$RC"
