#!/usr/bin/env bash
# session-resilience.sh — interactive-session recovery SLA (session-recovery-parity).
#
# The VPN proves when the network path works; every additional second an
# interactive `hop <host>` session takes to recover past that is a session-layer
# bug. This harness runs a REAL PTY session (member -> founder) alongside the
# VPN and measures, per perturbation:
#   SRT        = restore -> a typed marker byte echoes back through the session
#   VPN TTR    = restore -> founder vIP answers ping over the tunnel
#   parity     = SRT - TTR (the number Jason feels)
#
# Perturbations:
#   net_flap     member's network detached 8s (interface change -> netmon path)
#   zombie_path  traffic to founder+relay DROPped 25s with NO interface change
#                (exercises rx-stall zombie detection, not just redial)
#   host_restart founder daemon SIGKILL + restart (PTY lost -> fresh session)
#   degraded_path member's link up but bad (netem 600ms delay, 10% loss) for 60s:
#                no blackout, so no idle timeout or zombie watchdog — the
#                2026-10-12 case. Also fails on agent churn (>1 replacement).
#   worker_restart `hop recover` on the founder: the privsep worker restarts,
#                the monitor stays. The session must come back as the SAME live
#                shell (adopted by the new worker), not a fresh one.
#   paste_restart host_restart with a 64 KB paste typed while the host is down:
#                the reconnect replays it. A replay written outside the session
#                loop could deadlock the client for good (nobody reading).
#   relay_pinned direct UDP to the founder dropped 30s (relay still reachable),
#                then allowed: the session must ride the relay, and the pooled
#                connection must be direct again within RELAY_BACK_BUDGET_MS.
#
# Budgets (SRT ms, from RESTORE; truthful FAIL rows allowed):
#   net_flap ≤ 10000 · zombie_path ≤ 12000 · host_restart ≤ 20000
# zombie_path's budget is the detection proof: without rx-stall detection the
# session waits out QUIC's 60s idle and SRT lands ~35-45s.
#
# Env: CYCLES (default 10), REBUILD=1 (cross-build first), HOP_DUMP_LOGS=<dir>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMG=hop-sessres-e2e
NET=hop-sessres-net
FOUNDER=hop-sessres-founder
MEMBER=hop-sessres-member
CYCLES="${CYCLES:-14}"
BACKSTOP_MS=90000

BUDGET_net_flap=10000
BUDGET_zombie_path=12000
BUDGET_degraded_path=10000
BUDGET_relay_pinned=10000
BUDGET_worker_restart=15000
RELAY_BACK_BUDGET_MS=120000
BUDGET_host_restart=20000
BUDGET_paste_restart=20000

say() { echo "=== $* ==="; }
trap 'cleanup' EXIT
cleanup() {
  say "cleanup"
  if [ -n "${HOP_DUMP_LOGS:-}" ]; then
    mkdir -p "$HOP_DUMP_LOGS"
    # The interactive client dials through its own agent process, not the
    # member daemon's mux, so its pool decisions are only in agent.log.
    docker exec "$MEMBER" cat /cfg/agent.log >"${HOP_DUMP_LOGS}/agent.log" 2>/dev/null || true
    docker exec "$MEMBER" cat /cfg/log >"${HOP_DUMP_LOGS}/member.log" 2>/dev/null || true
    docker exec "$MEMBER" cat /cfg/session.log >"${HOP_DUMP_LOGS}/session.log" 2>/dev/null || true
    docker exec "$MEMBER" cat /cfg/session.raw >"${HOP_DUMP_LOGS}/session.raw" 2>/dev/null || true
    docker exec "$FOUNDER" cat /cfg/log >"${HOP_DUMP_LOGS}/founder.log" 2>/dev/null || true
  fi
  # HOP_KEEP_CONTAINERS=1: leave both containers running for inspection.
  if [ "${HOP_KEEP_CONTAINERS:-0}" = 1 ]; then echo "keeping $FOUNDER $MEMBER"; return; fi
  docker rm -f "$FOUNDER" "$MEMBER" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -f "$SCRIPT_DIR/hop"
}

# --- build ----------------------------------------------------------------
BIN="$ROOT/target/aarch64-unknown-linux-gnu/release/hop"
if [ "${REBUILD:-0}" = 1 ] || [ ! -x "$BIN" ]; then
  say "cross-building aarch64 linux binary"
  (cd "$ROOT" && AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target aarch64-unknown-linux-gnu -p hop-cli)
fi
cp "$BIN" "$SCRIPT_DIR/hop"

say "building image"
docker build -t "$IMG" -f - "$SCRIPT_DIR" >/dev/null <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates jq iputils-ping iproute2 iptables dnsutils python3 && \
    rm -rf /var/lib/apt/lists/*
COPY hop /usr/local/bin/hop
RUN chmod +x /usr/local/bin/hop
DOCKERFILE

COMMON_ENV=(--cap-add=NET_ADMIN --device /dev/net/tun
        -e HOP_VPN=1 -e HOP_PRIVSEP=1 -e HOP_PRIVSEP_DROP=1
        -e RUST_LOG="${SESS_LOG:-hop=info,hop_core=warn}" --user root
        -e HOP_AGENT_PROBE_SECS="${HOP_AGENT_PROBE_SECS:-}")

start_daemon() { docker exec -d "$1" bash -lc 'hop --config /cfg host --quiet >>/cfg/log 2>&1'; }
# The whole daemon: the monitor runs as `hop --config /cfg host`, its worker as
# `hop host --config /cfg` — a pattern matching only the latter left the monitor
# up, and every "restart" then started a second daemon next to it.
stop_daemon()  { docker exec "$1" pkill -9 -f 'hop (--config [^ ]+ )?host' >/dev/null 2>&1 || true; }

say "starting containers"
docker network create "$NET" >/dev/null
docker run -d --name "$FOUNDER" --network "$NET" "${COMMON_ENV[@]}" "$IMG" sleep infinity >/dev/null
docker run -d --name "$MEMBER"  --network "$NET" "${COMMON_ENV[@]}" "$IMG" sleep infinity >/dev/null
docker exec "$FOUNDER" mkdir -p /cfg; docker exec "$MEMBER" mkdir -p /cfg

say "founder up"
start_daemon "$FOUNDER"
for _ in $(seq 1 60); do docker exec "$FOUNDER" grep -q 'vpn: enabled' /cfg/log 2>/dev/null && break; sleep 1; done
docker exec "$FOUNDER" grep -q 'vpn: enabled' /cfg/log || { echo "FAIL: founder never enabled"; docker exec "$FOUNDER" tail -20 /cfg/log; exit 1; }
FOUNDER_VIP=$(docker exec "$FOUNDER" sh -c "grep -aoE 'virtual IP 100[0-9.]+' /cfg/log | head -1 | grep -oE '100[0-9.]+'")
FOUNDER_ID=$(docker exec "$FOUNDER" hop --config /cfg id 2>/dev/null | tail -1)
FOUNDER_IP=$(docker exec "$FOUNDER" hostname -i | awk '{print $1}')
INVITE=$(docker exec "$FOUNDER" cat /cfg/creator_invite 2>/dev/null)
echo "founder vIP=$FOUNDER_VIP id=${FOUNDER_ID:0:10} ip=$FOUNDER_IP invite_len=${#INVITE}"
[ -n "$FOUNDER_VIP" ] && [ -n "$INVITE" ] && [ -n "$FOUNDER_ID" ] || { echo "FAIL: founder facts missing"; exit 1; }

say "a duplicate start exits cleanly and leaves the live daemon alone"
DUP_RC=0
docker exec "$FOUNDER" timeout 40 hop --config /cfg host --quiet >/dev/null 2>&1 || DUP_RC=$?
if [ "$DUP_RC" != 1 ] && [ "$DUP_RC" != 75 ]; then
  echo "FAIL: a second hop host on the same config exited $DUP_RC (want a clean refusal)"; exit 1
fi
if docker exec "$FOUNDER" grep -aq "crash-looped" /cfg/log; then
  echo "FAIL: the duplicate start was treated as a crash loop"; exit 1
fi
DUP_HOST=$(docker exec "$FOUNDER" hop --config /cfg --json status 2>/dev/null \
  | python3 -c 'import json,sys; print("yes" if json.load(sys.stdin).get("host") else "no")' 2>/dev/null || echo no)
[ "$DUP_HOST" = yes ] || { echo "FAIL: the live daemon stopped answering over its socket after the duplicate start"; exit 1; }
echo "  refused with status $DUP_RC; the live daemon still answers"

say "member joins + daemon up (client routes through daemon mux — real topology)"
docker exec "$MEMBER" sh -c "hop --config /cfg connect '$INVITE' --warren >/cfg/join.log 2>&1" || true
start_daemon "$MEMBER"
for _ in $(seq 1 60); do docker exec "$MEMBER" ping -c1 -W1 "$FOUNDER_VIP" >/dev/null 2>&1 && break; sleep 1; done
docker exec "$MEMBER" ping -c1 -W1 "$FOUNDER_VIP" >/dev/null 2>&1 || { echo "FAIL: member never reached founder vIP"; exit 1; }

# Relay IP (prod) — zombie_path must drop it too or iroh fails over via relay
# (which would be re-pathing WORKING, a different test).
RELAY_IP=$(docker exec "$MEMBER" getent hosts relay.keik.ai | awk '{print $1}' | head -1)
echo "relay -> ${RELAY_IP:-<unresolved>}"

# --- the PTY session driver ------------------------------------------------
# Types a '#' marker every 300ms into a real `hop <founder>` session and logs
# MRX <epoch_ms> whenever a chunk containing '#' comes back (remote PTY echo).
# '#' does not occur in any client-side reconnect banner/TUI text, so MRX is
# proof of REMOTE echo — i.e. the session is genuinely alive end-to-end.
docker exec -i "$MEMBER" sh -c 'cat > /cfg/driver.py' <<'PYEOF'
import os, pty, select, sys, time
node_id = sys.argv[1]
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm-256color"
    os.execvp("hop", ["hop", "--config", "/cfg", node_id])
log = open("/cfg/session.log", "a", buffering=1)
raw = open("/cfg/session.raw", "ab", buffering=0)
log.write(f"START {int(time.time()*1000)}\n")
last_tx = 0.0
tx_count = 0
while True:
    now = time.time() * 1000
    r, _, _ = select.select([fd], [], [], 0.05)
    if fd in r:
        try:
            data = os.read(fd, 65536)
        except OSError:
            log.write(f"EXIT {int(now)}\n"); break
        if not data:
            log.write(f"EXIT {int(now)}\n"); break
        raw.write(data)
        if b"#" in data:
            log.write(f"MRX {int(now)}\n")
    # paste_restart: a 64 KB paste typed while the host is down, replayed on
    # reconnect. Ctrl-U afterwards so the shell line doesn't grow unbounded.
    if os.path.exists("/cfg/paste-now"):
        try:
            os.remove("/cfg/paste-now")
            os.write(fd, b"x" * 65536)
            os.write(fd, b"\x15")
        except OSError:
            pass
    if now - last_tx >= 300:
        try:
            os.write(fd, b"#")
            tx_count += 1
            if tx_count % 50 == 0:
                os.write(fd, b"\x15")  # ctrl-U: keep readline's line short
        except OSError:
            pass
        last_tx = now
PYEOF

# Prints the pooled connection's on_relay (True/False/None) for host $1 from
# whichever health files exist (net-stats JSON with "health", or agent-health.json).
docker exec -i "$MEMBER" sh -c 'cat > /cfg/on_relay.py' <<'PYEOF'
import json, sys
host, on = sys.argv[1], None
for path in sys.argv[2:]:
    try:
        d = json.load(open(path))
    except Exception:
        continue
    c = d.get("health", d).get("agent_conns", {}).get(host)
    if c is not None:
        on = c.get("on_relay")
print(on)
PYEOF

start_session() {
  docker exec "$MEMBER" sh -c ": > /cfg/session.log; : > /cfg/session.raw"
  docker exec -d "$MEMBER" sh -c "python3 /cfg/driver.py '$FOUNDER_ID' >/cfg/driver.err 2>&1"
}
kill_session() { docker exec "$MEMBER" pkill -9 -f driver.py >/dev/null 2>&1 || true; docker exec "$MEMBER" pkill -9 -f "hop --config /cfg $FOUNDER_ID" >/dev/null 2>&1 || true; }

# Last MRX timestamp (ms) or empty.
last_mrx() { docker exec "$MEMBER" sh -c "grep -a '^MRX' /cfg/session.log 2>/dev/null | tail -1 | awk '{print \$2}'"; }
now_ms()   { docker exec "$MEMBER" date +%s%3N; }

session_alive() {
  local m n
  m=$(last_mrx); n=$(now_ms)
  [ -n "$m" ] && [ $((n - m)) -lt 3000 ]
}

ensure_session() {
  session_alive && return 0
  kill_session
  start_session
  for _ in $(seq 1 30); do session_alive && return 0; sleep 1; done
  return 1
}

# First MRX AFTER the given ms timestamp -> prints SRT ms or TIMEOUT.
measure_srt() {
  local restore_ms="$1" ceil="$2"
  docker exec "$MEMBER" sh -c '
    restore='"$restore_ms"'; ceil='"$ceil"'
    while :; do
      m=$(grep -a "^MRX" /cfg/session.log 2>/dev/null | awk -v r="$restore" "\$2 > r {print \$2; exit}")
      n=$(date +%s%3N)
      if [ -n "$m" ]; then echo $((m - restore)); exit 0; fi
      [ $((n - restore)) -gt "$ceil" ] && { echo TIMEOUT; exit 0; }
      sleep 0.2
    done'
}

# VPN TTR from the same restore point (background-friendly; writes to a file).
measure_vpn_ttr() {
  local restore_ms="$1" out="$2"
  docker exec "$MEMBER" sh -c '
    vip="'"$FOUNDER_VIP"'"; restore='"$restore_ms"'
    while :; do
      if ping -c1 -W1 "$vip" >/dev/null 2>&1; then
        echo $(($(date +%s%3N) - restore)); exit 0
      fi
      [ $(($(date +%s%3N) - restore)) -gt '"$BACKSTOP_MS"' ] && { echo TIMEOUT; exit 0; }
      sleep 0.3
    done' >"$out"
}

# --- perturbations ---------------------------------------------------------
d_net_flap()     { docker network disconnect "$NET" "$MEMBER" >/dev/null 2>&1; sleep 8; }
r_net_flap()     { docker network connect "$NET" "$MEMBER" >/dev/null 2>&1; }
d_zombie_path()  {
  docker exec "$MEMBER" sh -c "iptables -I OUTPUT -d $FOUNDER_IP -j DROP; iptables -I INPUT -s $FOUNDER_IP -j DROP" >/dev/null 2>&1
  [ -n "$RELAY_IP" ] && docker exec "$MEMBER" sh -c "iptables -I OUTPUT -d $RELAY_IP -j DROP; iptables -I INPUT -s $RELAY_IP -j DROP" >/dev/null 2>&1
  sleep 25
}
r_zombie_path()  {
  docker exec "$MEMBER" sh -c "iptables -D OUTPUT -d $FOUNDER_IP -j DROP; iptables -D INPUT -s $FOUNDER_IP -j DROP" >/dev/null 2>&1 || true
  [ -n "$RELAY_IP" ] && docker exec "$MEMBER" sh -c "iptables -D OUTPUT -d $RELAY_IP -j DROP; iptables -D INPUT -s $RELAY_IP -j DROP" >/dev/null 2>&1 || true
}
# degraded_path: the member's link stays up but turns bad (tc netem: 600 ms
# delay, 10 % loss) for DEGRADE_SECS. Not a blackout, so neither QUIC's idle
# timeout nor the rx-stall zombie watchdog fires — the 2026-10-12 case. Measures
# recovery once the link is good again, and counts the agent's replacement
# decisions during the window: a fresh connection over the same bad link is no
# better, so the agent must keep its connection (at most one "no better"
# decision per 2 min), never churn it.
DEGRADE_SECS="${DEGRADE_SECS:-60}"
d_degraded_path() {
  REPL_BEFORE=$(docker exec "$MEMBER" sh -c "grep -ac 'replaced degraded connection' /cfg/log /cfg/agent.log 2>/dev/null | awk -F: '{s+=\$NF} END{print s+0}'")
  docker exec "$MEMBER" tc qdisc add dev eth0 root netem delay 600ms loss 10% >/dev/null 2>&1
  sleep "$DEGRADE_SECS"
}
r_degraded_path() {
  docker exec "$MEMBER" tc qdisc del dev eth0 root >/dev/null 2>&1 || true
  local after
  after=$(docker exec "$MEMBER" sh -c "grep -ac 'replaced degraded connection' /cfg/log /cfg/agent.log 2>/dev/null | awk -F: '{s+=\$NF} END{print s+0}'")
  local churn=$((after - REPL_BEFORE))
  echo "    degraded_path: $churn replacement(s) during ${DEGRADE_SECS}s of 600ms/10% loss"
  # Same bad link either way: replacing is churn, not recovery.
  [ "$churn" -le 1 ] || echo "CHURN" >>"$RDIR/degraded_path.churn"
}

# relay_pinned: direct UDP between member and founder is dropped for 30 s (the
# relay stays reachable), so the connection moves to the relay; then direct is
# allowed again. The session must survive throughout (SRT tiny), and the
# connection must not stay on the relay afterwards.
d_relay_pinned() {
  docker exec "$MEMBER" sh -c "iptables -I OUTPUT -d $FOUNDER_IP -p udp -j DROP; iptables -I INPUT -s $FOUNDER_IP -p udp -j DROP" >/dev/null 2>&1
  sleep 30
}
r_relay_pinned() {
  docker exec "$MEMBER" sh -c "iptables -D OUTPUT -d $FOUNDER_IP -p udp -j DROP; iptables -D INPUT -s $FOUNDER_IP -p udp -j DROP" >/dev/null 2>&1 || true
}

# After relay_pinned: ms until the member daemon's pooled connection to the
# founder reports a direct path again (health.agent_conns.<id>.on_relay).
measure_back_to_direct() {
  local restore_ms="$1" out="$2" short="${FOUNDER_ID:0:10}"
  docker exec "$MEMBER" sh -c '
    restore='"$restore_ms"'; ceil='"$RELAY_BACK_BUDGET_MS"'
    while :; do
      # The pool is the daemon mux (health over its socket) or, if a user agent
      # serves the client, that agent (agent-health.json).
      hop --config /cfg --json debug net-stats >/tmp/ns.json 2>/dev/null
      r=$(python3 /cfg/on_relay.py '"$short"' /tmp/ns.json /cfg/agent-health.json 2>/dev/null)
      if [ "$r" = "False" ]; then echo $(($(date +%s%3N) - restore)); exit 0; fi
      [ $(($(date +%s%3N) - restore)) -gt "$ceil" ] && { echo TIMEOUT; exit 0; }
      sleep 2
    done' >"$out"
}

# worker_restart: only the privsep worker restarts (as on a self-restart or
# `hop recover`); the monitor keeps the shells' PTY masters and the new worker
# adopts them. Fails the run if the session did not survive as the same shell.
d_worker_restart() {
  ADOPT_BEFORE=$(docker exec "$FOUNDER" sh -c "grep -ac 'adopted [1-9][0-9]* live session' /cfg/log; true" | head -1)
  docker exec "$FOUNDER" hop --config /cfg recover --quiet >/dev/null 2>&1 || true
  sleep 2
}
r_worker_restart() {
  local after
  for _ in $(seq 1 20); do
    after=$(docker exec "$FOUNDER" sh -c "grep -ac 'adopted [1-9][0-9]* live session' /cfg/log; true" | head -1)
    [ "${after:-0}" -gt "${ADOPT_BEFORE:-0}" ] && break
    sleep 1
  done
  if [ "${after:-0}" -gt "${ADOPT_BEFORE:-0}" ]; then
    echo "    worker_restart: the new worker adopted the live session"
  else
    echo "    worker_restart: the session was NOT adopted (its shell died with the worker)"
    echo "NOTADOPTED" >>"$RDIR/worker_restart.lost"
  fi
}

d_host_restart() { stop_daemon "$FOUNDER"; sleep 3; }
d_paste_restart() { stop_daemon "$FOUNDER"; docker exec "$MEMBER" touch /cfg/paste-now; sleep 3; }
r_paste_restart() { start_daemon "$FOUNDER"; }
r_host_restart() { start_daemon "$FOUNDER"; }

# PERTS env: space-separated subset for targeted soaks (default all).
if [ -n "${PERTS:-}" ]; then read -r -a PERTS <<<"$PERTS"; else PERTS=(net_flap zombie_path host_restart degraded_path relay_pinned worker_restart paste_restart); fi
RDIR=$(mktemp -d)

say "SESSION SOAK: $CYCLES cycles"
for c in $(seq 1 "$CYCLES"); do
  if [ "${SOAK_RANDOM:-0}" = 1 ]; then
    name="${PERTS[$(( RANDOM % ${#PERTS[@]} ))]}"
  else
    name="${PERTS[$(( (c-1) % ${#PERTS[@]} ))]}"
  fi
  if ! ensure_session; then
    echo "  cycle $c  $name  -> SKIPPED (session baseline unrecoverable)"
    echo "  --- driver.err:"; docker exec "$MEMBER" cat /cfg/driver.err 2>/dev/null || true
    echo "  --- session.log tail:"; docker exec "$MEMBER" tail -5 /cfg/session.log 2>/dev/null || true
    echo "  --- join.log tail:"; docker exec "$MEMBER" tail -3 /cfg/join.log 2>/dev/null || true
    echo "  --- member daemon log tail:"; docker exec "$MEMBER" tail -5 /cfg/log 2>/dev/null || true
    continue
  fi

  "d_$name"
  restore_ms=$(now_ms)
  "r_$name"

  if [ "$name" = relay_pinned ]; then
    measure_back_to_direct "$restore_ms" "$RDIR/direct.$c" &
  fi
  vpnfile="$RDIR/vpn.$c"
  measure_vpn_ttr "$restore_ms" "$vpnfile" &
  vpid=$!
  srt=$(measure_srt "$restore_ms" "$BACKSTOP_MS")
  wait "$vpid" 2>/dev/null || true
  ttr=$(cat "$vpnfile" 2>/dev/null || echo "?")

  budget_var_now="BUDGET_$name"
  if [ "$srt" != "TIMEOUT" ] && [ "$srt" -gt "${!budget_var_now}" ]; then
    echo "  --- over-budget forensics (cycle $c, SRT ${srt}ms):"
    echo "  session.raw tail (what the client displayed):"
    docker exec "$MEMBER" sh -c "tail -c 1500 /cfg/session.raw | cat -v" 2>/dev/null | sed 's/^/    /' || true
    echo "  member daemon tail:"; docker exec "$MEMBER" sh -c "tail -8 /cfg/log" 2>/dev/null | sed 's/^/    /' || true
  fi
  if [ "$srt" = "TIMEOUT" ]; then
    echo "  cycle $c  $name  -> SRT TIMEOUT (>${BACKSTOP_MS}ms)  vpn_ttr=${ttr}ms"
    echo "  --- forensics (cycle $c):"
    echo "  session.log tail:"; docker exec "$MEMBER" tail -4 /cfg/session.log 2>/dev/null | sed 's/^/    /' || true
    echo "  client procs:"; docker exec "$MEMBER" sh -c "ps -ef | grep -E 'driver.py|hop --config /cfg [0-9a-f]' | grep -v grep" 2>/dev/null | sed 's/^/    /' || true
    echo "  session.raw tail (what the client displayed):"
    docker exec "$MEMBER" sh -c "tail -c 1500 /cfg/session.raw | cat -v" 2>/dev/null | sed 's/^/    /' || true
    echo "  member daemon tail:"; docker exec "$MEMBER" sh -c "tail -8 /cfg/log" 2>/dev/null | sed 's/^/    /' || true
    echo "  founder daemon tail:"; docker exec "$FOUNDER" sh -c "tail -6 /cfg/log" 2>/dev/null | sed 's/^/    /' || true
    echo "-1" >>"$RDIR/$name"
  else
    delta="?"
    case "$ttr" in (*[!0-9]*) ;; (*) delta=$((srt - ttr));; esac
    echo "  cycle $c  $name  -> SRT ${srt}ms  vpn_ttr=${ttr}ms  parity_delta=${delta}ms"
    echo "$srt" >>"$RDIR/$name"
    case "$delta" in (*[!0-9-]*) ;; (*) echo "$delta" >>"$RDIR/$name.delta";; esac
  fi
done

# --- report + artifact ------------------------------------------------------
percentile() { # file pct -> value (ms) of sorted numeric lines
  local f="$1" p="$2"
  sort -n "$f" | awk -v p="$p" '{a[NR]=$1} END{ if (NR==0) {print "n/a"; exit}
    i=int((p/100)*NR); if (i<1) i=1; if (i>NR) i=NR; print a[i] }'
}

ART="${SESS_ARTIFACT:-$SCRIPT_DIR/session-results.md}"
FAILED=0
{
  echo "# Interactive-session recovery SLA (session-recovery-parity)"
  echo
  echo "Generated by \`tests/e2e/session-resilience.sh\` on $(date -u +%Y-%m-%dT%H:%M:%SZ) — $CYCLES cycles,"
  echo "Linux Docker, member routes through its daemon mux. SRT = restore → typed"
  echo "marker echoes back through the session. parity = SRT − VPN TTR."
  echo
  echo "| perturbation | SRT p50 | SRT max | parity p50 | budget | result |"
  echo "|---|---|---|---|---|---|"
} >"$ART"

say "RESULTS"
for name in "${PERTS[@]}"; do
  f="$RDIR/$name"
  budget_var="BUDGET_$name"; budget="${!budget_var}"
  if [ ! -s "$f" ]; then
    echo "  $name: no samples"
    echo "| $name | n/a | n/a | n/a | ${budget}ms | NO-SAMPLES |" >>"$ART"
    FAILED=1
    continue
  fi
  if grep -q '^-1$' "$f"; then
    echo "  $name: TIMEOUT cycle present -> FAIL"
    echo "| $name | — | TIMEOUT | — | ${budget}ms | **FAIL(timeout)** |" >>"$ART"
    FAILED=1
    continue
  fi
  p50=$(percentile "$f" 50); max=$(sort -n "$f" | tail -1)
  dp50="n/a"; [ -s "$f.delta" ] && dp50=$(percentile "$f.delta" 50)
  verdict="PASS"; [ "$max" -gt "$budget" ] && { verdict="**FAIL**"; FAILED=1; }
  echo "  $name: SRT p50=${p50}ms max=${max}ms parity_p50=${dp50}ms budget=${budget}ms $verdict"
  echo "| $name | ${p50}ms | ${max}ms | ${dp50}ms | ${budget}ms | $verdict |" >>"$ART"
done
# Topology: the member's client shares /cfg with the member daemon, so every
# session must go through the daemon's mux (mux.sock). A user agent here is a
# second endpoint under the same node id — the harness then tests the wrong
# path (it did, unnoticed, until 2026-10-12).
# (`grep -c` prints 0 AND exits 1 on no match; take its first line, default ?.)
USER_AGENTS=$(docker exec "$MEMBER" sh -c "ps -eo args | grep -c '^/usr/local/bin/hop agent --daemon'; true" 2>/dev/null | head -1)
USER_AGENTS="${USER_AGENTS:-?}"
echo "  topology: $USER_AGENTS user agent(s) on the member (want 0)"
if [ "$USER_AGENTS" != 0 ]; then
  echo "| topology: user agents on member | | $USER_AGENTS | | 0 | **FAIL** |" >>"$ART"
  FAILED=1
fi

# Long soak (SOAK_HEALTH=1, set by long-soak.sh): after hours of perturbations,
# neither node may show slow rot — a steady memory climb (hop status flags
# >= 20 MB/h over >= 3 h) — and the founder must never have fallen back from
# privsep after a crash loop.
if [ "${SOAK_HEALTH:-0}" = 1 ]; then
  for node in "$FOUNDER" "$MEMBER"; do
    leak=$(docker exec "$node" hop --config /cfg --json status 2>/dev/null \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(p["detail"] for p in d.get("problems",[]) if p.get("component")=="memory"))' 2>/dev/null)
    rss=$(docker exec "$node" hop --config /cfg --json status 2>/dev/null \
      | python3 -c 'import json,sys; h=json.load(sys.stdin).get("host") or {}; print(h.get("rss_mb"), h.get("rss_slope_mb_per_hour"), h.get("rss_window_hours"))' 2>/dev/null)
    echo "  soak health $node: rss_mb / slope MB/h / window h = $rss"
    if [ -n "$leak" ]; then
      echo "  soak health $node: $leak"
      echo "| soak memory $node | | leak | | <20 MB/h | **FAIL** |" >>"$ART"
      FAILED=1
    fi
  done
  if docker exec "$FOUNDER" grep -aq "crash-looped" /cfg/log 2>/dev/null; then
    echo "  soak health: the founder's monitor fell back after a crash loop"
    echo "| soak crash-loop fallback | | yes | | never | **FAIL** |" >>"$ART"
    FAILED=1
  fi
fi

# Extra assertions for the new perturbations.
if [ -s "$RDIR/worker_restart.lost" ]; then
  echo "  worker_restart: a session did not survive the worker restart -> FAIL"
  echo "| worker_restart shells survive | | lost | | adopted | **FAIL** |" >>"$ART"
  FAILED=1
fi
if [ -s "$RDIR/degraded_path.churn" ]; then
  echo "  degraded_path: agent replaced its connection more than once in a window -> FAIL"
  echo "| degraded_path churn | | | | ≤1 / window | **FAIL** |" >>"$ART"
  FAILED=1
fi
wait 2>/dev/null || true
for f in "$RDIR"/direct.*; do
  [ -e "$f" ] || continue
  v=$(cat "$f")
  echo "  relay_pinned: back on a direct path after ${v}ms (budget ${RELAY_BACK_BUDGET_MS}ms)"
  if [ "$v" = TIMEOUT ]; then
    echo "| relay_pinned back-to-direct | | TIMEOUT | | ${RELAY_BACK_BUDGET_MS}ms | **FAIL** |" >>"$ART"
    FAILED=1
  else
    echo "| relay_pinned back-to-direct | ${v}ms | | | ${RELAY_BACK_BUDGET_MS}ms | PASS |" >>"$ART"
  fi
done
echo "artifact: $ART"

if [ "$FAILED" = 1 ]; then
  echo "SESSION RESILIENCE: FAIL"
  exit 1
fi
echo "SESSION RESILIENCE: PASS"
