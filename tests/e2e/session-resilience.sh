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
#
# Budgets (SRT ms, from RESTORE; truthful FAIL rows allowed):
#   net_flap ≤ 10000 · zombie_path ≤ 12000 · host_restart ≤ 20000
# zombie_path's budget is the detection proof: without rx-stall detection the
# session waits out QUIC's 60s idle and SRT lands ~35-45s.
#
# Env: CYCLES (default 6), REBUILD=1 (cross-build first), HOP_DUMP_LOGS=<dir>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMG=hop-sessres-e2e
NET=hop-sessres-net
FOUNDER=hop-sessres-founder
MEMBER=hop-sessres-member
CYCLES="${CYCLES:-6}"
BACKSTOP_MS=90000

BUDGET_net_flap=10000
BUDGET_zombie_path=12000
BUDGET_host_restart=20000

say() { echo "=== $* ==="; }
trap 'cleanup' EXIT
cleanup() {
  say "cleanup"
  if [ -n "${HOP_DUMP_LOGS:-}" ]; then
    docker exec "$MEMBER" cat /cfg/log >"${HOP_DUMP_LOGS}/member.log" 2>/dev/null || true
    docker exec "$MEMBER" cat /cfg/session.log >"${HOP_DUMP_LOGS}/session.log" 2>/dev/null || true
    docker exec "$FOUNDER" cat /cfg/log >"${HOP_DUMP_LOGS}/founder.log" 2>/dev/null || true
  fi
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
        -e RUST_LOG="${SESS_LOG:-hop=info,hop_core=warn}" --user root)

start_daemon() { docker exec -d "$1" bash -lc 'hop --config /cfg host --quiet >>/cfg/log 2>&1'; }
stop_daemon()  { docker exec "$1" pkill -9 -f 'hop host' >/dev/null 2>&1 || true; }

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
d_host_restart() { stop_daemon "$FOUNDER"; sleep 3; }
r_host_restart() { start_daemon "$FOUNDER"; }

# PERTS env: space-separated subset for targeted soaks (default all).
if [ -n "${PERTS:-}" ]; then read -r -a PERTS <<<"$PERTS"; else PERTS=(net_flap zombie_path host_restart); fi
RDIR=$(mktemp -d)

say "SESSION SOAK: $CYCLES cycles"
for c in $(seq 1 "$CYCLES"); do
  name="${PERTS[$(( (c-1) % ${#PERTS[@]} ))]}"
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

ART="$SCRIPT_DIR/session-results.md"
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
echo "artifact: $ART"

if [ "$FAILED" = 1 ]; then
  echo "SESSION RESILIENCE: FAIL"
  exit 1
fi
echo "SESSION RESILIENCE: PASS"
