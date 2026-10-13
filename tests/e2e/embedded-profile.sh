#!/usr/bin/env bash
# embedded-profile.sh — hop where nobody is watching (docs/technical/self-healing.md).
#
# A member the way embedded devices and short-lived containers run it:
#   * `hop host` is the container's PID 1: no init, no privsep monitor, nothing
#     that would restart it;
#   * read-only root filesystem (only /cfg and tmpfs are writable);
#   * a memory cap and a pid limit.
# Stages (each FAILs the run):
#   up            joins the founder's warren and routes to it over the VPN
#   footprint     resident memory after settling stays under MEM_BUDGET_MB
#   status        `hop status` reports healthy (exit 0)
#   recover       `hop recover` re-executes PID 1 in place (no supervisor would
#                 restart it); the container stays up, routes again, and a live
#                 shell session on it survives as the SAME shell (its PTY master
#                 is carried through the exec)
#   self-repair   a wedged VPN (test-only fault) is detected and repaired by a
#                 self-restart, again with no supervisor
#   churn         EPHEMERAL members join, ping the founder and are deleted; the
#                 founder must not escalate over peers that are simply gone
#
# Usage: REBUILD=1 ./tests/e2e/embedded-profile.sh   (HOP_DUMP_LOGS=<dir> keeps logs)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMG=hop-embedded-e2e
NET=hop-embedded-net
FOUNDER=hop-emb-founder
MEMBER=hop-emb-member
VOL=hop-emb-member-cfg
MEM_LIMIT="${MEM_LIMIT:-128m}"
MEM_BUDGET_MB="${MEM_BUDGET_MB:-96}"
EPHEMERAL="${EPHEMERAL:-5}"
RC=0

say() { echo "=== $* ==="; }
fail() { echo "FAIL: $*"; RC=1; }

cleanup() {
  if [ -n "${HOP_DUMP_LOGS:-}" ]; then
    mkdir -p "$HOP_DUMP_LOGS"
    docker logs "$MEMBER" >"$HOP_DUMP_LOGS/member.log" 2>&1 || true
    docker exec "$FOUNDER" cat /cfg/log >"$HOP_DUMP_LOGS/founder.log" 2>/dev/null || true
  fi
  if [ "${HOP_KEEP_CONTAINERS:-0}" = 1 ]; then echo "keeping $FOUNDER $MEMBER"; return; fi
  docker rm -f "$FOUNDER" "$MEMBER" >/dev/null 2>&1 || true
  for ((i = 1; i <= EPHEMERAL; i++)); do docker rm -f "hop-emb-eph-$i" >/dev/null 2>&1 || true; done
  docker volume rm "$VOL" >/dev/null 2>&1 || true
  for ((i = 1; i <= EPHEMERAL; i++)); do docker volume rm "hop-emb-eph-$i" >/dev/null 2>&1 || true; done
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -f "$SCRIPT_DIR/hop"
}
trap cleanup EXIT

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
        ca-certificates iputils-ping iproute2 python3 && \
    rm -rf /var/lib/apt/lists/* && useradd -m -s /bin/bash ubuntu2
COPY hop /usr/local/bin/hop
RUN chmod +x /usr/local/bin/hop
DOCKERFILE

docker rm -f "$FOUNDER" "$MEMBER" >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null

say "founder up (an ordinary privsep host)"
docker run -d --name "$FOUNDER" --network "$NET" --cap-add=NET_ADMIN --device /dev/net/tun \
  -e HOP_VPN=1 -e HOP_PRIVSEP=1 -e HOP_VPN_PROBE_SECS=10 -e RUST_LOG=hop=info,hop_core=warn \
  --user root "$IMG" sleep infinity >/dev/null
docker exec "$FOUNDER" mkdir -p /cfg
docker exec -d "$FOUNDER" bash -lc 'hop --config /cfg host --quiet >>/cfg/log 2>&1'
for _ in $(seq 1 60); do docker exec "$FOUNDER" grep -q 'vpn: enabled' /cfg/log 2>/dev/null && break; sleep 1; done
FOUNDER_VIP=$(docker exec "$FOUNDER" sh -c "grep -aoE 'virtual IP 100[0-9.]+' /cfg/log | head -1 | grep -oE '100[0-9.]+'")
[ -n "$FOUNDER_VIP" ] || { echo "FAIL: founder never brought the VPN up"; docker exec "$FOUNDER" tail -20 /cfg/log; exit 1; }
echo "founder vIP=$FOUNDER_VIP"

mint_invite() {
  docker exec "$FOUNDER" hop --config /cfg invite --tier node --user ubuntu2 2>&1 \
    | grep -E '^  [A-Za-z0-9_-]{40,}$' | head -1 | tr -d ' '
}

# A constrained member: join (one-shot, writes /cfg), then `hop host` as PID 1.
CONSTRAINTS=(--memory "$MEM_LIMIT" --pids-limit 256 --read-only --tmpfs /tmp --tmpfs /run
             --cap-add=NET_ADMIN --device /dev/net/tun --user root
             -e HOP_VPN=1 -e HOP_PRIVSEP=0 -e HOP_VPN_PROBE_SECS=10
             -e HOP_FAULT_VPN_WEDGE_FILE=/cfg/fault-vpn-wedge -e RUST_LOG=hop=info,hop_core=warn)
start_member() { # name volume
  local name="$1" vol="$2" inv
  inv=$(mint_invite)
  [ -n "$inv" ] || { echo "could not mint an invite"; return 1; }
  docker volume create "$vol" >/dev/null
  docker run --rm --network "$NET" "${CONSTRAINTS[@]}" -v "$vol:/cfg" "$IMG" \
    hop --config /cfg connect "$inv" --warren --yes >/dev/null 2>&1 || true
  docker run -d --name "$name" --network "$NET" "${CONSTRAINTS[@]}" -v "$vol:/cfg" "$IMG" \
    hop --config /cfg host --quiet >/dev/null
}
wait_ping() { # container seconds
  local i
  for i in $(seq 1 "$2"); do
    docker exec "$1" ping -c1 -W1 "$FOUNDER_VIP" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

say "up: constrained member (PID 1, no supervisor, read-only root, $MEM_LIMIT)"
start_member "$MEMBER" "$VOL"
T0=$(date +%s)
if wait_ping "$MEMBER" 90; then
  echo "  routes to the founder after $(( $(date +%s) - T0 ))s"
else
  fail "constrained member never routed to the founder"; docker logs "$MEMBER" 2>&1 | tail -15
fi

say "footprint"
sleep 30
MEM=$(docker stats --no-stream --format '{{.MemUsage}}' "$MEMBER" | awk '{print $1}')
MB=$(echo "$MEM" | awk '/MiB/ {sub("MiB",""); print int($1)} /GiB/ {sub("GiB",""); print int($1*1024)} /KiB/ {print 0}')
echo "  member memory: $MEM (budget ${MEM_BUDGET_MB} MiB, cap $MEM_LIMIT)"
[ -n "$MB" ] && [ "$MB" -le "$MEM_BUDGET_MB" ] || fail "member uses ${MEM} (budget ${MEM_BUDGET_MB} MiB)"

say "status"
if docker exec "$MEMBER" hop --config /cfg status >/tmp/hop-emb-status.$$ 2>&1; then
  echo "  hop status: healthy"
else
  fail "hop status reported problems:"; cat /tmp/hop-emb-status.$$
fi
rm -f /tmp/hop-emb-status.$$

say "session: an interactive shell on the member, driven from the founder"
MEMBER_INVITE=$(docker exec "$MEMBER" hop --config /cfg invite --user ubuntu2 2>&1 | grep -E '^  [A-Za-z0-9_-]{40,}$' | head -1 | tr -d ' ')
docker exec -i "$FOUNDER" tee /root/drive.py >/dev/null <<'PYEOF'
import os, pty, sys, time
inv = sys.argv[1]
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm"
    os.execvp("hop", ["hop", "--config", "/cfgc", inv])
log = open("/root/drive.log", "ab", buffering=0)
while True:
    r = __import__("select").select([fd], [], [], 0.2)[0]
    if r:
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        log.write(data)
    for name in ("pid1", "pid2"):
        if os.path.exists(f"/root/type-{name}"):
            os.remove(f"/root/type-{name}")
            os.write(fd, f"echo $$ > /tmp/{name}\n".encode())
PYEOF
docker exec "$FOUNDER" mkdir -p /cfgc
docker exec -d "$FOUNDER" python3 /root/drive.py "$MEMBER_INVITE"
SHELL1=""
for _ in $(seq 1 30); do
  docker exec "$FOUNDER" touch /root/type-pid1
  sleep 2
  SHELL1=$(docker exec "$MEMBER" cat /tmp/pid1 2>/dev/null | tr -d '[:space:]')
  [ -n "$SHELL1" ] && break
done
if [ -n "$SHELL1" ]; then echo "  session open on the member (shell pid $SHELL1)"; else fail "could not open a session on the member"; fi

say "recover: re-exec in place with no supervisor"
STARTS_BEFORE=$(docker logs "$MEMBER" 2>&1 | grep -c "Hosting as")
docker exec "$MEMBER" hop --config /cfg recover --quiet >/dev/null 2>&1 || true
# Wait for the restarted daemon to be up (and its VPN, which clears any stale
# fault file) before judging — or the next stage races its startup.
for _ in $(seq 1 30); do
  [ "$(docker logs "$MEMBER" 2>&1 | grep -c "Hosting as")" -gt "$STARTS_BEFORE" ] \
    && [ "$(docker logs "$MEMBER" 2>&1 | grep -c "vpn: enabled")" -gt "$STARTS_BEFORE" ] && break
  sleep 1
done
if [ "$(docker inspect -f '{{.State.Running}}' "$MEMBER")" != true ]; then
  fail "the member's PID 1 exited on a requested restart (nothing restarts it)"
# grep -c reads to the end: `grep -q` would exit at the first match, SIGPIPE
# `docker logs`, and under pipefail read as "not found".
elif [ "$(docker logs "$MEMBER" 2>&1 | grep -c "re-executing")" -eq 0 ]; then
  fail "no re-exec logged after hop recover"
elif wait_ping "$MEMBER" 60; then
  echo "  PID 1 re-executed in place and routes again"
  if [ -n "$SHELL1" ]; then
    SHELL2=""
    for _ in $(seq 1 30); do
      docker exec "$FOUNDER" touch /root/type-pid2
      sleep 2
      SHELL2=$(docker exec "$MEMBER" cat /tmp/pid2 2>/dev/null | tr -d '[:space:]')
      [ -n "$SHELL2" ] && break
    done
    if [ "$SHELL2" = "$SHELL1" ]; then
      echo "  the session resumed on the SAME shell (pid $SHELL2) across the re-exec"
    else
      fail "the session's shell did not survive the re-exec (before ${SHELL1}, after ${SHELL2:-none})"
    fi
  fi
else
  fail "re-executed member does not route"; docker logs "$MEMBER" 2>&1 | tail -15
fi

say "self-repair: wedged VPN, no supervisor"
REEXEC_BEFORE=$(docker logs "$MEMBER" 2>&1 | grep -c "re-executing")
docker exec "$MEMBER" touch /cfg/fault-vpn-wedge
sleep 5
if docker exec "$MEMBER" ping -c2 -W2 "$FOUNDER_VIP" >/dev/null 2>&1; then
  fail "the wedge fault did not break the member's VPN"
else
  T0=$(date +%s); OK=0
  for _ in $(seq 1 90); do
    if [ "$(docker logs "$MEMBER" 2>&1 | grep -c "re-executing")" -gt "$REEXEC_BEFORE" ] && wait_ping "$MEMBER" 2; then
      OK=1; break
    fi
    sleep 2
  done
  if [ "$OK" = 1 ]; then
    echo "  detected, restarted itself by re-exec, routes again after $(( $(date +%s) - T0 ))s"
  else
    fail "member did not repair its VPN within 180s"; docker logs "$MEMBER" 2>&1 | grep -E "vpn: every|re-executing|dial to" | tail -10
    echo "  --- member's own view (hop status --json: vpn_probes, vpn_ladder):"
    docker exec "$MEMBER" hop --config /cfg --json status 2>&1 | grep -E '"(vpn_ladder|host_ok|vpn_ok|fresh)"' | head -12
  fi
fi
docker exec "$MEMBER" rm -f /cfg/fault-vpn-wedge >/dev/null 2>&1 || true

say "churn: $EPHEMERAL short-lived members"
FOUNDER_RESTARTS_BEFORE=$(docker exec "$FOUNDER" grep -ac "restarting the worker" /cfg/log 2>/dev/null | head -1)
for ((i = 1; i <= EPHEMERAL; i++)); do
  T0=$(date +%s)
  start_member "hop-emb-eph-$i" "hop-emb-eph-$i"
  if wait_ping "hop-emb-eph-$i" 90; then
    echo "  ephemeral $i: routed after $(( $(date +%s) - T0 ))s; deleting it"
  else
    fail "ephemeral member $i never routed"
  fi
  docker rm -f "hop-emb-eph-$i" >/dev/null 2>&1
done
echo "  letting the founder probe its now-absent peers for 60s"
sleep 60
AFTER=$(docker exec "$FOUNDER" grep -ac "restarting the worker" /cfg/log 2>/dev/null | head -1)
if [ "${AFTER:-0}" -gt "${FOUNDER_RESTARTS_BEFORE:-0}" ]; then
  fail "the founder self-restarted over peers that were merely gone (false positive)"
else
  echo "  founder did not escalate over departed peers"
fi
wait_ping "$MEMBER" 10 || fail "the long-lived member lost the founder during churn"

echo ""
if [ "$RC" = 0 ]; then echo "EMBEDDED PROFILE: PASS"; else echo "EMBEDDED PROFILE: FAIL"; fi
exit $RC
