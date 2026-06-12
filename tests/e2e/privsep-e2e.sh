#!/usr/bin/env bash
# Privilege-separation e2e (privsep-node.md Phase 1).
#
# Two hop nodes federate into one warren and route real IP packets over the
# TUN data plane — but each daemon runs in privsep mode (HOP_PRIVSEP=1), so the
# root *monitor* owns the TUN and hands its fd to the unprivileged-model *worker*
# over the SCM_RIGHTS control channel. This proves the full handoff mechanic
# end-to-end: monitor creates+configures the device, worker wraps the passed fd
# (tun::Configuration::raw_fd, no reconfigure) and routes packets through it.
#
# Asserts: (1) each node really split into a monitor + a worker process, the
# worker carrying HOP_PRIVSEP_WORKER in its environ; (2) the monitor logged that
# it served CreateTun and passed the fd; (3) ping over the passed-fd TUN works.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NET=hop-privsep-e2e-net
IMG=hop-privsep-e2e
VOL=hop-privsep-e2e-shared

cleanup() {
    echo "--- cleanup ---"
    docker rm -f hop-ps-a hop-ps-b >/dev/null 2>&1 || true
    docker volume rm "$VOL" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -f "$SCRIPT_DIR/hop"
}
trap cleanup EXIT

echo "=== building aarch64 linux binary ==="
if [ "${REBUILD:-1}" = "1" ]; then
    AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target aarch64-unknown-linux-gnu -p hop-cli
fi
cp "$ROOT/target/aarch64-unknown-linux-gnu/release/hop" "$SCRIPT_DIR/hop"

echo "=== building privsep test image ==="
docker build -t "$IMG" -f - "$SCRIPT_DIR" >/dev/null <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates jq iputils-ping iproute2 procps && rm -rf /var/lib/apt/lists/*
# Phase 2: the unprivileged service account the worker drops to (HOP_PRIVSEP_DROP).
RUN useradd -r -M -s /usr/sbin/nologin hop
COPY hop /usr/local/bin/hop
RUN chmod +x /usr/local/bin/hop
DOCKERFILE

docker network create "$NET" >/dev/null
docker volume create "$VOL" >/dev/null

# HOP_PRIVSEP=1 turns each `hop host` into a monitor that spawns the worker.
# HOP_PRIVSEP_DROP=1 (Phase 2) drops that worker to the unprivileged `hop` user;
# the monitor re-owns /cfg first so the worker reads its own secrets. This also
# proves the Phase-0 feasibility on Linux for a NON-root worker: it does all TUN
# data-plane I/O on the monitor-passed fd while running as `hop`.
# HOP_VPN=1 opts into the warren VPN; the containers grant TUN + NET_ADMIN.
COMMON=(--network "$NET" --cap-add=NET_ADMIN --device /dev/net/tun
        -v "$VOL:/shared" -e RUST_LOG="${HOP_E2E_LOG:-hop=info,hop_core=info}"
        -e HOP_VPN=1 -e HOP_PRIVSEP=1 -e HOP_PRIVSEP_DROP=1 --user root)

echo "=== starting host-a (warren owner, privsep) ==="
docker run -d --name hop-ps-a "${COMMON[@]}" "$IMG" bash -c '
  set -e; mkdir -p /cfg
  hop --config /cfg host --quiet >/cfg/log 2>&1 &
  while ! grep -q "vpn: enabled" /cfg/log; do sleep 1; done
  cp /cfg/creator_invite /shared/invite-a
  grep -o "virtual IP [0-9.]*" /cfg/log | head -1 | awk "{print \$3}" > /shared/vip-a
  touch /shared/ready-a
  tail -f /cfg/log
' >/dev/null

echo "=== waiting for host-a (max 120s) ==="
for i in $(seq 1 120); do
  docker exec hop-ps-a test -f /shared/ready-a 2>/dev/null && break || true
  sleep 1
done
docker exec hop-ps-a test -f /shared/ready-a || { echo "FAIL: host-a not ready"; docker exec hop-ps-a cat /cfg/log | tail -30; exit 1; }
VIP_A=$(docker exec hop-ps-a cat /shared/vip-a)
echo "host-a virtual IP: $VIP_A"

echo "=== starting host-b (joins the warren, privsep) ==="
docker run -d --name hop-ps-b "${COMMON[@]}" "$IMG" bash -c '
  set -e; mkdir -p /cfg
  while [ ! -f /shared/invite-a ]; do sleep 1; done
  hop --config /cfg warren join "$(cat /shared/invite-a)" >/cfg/join.log 2>&1 || true
  hop --config /cfg host --quiet >/cfg/log 2>&1 &
  while ! grep -q "vpn: enabled" /cfg/log; do sleep 1; done
  touch /shared/ready-b
  tail -f /cfg/log
' >/dev/null

echo "=== waiting for host-b (max 120s) ==="
for i in $(seq 1 120); do
  docker exec hop-ps-b test -f /shared/ready-b 2>/dev/null && break || true
  sleep 1
done
docker exec hop-ps-b test -f /shared/ready-b || { echo "FAIL: host-b not ready"; docker exec hop-ps-b cat /cfg/log | tail -30; exit 1; }

RC=0

# ── ASSERTION 1: each node split into a monitor + worker, worker has the flag ──
echo ""
echo "=== TEST: monitor/worker process split ==="
for c in hop-ps-a hop-ps-b; do
  # Two `hop host` processes: the monitor (started by the entrypoint) and the
  # worker it spawned. The worker carries HOP_PRIVSEP_WORKER in its environ.
  NPROC=$(docker exec "$c" pgrep -fc 'hop --config /cfg host|hop host --config' 2>/dev/null | head -1 || echo 0)
  WORKER_PID=$(docker exec "$c" bash -c '
    for p in $(pgrep -f "hop"); do
      if tr "\0" "\n" </proc/$p/environ 2>/dev/null | grep -q "^HOP_PRIVSEP_WORKER=1$"; then echo $p; fi
    done' 2>/dev/null | head -1 || true)
  if [ -n "$WORKER_PID" ]; then
    echo "  $c: worker PID $WORKER_PID has HOP_PRIVSEP_WORKER=1 (monitor/worker split OK)"
    # Phase 2: the worker must run as the unprivileged `hop` user, not root.
    WUID=$(docker exec "$c" bash -c "awk '/^Uid:/{print \$2}' /proc/$WORKER_PID/status" 2>/dev/null | head -1 || echo "?")
    HOPUID=$(docker exec "$c" id -u hop 2>/dev/null || echo "")
    if [ -n "$HOPUID" ] && [ "$WUID" = "$HOPUID" ]; then
      echo "  $c: worker runs as hop (uid=$WUID, non-root) — privilege drop OK"
    else
      echo "  $c: FAIL — worker uid=$WUID, expected hop uid=$HOPUID (privilege drop did not take)"
      docker exec "$c" grep -i "privsep" /cfg/log | tail -10 || true
      RC=1
    fi
  else
    echo "  $c: FAIL — no worker process carrying HOP_PRIVSEP_WORKER found (procs: $NPROC)"
    docker exec "$c" bash -c 'ps -ef | grep -i hop | grep -v grep' || true
    RC=1
  fi
done

# ── ASSERTION 2: the monitor served CreateTun and passed the fd ──
echo ""
echo "=== TEST: monitor served the TUN fd over the control channel ==="
for c in hop-ps-a hop-ps-b; do
  if docker exec "$c" grep -q "served CreateTun, passed TUN fd to worker" /cfg/log 2>/dev/null; then
    echo "  $c: monitor logged CreateTun fd handoff OK"
    docker exec "$c" grep "served CreateTun" /cfg/log | tail -1 || true
  else
    echo "  $c: FAIL — monitor never logged the CreateTun fd handoff"
    docker exec "$c" grep -i "privsep" /cfg/log | tail -10 || true
    RC=1
  fi
done

echo "=== allow replication + tun routes to settle (15s) ==="
sleep 15

# ── ASSERTION 3: packets route over the passed-fd TUN ──
echo ""
echo "=== TEST: ping host-a vIP ($VIP_A) from host-b over the passed-fd TUN ==="
if docker exec hop-ps-b ping -c 3 -W 3 "$VIP_A"; then
  echo ""
  echo "PRIVSEP E2E: routing over the monitor-passed TUN fd works."
else
  echo ""
  echo "PRIVSEP E2E FAILED: ping over the passed-fd TUN did not succeed."
  echo "--- host-a log tail ---"; docker exec hop-ps-a cat /cfg/log | tail -25 || true
  echo "--- host-b log tail ---"; docker exec hop-ps-b cat /cfg/log | tail -25 || true
  RC=1
fi

if [ "$RC" = "0" ]; then
  echo ""
  echo "PRIVSEP E2E PASSED: monitor/worker split + SCM_RIGHTS TUN handoff + routing all verified."
else
  echo ""
  echo "PRIVSEP E2E FAILED (see assertions above)."
fi
exit $RC
