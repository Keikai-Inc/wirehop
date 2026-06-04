#!/usr/bin/env bash
# Step 8 — live multi-node TUN VPN e2e.
#
# Two hop nodes federate into one warren and route real IP packets over the
# hop/vpn/1 TUN data plane. host-a owns the warren (admin member); host-b joins
# (namespace import) + redeems host-a's invite to become an admin member. We then
# ping host-a's virtual IP from host-b over the actual TUN device.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NET=hop-vpn-e2e-net
IMG=hop-vpn-e2e
VOL=hop-vpn-e2e-shared

cleanup() {
    echo "--- cleanup ---"
    docker rm -f hop-vpn-a hop-vpn-b >/dev/null 2>&1 || true
    docker volume rm "$VOL" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -f "$SCRIPT_DIR/hop"
}
trap cleanup EXIT

echo "=== building aarch64 linux binary (with M4a) ==="
AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target aarch64-unknown-linux-gnu -p hop-cli
cp "$ROOT/target/aarch64-unknown-linux-gnu/release/hop" "$SCRIPT_DIR/hop"

echo "=== building VPN test image ==="
docker build -t "$IMG" -f - "$SCRIPT_DIR" >/dev/null <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates jq iputils-ping iproute2 && rm -rf /var/lib/apt/lists/*
COPY hop /usr/local/bin/hop
RUN chmod +x /usr/local/bin/hop
DOCKERFILE

docker network create "$NET" >/dev/null
docker volume create "$VOL" >/dev/null

# HOP_VPN=1 opts these nodes into the warren VPN. As of v0.6.37 the VPN is
# off-by-default (security-audit P0a) — a real node install opts in via
# `--host` / `hop config set vpn on` / HOP_VPN=1, which this mirrors. The
# containers grant TUN + NET_ADMIN so bring-up succeeds; the conflict guard
# finds no existing 100.64.0.0/10.
COMMON=(--network "$NET" --cap-add=NET_ADMIN --device /dev/net/tun
        -v "$VOL:/shared" -e RUST_LOG=hop=info,hop_core=info -e HOP_VPN=1 --user root)

echo "=== starting host-a (warren owner) ==="
docker run -d --name hop-vpn-a "${COMMON[@]}" "$IMG" bash -c '
  set -e; mkdir -p /cfg
  hop --config /cfg host --quiet >/cfg/log 2>&1 &
  # The creator invite is augmented with the warren ticket once netdoc is ready
  # (logged "creator invite augmented"); that completes before "vpn: enabled".
  # So the single creator invite = membership + warren join (the unified token).
  while ! grep -q "vpn: enabled" /cfg/log; do sleep 1; done
  cp /cfg/creator_invite /shared/invite-a
  grep -o "virtual IP [0-9.]*" /cfg/log | head -1 | awk "{print \$3}" > /shared/vip-a
  touch /shared/ready-a
  echo "host-a vIP: $(cat /shared/vip-a)"
  tail -f /cfg/log
' >/dev/null

echo "=== waiting for host-a to publish its ticket + vIP (max 120s) ==="
for i in $(seq 1 120); do
  if docker exec hop-vpn-a test -f /shared/ready-a 2>/dev/null; then break; fi
  sleep 1
done
docker exec hop-vpn-a test -f /shared/ready-a || { echo "FAIL: host-a not ready"; docker logs hop-vpn-a | tail; docker exec hop-vpn-a cat /cfg/log | tail -30; exit 1; }
VIP_A=$(docker exec hop-vpn-a cat /shared/vip-a)
echo "host-a virtual IP: $VIP_A"

echo "=== starting host-b (joins the warren from ONE unified invite) ==="
docker run -d --name hop-vpn-b "${COMMON[@]}" "$IMG" bash -c '
  set -e; mkdir -p /cfg
  while [ ! -f /shared/invite-a ]; do sleep 1; done
  INVITE="$(cat /shared/invite-a)"
  # Unified token: the single invite carries host-a s warren. `hop warren join`
  # redeems it for membership AND writes the namespace join ticket — no separate
  # netdoc ticket, no separate redeem step.
  hop --config /cfg warren join "$INVITE" >/cfg/join.log 2>&1 || true
  # Bring up the host; it imports the namespace from /cfg/netdoc-join.ticket and
  # the VPN comes up default-on.
  hop --config /cfg host --quiet >/cfg/log 2>&1 &
  while ! grep -q "vpn: enabled" /cfg/log; do sleep 1; done
  grep -o "virtual IP [0-9.]*" /cfg/log | head -1 | awk "{print \$3}" > /shared/vip-b
  touch /shared/ready-b
  echo "host-b vIP: $(cat /shared/vip-b)"
  tail -f /cfg/log
' >/dev/null

echo "=== waiting for host-b ready (max 120s) ==="
for i in $(seq 1 120); do
  if docker exec hop-vpn-b test -f /shared/ready-b 2>/dev/null; then break; fi
  sleep 1
done
docker exec hop-vpn-b test -f /shared/ready-b || { echo "FAIL: host-b not ready"; docker exec hop-vpn-b cat /cfg/log | tail -30; exit 1; }
VIP_B=$(docker exec hop-vpn-b cat /shared/vip-b)
echo "host-b virtual IP: $VIP_B"

echo "=== allow replication + tun routes to settle (15s) ==="
sleep 15

echo "=== diagnostics: interfaces + routes on host-b ==="
docker exec hop-vpn-b ip addr show | grep -A2 -iE 'utun|tun' || true
docker exec hop-vpn-b ip route | grep -i '100.64' || true
echo "=== diagnostics: unified-invite join ==="
echo "--- invite-a (bytes) ---"; docker exec hop-vpn-a wc -c /shared/invite-a 2>/dev/null || true
echo "--- host-b warren join.log ---"; docker exec hop-vpn-b cat /cfg/join.log 2>/dev/null | tail -20 || true
echo "--- host-b netdoc-join.ticket present? ---"; docker exec hop-vpn-b ls -l /cfg/netdoc-join.ticket 2>/dev/null || echo "(absent)"
echo "--- host-a namespace vs host-b namespace ---"
docker exec hop-vpn-a grep -o 'namespace [0-9a-f]*' /cfg/log | head -1 || true
docker exec hop-vpn-b grep -o 'namespace [0-9a-f]*' /cfg/log | head -1 || true
echo "--- host-a peers (did host-b's redeem register?) ---"; docker exec hop-vpn-a cat /cfg/peers.json 2>/dev/null | head -20 || true

echo "=== TEST: ping host-a virtual IP ($VIP_A) from host-b over the TUN ==="
if docker exec hop-vpn-b ping -c 3 -W 3 "$VIP_A"; then
    echo ""
    echo "VPN E2E PASSED: role-gated packet flow over TUN works."
    RC=0
else
    echo ""
    echo "VPN E2E FAILED: ping over TUN did not succeed."
    echo "--- host-a log tail ---"; docker exec hop-vpn-a cat /cfg/log | tail -25 || true
    echo "--- host-b log tail ---"; docker exec hop-vpn-b cat /cfg/log | tail -25 || true
    RC=1
fi

# ── Reboot reconvergence: restart host-b's daemon (Open path, not Import) and
#    confirm it reopens the SAME warren, actively re-syncs, and still routes.
if [ "$RC" = "0" ]; then
    echo ""
    echo "=== REBOOT TEST: restart host-b's daemon and re-verify ==="
    NS_BEFORE=$(docker exec hop-vpn-b grep -o 'namespace [0-9a-f]*' /cfg/log | head -1)
    docker exec hop-vpn-b pkill -f 'config /cfg host' || true
    sleep 3
    # Relaunch the host exactly as a boot service would; logs append to /cfg/log.
    docker exec -d hop-vpn-b bash -c 'hop --config /cfg host --quiet >>/cfg/log 2>&1'
    echo "waiting for host-b to come back up (max 90s)..."
    for i in $(seq 1 90); do
      if docker exec hop-vpn-b sh -c 'grep -c "resumed warren sync" /cfg/log' 2>/dev/null | grep -q '[1-9]'; then break; fi
      sleep 1
    done
    NS_AFTER=$(docker exec hop-vpn-b grep -o 'namespace [0-9a-f]*' /cfg/log | tail -1)
    RESUMED=$(docker exec hop-vpn-b grep -c 'resumed warren sync' /cfg/log 2>/dev/null || echo 0)
    echo "namespace before reboot: $NS_BEFORE"
    echo "namespace after  reboot: $NS_AFTER"
    echo "resume-sync occurrences: $RESUMED"
    sleep 5   # let the TUN path re-establish before re-pinging
    echo "--- re-ping host-a after host-b reboot ---"
    if [ "$NS_BEFORE" = "$NS_AFTER" ] && [ "$RESUMED" -ge 1 ] 2>/dev/null && docker exec hop-vpn-b ping -c 5 -W 3 "$VIP_A"; then
        echo "REBOOT TEST PASSED: same warren reopened, sync re-established, routing intact."
    else
        echo "REBOOT TEST FAILED."
        docker exec hop-vpn-b cat /cfg/log | tail -30 || true
        RC=1
    fi
fi
exit $RC
