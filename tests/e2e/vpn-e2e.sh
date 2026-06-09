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
# HOP_NETDOC_VALIDATION=enforce runs the C1 author-validation in full enforce on
# BOTH nodes from the start — the real multi-node bind→enforce→reconverge test.
# host-b announces its doc author to host-a (AnnounceNetdocAuthor); until that
# binding lands, host-b's self-owned ip/vpn entries pass under migration grace
# (unbound owner), so enforce can't partition a freshly-joined node. If routing
# works here, enforce is safe to default on.
COMMON=(--network "$NET" --cap-add=NET_ADMIN --device /dev/net/tun
        -v "$VOL:/shared" -e RUST_LOG=hop=info,hop_core=info -e HOP_VPN=1
        -e HOP_NETDOC_VALIDATION=enforce --user root)

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

echo "=== TEST: C1 member-binding announce (AnnounceNetdocAuthor) ==="
# host-b's daemon announces its doc author to host-a on startup; host-a (the
# trust anchor) records the peer/<host-b>.netdoc_author binding. Allow a few
# seconds for the best-effort announce + retry to land.
BIND_OK=0
for i in $(seq 1 30); do
  if docker exec hop-vpn-a sh -c 'grep -q "netdoc C1: vouched author" /cfg/log' 2>/dev/null; then
    BIND_OK=1; break
  fi
  sleep 1
done
if [ "$BIND_OK" = "1" ]; then
  echo "BINDING PASSED: host-a recorded host-b's announced netdoc author."
  docker exec hop-vpn-a grep "vouched author" /cfg/log | tail -1 || true
else
  echo "BINDING WARN: host-a did not log a vouched author within 30s"
  echo "--- host-b log (announce attempts) ---"; docker exec hop-vpn-b grep -i 'announce' /cfg/log | tail -10 || true
  echo "--- host-a log tail ---"; docker exec hop-vpn-a cat /cfg/log | tail -15 || true
fi

echo "=== TEST: per-member self-doc announce (peer/<host-b>.self_doc) ==="
# The same announce carries host-b's self-doc read ticket; host-a records it so
# other nodes can import host-b's self-state from its isolated self-doc.
SELFDOC_OK=0
for i in $(seq 1 30); do
  if docker exec hop-vpn-a sh -c 'grep -q "recorded self-doc for member" /cfg/log' 2>/dev/null; then
    SELFDOC_OK=1; break
  fi
  sleep 1
done
if [ "$SELFDOC_OK" = "1" ]; then
  echo "SELF-DOC PASSED: host-a recorded host-b's self-doc read ticket."
else
  echo "SELF-DOC WARN: host-a did not log a recorded self-doc within 30s"
  echo "--- host-a log tail ---"; docker exec hop-vpn-a cat /cfg/log | tail -15 || true
fi

echo "=== TEST: ping host-a virtual IP ($VIP_A) from host-b over the TUN (enforce mode) ==="
if docker exec hop-vpn-b ping -c 3 -W 3 "$VIP_A"; then
    echo ""
    echo "VPN E2E PASSED: role-gated packet flow over TUN works under enforce."
    if [ "$BIND_OK" != "1" ]; then
        echo "VPN E2E FAILED: routing works but the C1 binding was never recorded."
        RC=1
    elif [ "$SELFDOC_OK" != "1" ]; then
        echo "VPN E2E FAILED: routing works but the per-member self-doc was never recorded."
        RC=1
    else
        RC=0
    fi
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
    # The log is APPENDED across the restart, so the first boot's "resumed warren
    # sync" / "vpn: enabled" lines are still present. Wait for the count to
    # *increase* (the rebooted daemon's own lines) — not just be >= 1 — otherwise
    # the readiness check trips instantly and we ping before reconvergence.
    RESUMED_BEFORE=$(docker exec hop-vpn-b grep -c 'resumed warren sync' /cfg/log 2>/dev/null || echo 0)
    VPNUP_BEFORE=$(docker exec hop-vpn-b grep -c 'vpn: enabled' /cfg/log 2>/dev/null || echo 0)
    docker exec hop-vpn-b pkill -f 'config /cfg host' || true
    sleep 3
    # Relaunch the host exactly as a boot service would; logs append to /cfg/log.
    docker exec -d hop-vpn-b bash -c 'hop --config /cfg host --quiet >>/cfg/log 2>&1'
    echo "waiting for host-b to reconverge (resync + vpn re-enabled, max 90s)..."
    for i in $(seq 1 90); do
      R=$(docker exec hop-vpn-b grep -c 'resumed warren sync' /cfg/log 2>/dev/null || echo 0)
      V=$(docker exec hop-vpn-b grep -c 'vpn: enabled' /cfg/log 2>/dev/null || echo 0)
      if [ "$R" -gt "$RESUMED_BEFORE" ] && [ "$V" -gt "$VPNUP_BEFORE" ]; then break; fi
      sleep 1
    done
    NS_AFTER=$(docker exec hop-vpn-b grep -o 'namespace [0-9a-f]*' /cfg/log | tail -1)
    RESUMED=$(docker exec hop-vpn-b grep -c 'resumed warren sync' /cfg/log 2>/dev/null || echo 0)
    echo "namespace before reboot: $NS_BEFORE"
    echo "namespace after  reboot: $NS_AFTER"
    echo "resume-sync occurrences: $RESUMED (was $RESUMED_BEFORE)"
    sleep 8   # let the TUN path + QUIC data plane re-establish before re-pinging
    echo "--- re-ping host-a after host-b reboot (retry up to 3x) ---"
    PING_OK=0
    for attempt in 1 2 3; do
      if docker exec hop-vpn-b ping -c 5 -W 3 "$VIP_A"; then PING_OK=1; break; fi
      echo "  (re-ping attempt $attempt failed; settling 5s)"; sleep 5
    done
    if [ "$NS_BEFORE" = "$NS_AFTER" ] && [ "$RESUMED" -gt "$RESUMED_BEFORE" ] 2>/dev/null && [ "$PING_OK" = "1" ]; then
        echo "REBOOT TEST PASSED: same warren reopened, sync re-established, routing intact."
    else
        echo "REBOOT TEST FAILED."
        docker exec hop-vpn-b cat /cfg/log | tail -30 || true
        RC=1
    fi
fi
exit $RC
