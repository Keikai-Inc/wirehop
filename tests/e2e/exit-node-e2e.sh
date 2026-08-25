#!/usr/bin/env bash
# Exit-node e2e (P2): a member routes ALL traffic via a warren exit node.
# on a gateway's physical LAN, via an advertised subnet route.
#
# Topology:
#   hop-exit-lan   (192.168.77.10)  — plain container on LANNET only (the "LAN
#                                     device"; never runs hop). Not on the warren
#                                     overlay network, so a client can reach it
#                                     ONLY by being routed through the gateway.
#   hop-exit-a     gateway/founder   — on NET (overlay) AND LANNET; advertises
#                                     192.168.77.0/24 (routes.json) + sets up
#                                     ip_forward + nftables masquerade.
#   hop-exit-b     client/member     — on NET only; HOP_ACCEPT_ROUTES=1 installs the
#                                     route + forwards to the gateway.
#
# PASS = `ping 192.168.77.10` from host-b succeeds (only possible via the route).
#
# Runs UNDER privsep (HOP_PRIVSEP_DROP, the real daemon's mode): the gateway's
# nft/ip_forward calls are privileged and the dropped worker delegates them to the
# root monitor via the SetupGateway primitive (like CreateTun/BindPrivPort). This
# exercises that whole path. HOP_ACCEPT_ROUTES opts the client into route
# acceptance (off by default, like Tailscale --accept-routes).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NET=hop-exit-net
LANNET=hop-exit-lannet
IMG=hop-exit-e2e
VOL=hop-exit-shared
LAN_CIDR=192.168.77.0/24
LAN_TARGET=192.168.77.10

cleanup() {
    echo "--- cleanup ---"
    docker rm -f hop-exit-a hop-exit-b hop-exit-lan >/dev/null 2>&1 || true
    docker volume rm "$VOL" >/dev/null 2>&1 || true
    docker network rm "$NET" "$LANNET" >/dev/null 2>&1 || true
    rm -f "$SCRIPT_DIR/hop"
}
trap cleanup EXIT

echo "=== building aarch64 linux binary ==="
AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target aarch64-unknown-linux-gnu -p hop-cli
cp "$ROOT/target/aarch64-unknown-linux-gnu/release/hop" "$SCRIPT_DIR/hop"

echo "=== building image (with nftables + iproute2 + ping) ==="
build_img() {
  docker build -t "$IMG" -f - "$SCRIPT_DIR" >/dev/null <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates jq iputils-ping iproute2 nftables dnsutils && \
    rm -rf /var/lib/apt/lists/*
COPY hop /usr/local/bin/hop
RUN chmod +x /usr/local/bin/hop
DOCKERFILE
}
ok=0
for attempt in 1 2 3; do
  if build_img; then ok=1; break; fi
  echo "  (build failed [$attempt] — pruning + retry)"; docker builder prune -af >/dev/null 2>&1 || true
done
[ "$ok" = 1 ] || { echo "FATAL: image build failed"; exit 1; }

docker network create "$NET" >/dev/null
docker network create --subnet "$LAN_CIDR" "$LANNET" >/dev/null
docker volume create "$VOL" >/dev/null

echo "=== starting the LAN device ($LAN_TARGET, LANNET only, no hop) ==="
docker run -d --name hop-exit-lan --network "$LANNET" --ip "$LAN_TARGET" "$IMG" sleep infinity >/dev/null

COMMON=(--network "$NET" --cap-add=NET_ADMIN --device /dev/net/tun
        --sysctl net.ipv4.ip_forward=1
        -v "$VOL:/shared" -e RUST_LOG="${HOP_E2E_LOG:-hop=info,hop_core=info}"
        -e HOP_VPN=1 -e HOP_PRIVSEP=1 -e HOP_PRIVSEP_DROP=1 --user root)

echo "=== starting gateway host-a (advertises $LAN_CIDR) ==="
docker run -d --name hop-exit-a "${COMMON[@]}" "$IMG" bash -c "
  set -e; mkdir -p /cfg
  hop --config /cfg lan advertise --exit
  hop --config /cfg host --quiet >/cfg/log 2>&1 &
  while ! grep -q 'vpn: enabled' /cfg/log; do sleep 1; done
  cp /cfg/creator_invite /shared/invite-a
  grep -m1 'vpn: enabled' /cfg/log | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 > /shared/vip-a
  touch /shared/ready-a
  tail -f /cfg/log
" >/dev/null
# Attach host-a to the LAN so it can actually reach the device it gateways.
echo "=== attaching host-a to LANNET ==="
for i in $(seq 1 30); do
  if docker exec hop-exit-a true 2>/dev/null; then break; fi; sleep 1
done
docker network connect "$LANNET" hop-exit-a

echo "=== waiting for host-a ready (max 120s) ==="
for i in $(seq 1 120); do
  docker exec hop-exit-a test -f /shared/ready-a 2>/dev/null && break; sleep 1
done
docker exec hop-exit-a test -f /shared/ready-a || { echo "FAIL: host-a not ready"; docker exec hop-exit-a cat /cfg/log | tail -30; exit 1; }
echo "--- host-a gateway setup log ---"
docker exec hop-exit-a grep -aE 'vpn gateway|advertis|nftables|ip_forward' /cfg/log | tail -10 || true
docker exec hop-exit-a sh -c 'nft list table inet hop_gw 2>/dev/null' || echo "(WARN: hop_gw nftables table not present)"

echo "=== starting client host-b (HOP_ACCEPT_ROUTES=1) ==="
docker run -d --name hop-exit-b "${COMMON[@]}" -e HOP_EXIT_NODE=auto "$IMG" bash -c '
  set -e; mkdir -p /cfg
  while [ ! -f /shared/invite-a ]; do sleep 1; done
  hop --config /cfg connect "$(cat /shared/invite-a)" --warren >/cfg/join.log 2>&1 || true
  hop --config /cfg host --quiet >/cfg/log 2>&1 &
  while ! grep -q "vpn: enabled" /cfg/log; do sleep 1; done
  touch /shared/ready-b
  tail -f /cfg/log
' >/dev/null

echo "=== waiting for host-b ready (max 120s) ==="
for i in $(seq 1 120); do
  docker exec hop-exit-b test -f /shared/ready-b 2>/dev/null && break; sleep 1
done
docker exec hop-exit-b test -f /shared/ready-b || { echo "FAIL: host-b not ready"; docker exec hop-exit-b cat /cfg/log | tail -30; exit 1; }

echo "=== letting netdoc sync + route acceptance + kernel route install settle (35s) ==="
sleep 35

echo "=== diagnostics ==="
echo "--- host-b installed route for $LAN_CIDR? ---"; docker exec hop-exit-b ip route | grep -E '0.0.0.0/1|128.0.0.0/1|100.64' || true
echo "--- host-b accepted-route / egress debug ---"; docker exec hop-exit-b grep -aE 'vpn route|accepted|egress' /cfg/log | tail -10 || true
echo "--- host-a is on LANNET? ---"; docker exec hop-exit-a ip -o addr show | grep 192.168.77 || true
echo "--- sanity: host-a can reach the LAN device directly ---"
docker exec hop-exit-a ping -c2 -W2 "$LAN_TARGET" >/dev/null 2>&1 && echo "host-a → $LAN_TARGET OK" || echo "WARN: host-a can't reach $LAN_TARGET"

echo "=== member-tunnel sanity: host-b → host-a vIP (isolates tunnel vs routing) ==="
VIP_A=$(docker exec hop-exit-a cat /shared/vip-a 2>/dev/null || true)
echo "host-a vIP: ${VIP_A:-<unknown>}"
if [ -n "$VIP_A" ] && docker exec hop-exit-b ping -c 3 -W 3 "$VIP_A" >/dev/null 2>&1; then
  echo "MEMBER TUNNEL OK (host-b reaches host-a over the warren) — any routed failure is the gateway/forward path"
else
  echo "MEMBER TUNNEL DOWN — the warren tunnel itself isn't up; routed traffic can't work until it is"
fi

echo "=== TEST: ping the LAN device $LAN_TARGET from host-b (via the exit node (default route)) ==="
RC=1
for attempt in $(seq 1 6); do
  if docker exec hop-exit-b ping -c 3 -W 3 "$LAN_TARGET"; then
    echo ""; echo "EXIT-NODE E2E PASSED: host-b reached a non-hop LAN device via host-a as the exit node."
    RC=0; break
  fi
  echo "  (attempt $attempt: not yet reachable; settling 8s)"; sleep 8
done

if [ "$RC" != 0 ]; then
  echo ""; echo "EXIT-NODE E2E FAILED: host-b could not reach $LAN_TARGET."
  echo "--- host-a log tail ---"; docker exec hop-exit-a cat /cfg/log | tail -40 || true
  echo "--- host-a nftables ---"; docker exec hop-exit-a nft list ruleset 2>/dev/null | tail -30 || true
  echo "--- host-a ip_forward ---"; docker exec hop-exit-a cat /proc/sys/net/ipv4/ip_forward || true
  echo "--- host-b log tail ---"; docker exec hop-exit-b cat /cfg/log | tail -40 || true
  echo "--- host-b routes ---"; docker exec hop-exit-b ip route || true
  echo "--- host-b egress (debug): does it route the packet to the gateway? ---"
  docker exec hop-exit-b grep -aE 'vpn egress|UNRESOLVED|reach DENIED|192.168.77' /cfg/log | tail -25 || true
  echo "--- host-a ingress (debug): does the packet arrive + get forwarded? ---"
  docker exec hop-exit-a grep -aE 'vpn ingress|DROP|192.168.77|no endpoint→vIP|gateway' /cfg/log | tail -25 || true
  echo "--- host-a conntrack for the target (did a flow form?) ---"
  docker exec hop-exit-a sh -c 'cat /proc/net/nf_conntrack 2>/dev/null | grep 192.168.77 | head' || true
fi
exit "$RC"
