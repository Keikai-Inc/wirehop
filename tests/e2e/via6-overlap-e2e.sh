#!/usr/bin/env bash
# 4via6 overlapping-subnet e2e (Tier 3a): a warren client whose OWN LAN is
# 192.168.1.0/24 reaches a device at 192.168.1.50 on a DIFFERENT site that ALSO
# uses 192.168.1.0/24 — via the device's 4via6 IPv6 address — and the traffic
# reaches the REMOTE device, not the local collision.
#
# Topology:
#   via6-lan     (192.168.1.50)   — plain container on SITEB_NET only (the remote
#                                    "device"; never runs hop). Reachable only by
#                                    being routed + SIIT-translated through the gw.
#   via6-gw      gateway/founder   — on NET (overlay) AND SITEB_NET (192.168.1.0/24);
#                                    advertises 192.168.1.0/24 (gateway NAT) and is
#                                    auto-assigned a 4via6 site id.
#   via6-client  client/member     — on NET only; HOP_VIA6=1 routes the via6 /64
#                                    into its TUN. It ALSO holds a LOCAL 192.168.1.50
#                                    on a dummy interface — the overlap collision.
#
# PASS = `ping -6 <via6(site, 192.168.1.50)>` from the client succeeds. Because the
# via6 /64 routes only through the tunnel → gateway → SIIT → the remote LAN, a
# reply proves the overlapping remote device was reached (the local v4 192.168.1.50
# can never answer an fd68::/64 address). The local collision is shown separately
# (`ping 192.168.1.50` hits the client's own address) to prove the overlap is real.
#
# Runs UNDER privsep (HOP_PRIVSEP_DROP). The gateway's nft/ip_forward + the client's
# v6 TUN config are privileged and delegated to the root monitor (SetupGateway /
# ConfigureTunV6). Reuses the shipped Tier-1 kernel NAT path entirely.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NET=hop-via6-net
SITEB_NET=hop-via6-siteb
IMG=hop-via6-e2e
VOL=hop-via6-shared
LAN_CIDR=192.168.1.0/24
DEVICE_IP=192.168.1.50
RESULTS="$SCRIPT_DIR/via6-results.md"

cleanup() {
    echo "--- cleanup ---"
    docker rm -f via6-gw via6-client via6-lan >/dev/null 2>&1 || true
    docker volume rm "$VOL" >/dev/null 2>&1 || true
    docker network rm "$NET" "$SITEB_NET" >/dev/null 2>&1 || true
    rm -f "$SCRIPT_DIR/hop"
}
trap cleanup EXIT

echo "=== building aarch64 linux binary ==="
AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target aarch64-unknown-linux-gnu -p hop-cli
cp "$ROOT/target/aarch64-unknown-linux-gnu/release/hop" "$SCRIPT_DIR/hop"

echo "=== building image ==="
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
docker network create --subnet "$LAN_CIDR" "$SITEB_NET" >/dev/null
docker volume create "$VOL" >/dev/null

echo "=== starting the remote device ($DEVICE_IP on SITEB_NET, no hop) ==="
docker run -d --name via6-lan --network "$SITEB_NET" --ip "$DEVICE_IP" "$IMG" sleep infinity >/dev/null

COMMON=(--network "$NET" --cap-add=NET_ADMIN --device /dev/net/tun
        --sysctl net.ipv4.ip_forward=1
        --sysctl net.ipv6.conf.all.disable_ipv6=0
        --sysctl net.ipv6.conf.all.forwarding=1
        -v "$VOL:/shared" -e RUST_LOG="${HOP_E2E_LOG:-hop=info,hop_core=info}"
        -e HOP_VPN=1 -e HOP_PRIVSEP=1 -e HOP_PRIVSEP_DROP=1 --user root)

echo "=== starting gateway via6-gw (advertises $LAN_CIDR, auto site id) ==="
docker run -d --name via6-gw "${COMMON[@]}" "$IMG" bash -c "
  set -e; mkdir -p /cfg
  hop --config /cfg lan advertise $LAN_CIDR
  hop --config /cfg host --quiet >/cfg/log 2>&1 &
  while ! grep -q 'vpn: enabled' /cfg/log; do sleep 1; done
  cp /cfg/creator_invite /shared/invite-gw
  grep -m1 'vpn: enabled' /cfg/log | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 > /shared/vip-gw
  while ! grep -q 'via6: this node.s site id' /cfg/log; do sleep 1; done
  grep -m1 'via6: this node.s site id' /cfg/log | grep -oE '[0-9]+$' > /shared/siteid-gw
  touch /shared/ready-gw
  tail -f /cfg/log
" >/dev/null

echo "=== attaching via6-gw to SITEB_NET ==="
for i in $(seq 1 30); do docker exec via6-gw true 2>/dev/null && break; sleep 1; done
docker network connect "$SITEB_NET" via6-gw

echo "=== waiting for gateway ready (max 120s) ==="
for i in $(seq 1 120); do docker exec via6-gw test -f /shared/ready-gw 2>/dev/null && break; sleep 1; done
docker exec via6-gw test -f /shared/ready-gw || { echo "FAIL: gateway not ready"; docker exec via6-gw cat /cfg/log | tail -30; exit 1; }
SID=$(docker exec via6-gw cat /shared/siteid-gw 2>/dev/null | tr -d '[:space:]')
VIP_GW=$(docker exec via6-gw cat /shared/vip-gw 2>/dev/null | tr -d '[:space:]')
echo "--- gateway site id = ${SID:-<none>}, vIP = ${VIP_GW:-<none>} ---"
[ -n "$SID" ] || { echo "FAIL: gateway has no site id"; docker exec via6-gw grep -a via6 /cfg/log | tail; exit 1; }
docker exec via6-gw ping -c2 -W2 "$DEVICE_IP" >/dev/null 2>&1 && echo "gateway → $DEVICE_IP OK (direct LAN)" || echo "WARN: gateway can't reach $DEVICE_IP"

# Compute the via6 address for (SID, 192.168.1.50):
#   fd68:6f70:7669:6136 : <site hi16> : <site lo16> : c0a8 : 0132
HI=$(printf '%04x' $(( (SID >> 16) & 0xffff )))
LO=$(printf '%04x' $(( SID & 0xffff )))
VIA6="fd68:6f70:7669:6136:${HI}:${LO}:c0a8:0132"
echo "--- via6 address for $DEVICE_IP @ site $SID = $VIA6 ---"

echo "=== starting client via6-client (HOP_VIA6=1 + local 192.168.1.50 collision) ==="
docker run -d --name via6-client "${COMMON[@]}" -e HOP_VIA6=1 "$IMG" bash -c '
  set -e; mkdir -p /cfg
  # Create the OVERLAP: the client'\''s own LAN also uses 192.168.1.0/24, with a
  # local 192.168.1.50 — the address that would collide with the remote device.
  ip link add collision0 type dummy 2>/dev/null || true
  ip addr add 192.168.1.50/24 dev collision0 2>/dev/null || true
  ip link set collision0 up 2>/dev/null || true
  while [ ! -f /shared/invite-gw ]; do sleep 1; done
  hop --config /cfg connect "$(cat /shared/invite-gw)" --warren >/cfg/join.log 2>&1 || true
  hop --config /cfg host --quiet >/cfg/log 2>&1 &
  while ! grep -q "vpn: enabled" /cfg/log; do sleep 1; done
  while ! grep -q "via6: client routing enabled" /cfg/log; do sleep 1; done
  touch /shared/ready-client
  tail -f /cfg/log
' >/dev/null

echo "=== waiting for client ready (max 120s) ==="
for i in $(seq 1 120); do docker exec via6-client test -f /shared/ready-client 2>/dev/null && break; sleep 1; done
docker exec via6-client test -f /shared/ready-client || { echo "FAIL: client not ready"; docker exec via6-client cat /cfg/log | tail -30; exit 1; }

echo "=== letting netdoc sync (site id roster + endpoints) settle (35s) ==="
sleep 35

echo "=== diagnostics ==="
echo "--- client via6 TUN config ---"; docker exec via6-client ip -6 addr show 2>/dev/null | grep -iE 'fd68|tun|utun' || true
echo "--- client via6 route ---"; docker exec via6-client ip -6 route 2>/dev/null | grep -i fd68 || true
echo "--- client LOCAL collision (192.168.1.50 is the client's own addr) ---"
docker exec via6-client ip -o addr show | grep '192.168.1.50' || true
echo "--- proving the overlap: client ping of the v4 192.168.1.50 hits LOCAL ---"
docker exec via6-client ping -c1 -W2 192.168.1.50 >/dev/null 2>&1 && echo "  client → 192.168.1.50 (v4) answers LOCALLY (collision confirmed)" || echo "  (local collision ping did not answer)"

echo "=== member-tunnel sanity: client → gateway vIP ==="
if [ -n "$VIP_GW" ] && docker exec via6-client ping -c3 -W3 "$VIP_GW" >/dev/null 2>&1; then
  echo "MEMBER TUNNEL OK (client reaches gateway over the warren)"
else
  echo "MEMBER TUNNEL DOWN — the warren tunnel isn't up; via6 can't work until it is"
fi

echo ""
echo "=== TEST: client reaches the REMOTE $DEVICE_IP via its 4via6 address ==="
echo "    ping -6 $VIA6   (routes via6 /64 → TUN → gateway → SIIT v6↔v4 → remote LAN)"
RC=1
for attempt in $(seq 1 6); do
  if docker exec via6-client ping -6 -c3 -W3 "$VIA6"; then
    echo ""; echo "4VIA6 OVERLAP E2E PASSED: client reached the remote $DEVICE_IP across overlapping subnets via 4via6."
    RC=0; break
  fi
  echo "  (attempt $attempt: not yet reachable; settling 8s)"; sleep 8
done

# Emit the results artifact (deliverable 2).
{
  echo "# 4via6 overlapping-subnet e2e"
  echo
  echo "- Date: (stamped by caller)"
  echo "- Result: $([ "$RC" = 0 ] && echo PASS || echo FAIL)"
  echo "- Overlap: client LAN and site-B LAN both \`$LAN_CIDR\`; device \`$DEVICE_IP\`"
  echo "- Gateway site id: \`$SID\`"
  echo "- via6 address tested: \`$VIA6\`"
  echo "- Local v4 collision present on client: yes (\`192.168.1.50\` on collision0)"
  echo "- Assertion: \`ping -6 $VIA6\` from the client succeeds → reached the REMOTE device"
  echo "  (the fd68::/64 via6 address can only route through the tunnel+gateway+SIIT,"
  echo "   so a reply proves disambiguation from the local collision)."
} > "$RESULTS"
echo "--- wrote $RESULTS ---"

if [ "$RC" != 0 ]; then
  echo ""; echo "4VIA6 OVERLAP E2E FAILED: client could not reach $VIA6."
  echo "--- client log (egress/via6) ---"; docker exec via6-client grep -aE 'via6|vpn egress|UNRESOLVED' /cfg/log | tail -30 || true
  echo "--- client routes (v6) ---"; docker exec via6-client ip -6 route || true
  echo "--- gateway log (via6 ingress/translate) ---"; docker exec via6-gw grep -aE 'via6|vpn ingress|gateway|DROP' /cfg/log | tail -30 || true
  echo "--- gateway nftables ---"; docker exec via6-gw nft list ruleset 2>/dev/null | tail -20 || true
  echo "--- gateway conntrack to device ---"; docker exec via6-gw sh -c 'cat /proc/net/nf_conntrack 2>/dev/null | grep 192.168.1.50 | head' || true
fi
exit "$RC"
