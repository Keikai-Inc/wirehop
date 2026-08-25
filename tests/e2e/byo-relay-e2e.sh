#!/usr/bin/env bash
# BYO relay e2e — `hop host --relay` serves a MEMBER-ONLY iroh relay (roadmap G3).
#
# Proves "two members connect via the BYO relay only". All three nodes share one
# network so members JOIN over a direct path (a joiner isn't a member yet, so the
# member-only relay would deny it — joins must use a direct/fallback path; this is
# the documented caveat). Once joined, we SEVER the direct alice↔bob path with a
# blackhole route while leaving the relay host reachable, so the only remaining
# path for alice⇄bob traffic is relayhost's member-only BYO relay.
#
#     alice ──┐        ┌── bob          after join: blackhole alice↔bob direct,
#             ├ net ───┤                keep alice→relayhost + bob→relayhost open
#        relayhost (--relay)            ⇒ alice⇄bob can ONLY go via the BYO relay
#
# Asserts: (1) the relay comes up member-only; (2) after severing, there is no
# direct alice↔bob path; (3) alice⇄bob still route (so it WAS the relay);
# (4) a non-member is denied (deterministic relay.rs gating unit test).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NET=hop-byo-relay-net
IMG=hop-byo-relay
VOL=hop-byo-relay-shared
RELAY=hop-byo-relayhost
ALICE=hop-byo-alice
BOB=hop-byo-bob

cleanup() {
    if [ "${KEEP:-0}" = "1" ]; then
        echo "--- KEEP=1: leaving containers/networks up for inspection ---"
        echo "    docker exec $RELAY cat /cfg/log   # relay/founder"
        echo "    docker exec $ALICE cat /cfg/log   # alice"
        echo "    docker exec $BOB cat /cfg/log     # bob"
        rm -f "$SCRIPT_DIR/hop"; return
    fi
    echo "--- cleanup ---"
    docker rm -f "$RELAY" "$ALICE" "$BOB" >/dev/null 2>&1 || true
    docker volume rm "$VOL" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -f "$SCRIPT_DIR/hop"
}
trap cleanup EXIT

echo "=== building aarch64 linux binary (REBUILD=${REBUILD:-0}) ==="
if [ "${REBUILD:-0}" = "1" ] || [ ! -x "$ROOT/target/aarch64-unknown-linux-gnu/release/hop" ]; then
  AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target aarch64-unknown-linux-gnu -p hop-cli
fi
cp "$ROOT/target/aarch64-unknown-linux-gnu/release/hop" "$SCRIPT_DIR/hop"

echo "=== building image ==="
docker build -t "$IMG" -f - "$SCRIPT_DIR" >/dev/null <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates jq iputils-ping iproute2 dnsutils && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash hop
COPY hop /usr/local/bin/hop
RUN chmod +x /usr/local/bin/hop
DOCKERFILE

docker network create "$NET" >/dev/null
docker volume create "$VOL" >/dev/null

# Every node points its home relay at the BYO relay; the relay refreshes its
# admit-set fast so a freshly-joined member becomes admittable within ~3s.
COMMON=(--network "$NET" --cap-add=NET_ADMIN --device /dev/net/tun -v "$VOL:/shared"
        -e RUST_LOG="${HOP_E2E_LOG:-hop=info,hop_core=info,iroh_relay=warn}" -e HOP_VPN=1
        -e HOP_PRIVSEP=1 -e HOP_PRIVSEP_DROP=1
        -e HOP_RELAY_URL="http://$RELAY:3340"
        -e HOP_RELAY_REFRESH_SECS=3 --user root)

echo "=== starting relayhost (founder + BYO relay) ==="
docker run -d --name "$RELAY" "${COMMON[@]}" "$IMG" bash -c '
  set -e; mkdir -p /cfg
  hop --config /cfg host --quiet --relay --relay-port 3340 >/cfg/log 2>&1 &
  while ! grep -q "vpn: enabled" /cfg/log; do sleep 1; done
  # creator_invite is SINGLE-USE; we need two joiners, so mint a REUSABLE node-tier
  # admin invite bound to the unprivileged hop user (root is refused).
  hop --config /cfg invite --tier node --role admin --user hop --max-uses 5 >/cfg/mint.log 2>&1 || true
  grep -aoE "[A-Za-z0-9_-]{60,}" /cfg/mint.log | head -1 > /shared/invite
  grep -m1 "vpn: enabled" /cfg/log | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1 > /shared/vip-relay
  touch /shared/ready-relay
  tail -f /cfg/log
' >/dev/null

echo "=== waiting for relayhost ready (max 120s) ==="
for i in $(seq 1 120); do
  docker exec "$RELAY" test -f /shared/ready-relay 2>/dev/null && break
  sleep 1
done
docker exec "$RELAY" test -f /shared/ready-relay || { echo "FAIL: relayhost not ready"; docker exec "$RELAY" cat /cfg/log | tail -30; exit 1; }
if docker exec "$RELAY" grep -q "member-only BYO relay up" /cfg/log; then
  echo "RELAY-UP OK: $(docker exec "$RELAY" grep -m1 'member-only BYO relay up' /cfg/log | sed -E 's/\x1b\[[0-9;]*m//g')"
else
  echo "FAIL: relayhost did not start the BYO relay"; docker exec "$RELAY" grep -i relay /cfg/log | tail; exit 1
fi
VIP_RELAY=$(docker exec "$RELAY" cat /shared/vip-relay)
INVITE_LEN=$(docker exec "$RELAY" sh -c "wc -c < /shared/invite" 2>/dev/null | tr -d ' ')
echo "relayhost vIP: $VIP_RELAY  |  minted invite length: ${INVITE_LEN:-0}"
[ "${INVITE_LEN:-0}" -gt 60 ] || { echo "FAIL: relayhost did not mint a usable invite"; docker exec "$RELAY" cat /cfg/mint.log | tail; exit 1; }

start_member() { # <container> <tag> — joins over the shared net (direct path)
  docker run -d --name "$1" "${COMMON[@]}" "$IMG" bash -c '
    set -e; mkdir -p /cfg; TAG="$0"
    while [ ! -f /shared/invite ]; do sleep 1; done
    hop --config /cfg connect "$(cat /shared/invite)" --warren >/cfg/join.log 2>&1 || true
    hop --config /cfg host --quiet >/cfg/log 2>&1 &
    while ! grep -q "vpn: enabled" /cfg/log; do sleep 1; done
    grep -m1 "vpn: enabled" /cfg/log | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1 > "/shared/vip-$TAG"
    touch "/shared/ready-$TAG"
    tail -f /cfg/log
  ' "$2" >/dev/null
}
wait_member() { # <container> <tag>
  for i in $(seq 1 120); do docker exec "$1" test -f "/shared/ready-$2" 2>/dev/null && return 0; sleep 1; done
  echo "FAIL: $1 not ready"; docker exec "$1" cat /cfg/join.log 2>/dev/null | tail -10; docker exec "$1" cat /cfg/log 2>/dev/null | tail -25; return 1
}

echo "=== starting alice ==="; start_member "$ALICE" alice; wait_member "$ALICE" alice
VIP_ALICE=$(docker exec "$ALICE" cat /shared/vip-alice); echo "alice vIP: $VIP_ALICE"
echo "=== starting bob ===";   start_member "$BOB" bob;     wait_member "$BOB" bob
VIP_BOB=$(docker exec "$BOB" cat /shared/vip-bob); echo "bob vIP: $VIP_BOB"

RC=0
docker_ip() { docker exec "$1" sh -c "ip -4 -o addr show | grep -oE '172\.[0-9]+\.[0-9]+\.[0-9]+' | head -1"; }
IP_ALICE=$(docker_ip "$ALICE"); IP_BOB=$(docker_ip "$BOB")
echo "alice docker IP: $IP_ALICE  |  bob docker IP: $IP_BOB"

echo "=== SEVER the direct alice↔bob path (blackhole each other; keep relayhost) ==="
docker exec "$ALICE" ip route add blackhole "$IP_BOB"   >/dev/null 2>&1 || true
docker exec "$BOB"   ip route add blackhole "$IP_ALICE" >/dev/null 2>&1 || true

echo "=== PROOF 1: no direct alice↔bob path remains ==="
if docker exec "$ALICE" ping -c1 -W2 "$IP_BOB" >/dev/null 2>&1; then
  echo "FAIL: alice still has a DIRECT path to bob — blackhole did not take."; RC=1
else
  echo "NO-DIRECT-PATH OK: alice cannot reach bob directly (blackholed)."
fi

echo "=== PROOF 2: alice ⇄ bob route over the BYO relay (vIP, settle up to 120s) ==="
settle_ping() { # <from> <vip>
  for attempt in $(seq 1 20); do
    docker exec "$1" ping -c2 -W3 "$2" >/dev/null 2>&1 && { echo ok; return 0; }
    sleep 6
  done
  echo timeout; return 1
}
if [ "$(settle_ping "$ALICE" "$VIP_BOB")" = ok ]; then
  echo "RELAY-ROUTING OK: alice → bob ($VIP_BOB) over the BYO relay."
else
  echo "FAIL: alice could not reach bob over the BYO relay."
  echo "--- alice egress ---"; docker exec "$ALICE" sh -c "grep -aE 'vpn|relay|dial|reach|egress|Connecting' /cfg/log | tail -25" | sed -E 's/\x1b\[[0-9;]*m//g' || true
  RC=1
fi
if [ "$RC" = 0 ] && [ "$(settle_ping "$BOB" "$VIP_ALICE")" = ok ]; then
  echo "RELAY-ROUTING OK: bob → alice ($VIP_ALICE) over the BYO relay."
elif [ "$RC" = 0 ]; then
  echo "FAIL: bob could not reach alice over the BYO relay."; RC=1
fi

echo "=== PROOF 3: member-gating is enforced (deterministic unit test) ==="
if cargo test -p hop-core --lib net::relay::tests::member_gating_admits_members_denies_strangers \
     >/tmp/byo-gate-test.log 2>&1; then
  echo "GATING OK: member admitted, stranger denied ($(grep -oE '[0-9]+ passed' /tmp/byo-gate-test.log | head -1))."
else
  echo "FAIL: member-gating unit test failed."; tail -20 /tmp/byo-gate-test.log; RC=1
fi

if [ "$RC" = 0 ]; then
  echo ""; echo "BYO RELAY E2E PASSED: members connect via the member-only BYO relay only."
else
  echo ""; echo "BYO RELAY E2E FAILED."
fi
exit $RC
