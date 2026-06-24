#!/usr/bin/env bash
# Genuine 2-machine macOS gateway e2e using Tart VMs (Apple Silicon host).
#
# The Linux subnet-routing e2e (subnet-routing-e2e.sh) runs in Docker and cannot
# exercise the macOS pf gateway. This harness boots two real macOS VMs and drives
# the full warren LAN-bridging data plane on macOS:
#
#   hop-gw      founder/gateway — advertises routes, sets up pf NAT + ip.forwarding
#   hop-client  member — HOP_ACCEPT_ROUTES, installs the routes, forwards via gw
#
# It asserts three things, each isolating a layer:
#   1. member tunnel  — client pings the gateway's vIP over the warren
#   2. subnet route   — client reaches 10.99.0.1 (a loopback alias ON the gateway),
#                       a destination it has NO route to except via the gateway
#   3. SNAT/forward   — client reaches 8.8.8.8 through the gateway's pf SNAT onto
#                       its LAN egress (proves kernel forward + pf NAT, not just
#                       local delivery); verified by the pf nat counter incrementing
#
# WHY BRIDGED, NOT softnet/shared-NAT: iroh's relay (relay.keik.ai) does NOT come
# online from Tart's shared-NAT or un-sudo'd softnet networks, so the warren can't
# federate there. Both VMs must be --net-bridged onto the host LAN (where they
# behave like the host, which federates fine). softnet *would* give isolation but
# needs passwordless sudo for the softnet helper (not assumed here).
#
# WHY 8.8.8.8 FOR SNAT (not a LAN device like a Tablo): a bridged client shares the
# host LAN (e.g. 192.168.1.0/24), so a *remote* 192.168.1.x is the subnet-OVERLAP
# case — macOS sources from en0, pf only SNATs 100.64/10, and it fails. That's the
# documented limitation 4via6 solves, not a gateway bug. 8.8.8.8 is off every local
# subnet, so the client sources from its vIP and the gateway SNATs cleanly.
#
# PITFALL baked in: never advertise the host's own IP (the SSH source) — the client
# tunnels its replies to you and you lose management access. And advertised routes
# are CUMULATIVE in the warren doc (removing from routes.json doesn't withdraw), so
# this harness always starts from a FRESH warren (wiped gateway config).
#
# Prereqs: tart, a macOS base image with admin/admin + Remote Login (e.g.
# ghcr.io/cirruslabs/macos-sequoia-base), and a release macOS binary at
# target/release/hop (cargo build --release -p hop-cli). Run from anywhere.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

BASE_IMG="${HOP_E2E_BASE_IMG:-ghcr.io/cirruslabs/macos-sequoia-base:latest}"
BRIDGE_IFACE="${HOP_E2E_BRIDGE:-en0}"
GW_VM="${HOP_E2E_GW_VM:-hop-gw}"
CL_VM="${HOP_E2E_CL_VM:-hop-client}"
BIN="${HOP_E2E_BIN:-$ROOT/target/release/hop}"
KEY="${HOP_E2E_KEY:-/tmp/hop-e2e-key}"
LOOPBACK_TARGET=10.99.0.1
LOOPBACK_CIDR=10.99.0.0/24
SNAT_TARGET=8.8.8.8
SNAT_CIDR=8.8.8.8/32
SSHOPTS=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=8)
HOPENV="HOP_VPN=1 HOP_PRIVSEP=1 HOP_PRIVSEP_DROP=1 RUST_LOG=hop=info,hop_core=info"

say() { echo "=== $* ==="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# Resolve a bridged VM's LAN IP from its configured MAC via the host arp table.
vm_ip() {
  local vm="$1" mac norm
  mac=$(python3 -c "import json;print(json.load(open('$HOME/.tart/vms/$vm/config.json'))['macAddress'])") || return 1
  norm=$(echo "$mac" | python3 -c "import sys;print(':'.join(format(int(x,16),'x') for x in sys.stdin.read().strip().split(':')))")
  ping -c1 -t1 255.255.255.255 >/dev/null 2>&1 || true
  arp -a -n 2>/dev/null | grep -iw "$norm" | grep -v bridge100 | grep -oE '([0-9]+\.){3}[0-9]+' | head -1
}

vssh() { ssh "${SSHOPTS[@]}" "admin@$1" "$2" 2>&1 | grep -vE 'Warning: Permanently'; }

# Install our pubkey into a freshly-cloned VM over password SSH (admin/admin). The
# single-quoted expect reading a base64'd key from a file is the only reliable form
# — bash double-quote expansion mangles `send "admin\r"`.
install_key() {
  local ip="$1"
  [ -f "$KEY" ] || ssh-keygen -t ed25519 -N '' -f "$KEY" -q
  base64 -i "$KEY.pub" | tr -d '\n' > /tmp/hop-e2e-key.b64
  expect -c '
    set timeout 40
    set b64 [string trim [exec cat /tmp/hop-e2e-key.b64]]
    spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@'"$ip"' "mkdir -p .ssh; echo $b64 | base64 -D >> .ssh/authorized_keys; chmod 700 .ssh; chmod 600 .ssh/authorized_keys; echo INSTALLED_OK"
    expect { "assword:" { send "admin\r"; exp_continue } "INSTALLED_OK" {} timeout { exit 2 } }
    expect eof' >/dev/null 2>&1
}

boot_bridged() {
  local vm="$1"
  tart stop "$vm" >/dev/null 2>&1 || true; sleep 2
  nohup tart run "$vm" --no-graphics --net-bridged="$BRIDGE_IFACE" >"/tmp/$vm-run.log" 2>&1 &
  sleep 30
}

cleanup() {
  say "cleanup (stopping VMs; pass HOP_E2E_KEEP=1 to leave them running)"
  [ "${HOP_E2E_KEEP:-0}" = 1 ] && return
  tart stop "$GW_VM" >/dev/null 2>&1 || true
  tart stop "$CL_VM" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v tart >/dev/null || fail "tart not installed"
[ -x "$BIN" ] || fail "macOS binary not found at $BIN (cargo build --release -p hop-cli)"

# --- provision VMs ---------------------------------------------------------
say "cloning VMs from $BASE_IMG (if absent)"
tart list 2>/dev/null | grep -qw "$GW_VM" || tart clone "$BASE_IMG" "$GW_VM"
tart list 2>/dev/null | grep -qw "$CL_VM" || tart clone "$GW_VM" "$CL_VM"

say "booting both VMs bridged on $BRIDGE_IFACE"
boot_bridged "$GW_VM"; boot_bridged "$CL_VM"
GW_IP=$(vm_ip "$GW_VM"); CL_IP=$(vm_ip "$CL_VM")
[ -n "$GW_IP" ] && [ -n "$CL_IP" ] || fail "could not resolve VM IPs (gw=$GW_IP cl=$CL_IP)"
echo "gateway=$GW_IP  client=$CL_IP"

say "ensuring keyless SSH + binary on both"
for ip in "$GW_IP" "$CL_IP"; do
  vssh "$ip" 'echo ok' | grep -q ok || install_key "$ip"
  vssh "$ip" 'echo ok' | grep -q ok || fail "keyless SSH to $ip failed"
  scp "${SSHOPTS[@]}" "$BIN" "admin@$ip:/tmp/hop" >/dev/null 2>&1
  vssh "$ip" 'sudo install -m 0755 /tmp/hop /usr/local/bin/hop && /usr/local/bin/hop --version'
done

# --- gateway: fresh warren, advertise loopback + SNAT routes ---------------
say "gateway: fresh warren advertising $LOOPBACK_CIDR + $SNAT_CIDR"
vssh "$GW_IP" "
  sudo pkill -f 'hop .*host' 2>/dev/null; sleep 3
  ifconfig lo0 | grep -q ${LOOPBACK_TARGET} || sudo ifconfig lo0 alias ${LOOPBACK_TARGET} 255.255.255.255
  sudo rm -rf /tmp/hopcfg; sudo mkdir -p /tmp/hopcfg
  sudo /usr/local/bin/hop --config /tmp/hopcfg lan advertise ${LOOPBACK_CIDR} >/dev/null 2>&1
  sudo /usr/local/bin/hop --config /tmp/hopcfg lan advertise ${SNAT_CIDR} >/dev/null 2>&1
  sudo bash -c '${HOPENV} nohup /usr/local/bin/hop --config /tmp/hopcfg host --quiet >/tmp/hop.log 2>&1 &'
"
sleep 28
GW_VIP=$(vssh "$GW_IP" 'sudo grep -aoE "virtual IP 100[0-9.]+" /tmp/hop.log | head -1 | grep -oE "100[0-9.]+"')
vssh "$GW_IP" 'sudo grep -aiE "forwarding.*live" /tmp/hop.log | sed -E "s/\x1b\[[0-9;]*m//g" | tail -1'
echo "gateway vIP: $GW_VIP"
vssh "$GW_IP" 'sudo pfctl -s nat 2>/dev/null | grep -q "com.hop" && echo "pf: com.hop anchor referenced from main ruleset OK" || echo "pf: com.hop NOT referenced (bug)"'

# --- client: join + accept routes ------------------------------------------
say "client: join warren + accept routes"
# The invite token is the single long base64 line — grab the longest output line
# (portable; macOS BSD grep rejects an open-ended {300,} repetition).
vssh "$GW_IP" 'sudo /usr/local/bin/hop --config /tmp/hopcfg invite --max-uses 10 --tier node --expiry 3600 --user admin 2>&1' \
  | awk '{ if (length($0) > m) { m = length($0); s = $0 } } END { print s }' > /tmp/hop-invite.txt
[ -s /tmp/hop-invite.txt ] || fail "could not mint invite"
scp "${SSHOPTS[@]}" /tmp/hop-invite.txt "admin@$CL_IP:/tmp/invite.txt" >/dev/null 2>&1
vssh "$CL_IP" "
  sudo pkill -f 'hop .*host' 2>/dev/null; sleep 2
  sudo rm -rf /Users/admin/hopcfg; sudo mkdir -p /Users/admin/hopcfg
  sudo /usr/local/bin/hop --config /Users/admin/hopcfg connect \"\$(cat /tmp/invite.txt)\" --warren --yes 2>&1 | grep -iE 'authorized|reject' | head -1
  sudo bash -c 'HOP_ACCEPT_ROUTES=1 ${HOPENV} nohup /usr/local/bin/hop --config /Users/admin/hopcfg host --quiet >/tmp/hop.log 2>&1 &'
"
# --- gate on warren convergence -------------------------------------------
# The client must reconcile the gateway as a peer AND install the advertised
# routes before any gateway test is meaningful. This is the flaky step (warren
# netdoc sync / the endpoint-identity-collision relay pruning, a known separate
# issue) — poll generously and report a convergence failure DISTINCTLY from a
# gateway-forwarding failure, so a red here isn't misread as a pf/route bug.
say "waiting for warren convergence (member tunnel + route install, up to ~120s)"
converged=0
for i in $(seq 1 15); do
  if vssh "$CL_IP" "ping -c2 -t3 $GW_VIP" | grep -q '0.0% packet loss' \
     && vssh "$CL_IP" "netstat -rn -f inet | grep -q '10.99'"; then
    converged=1; echo "converged after ~$((i*8))s"; break
  fi
  sleep 8
done
if [ "$converged" != 1 ]; then
  echo "INCONCLUSIVE: warren did not converge (client reconciled no peer / no routes)."
  echo "  This is warren federation flakiness (netdoc sync / endpoint-collision), NOT"
  echo "  the macOS gateway path. Client peer state:"
  vssh "$CL_IP" "sudo grep -aoE 'reconciled [0-9]+ peer' /tmp/hop.log | tail -1; netstat -rn -f inet | grep utun"
  exit 2
fi

# --- assertions (warren is converged; now the gateway path is under test) ---
RC=0
say "TEST 1: member tunnel — client → gateway vIP ($GW_VIP)"
if vssh "$CL_IP" "ping -c3 -t4 $GW_VIP" | grep -q '0.0% packet loss'; then
  echo "PASS: member tunnel up"
else echo "FAIL: member tunnel down"; RC=1; fi

say "TEST 2: subnet route — client → $LOOPBACK_TARGET (synthetic; only reachable via gateway)"
vssh "$CL_IP" "route -n get $LOOPBACK_TARGET 2>/dev/null | grep -qE 'interface: utun'" \
  || { echo "FAIL: $LOOPBACK_CIDR route not installed on client"; RC=1; }
if vssh "$CL_IP" "ping -c3 -t4 $LOOPBACK_TARGET" | grep -q '0.0% packet loss'; then
  echo "PASS: subnet route forwards to a gateway-local address"
else echo "FAIL: subnet route"; RC=1; fi

# SNAT test: a BRIDGED client can reach 8.8.8.8 directly, so reachability alone is
# not proof. Require (a) the /32 routed via utun, and (b) the gateway's com.hop nat
# counter to INCREMENT during the ping — that is the proof it traversed the gateway.
say "TEST 3: SNAT/forward — client → $SNAT_TARGET MUST traverse the gateway pf NAT"
if ! vssh "$CL_IP" "route -n get $SNAT_TARGET 2>/dev/null | grep -qE 'interface: utun'"; then
  echo "FAIL: $SNAT_CIDR not routed via utun on the client (would be a direct, non-gateway reach)"; RC=1
else
  before=$(vssh "$GW_IP" 'sudo pfctl -a com.hop -s nat -v 2>/dev/null | grep -oE "Packets: [0-9]+" | grep -oE "[0-9]+" | head -1'); before=${before:-0}
  ok=$(vssh "$CL_IP" "ping -c4 -t5 $SNAT_TARGET" | grep -c '0.0% packet loss' || true)
  after=$(vssh "$GW_IP" 'sudo pfctl -a com.hop -s nat -v 2>/dev/null | grep -oE "Packets: [0-9]+" | grep -oE "[0-9]+" | head -1'); after=${after:-0}
  if [ "$ok" = 1 ] && [ "$after" -gt "$before" ]; then
    echo "PASS: SNAT to external network via gateway (com.hop nat packets $before → $after)"
  else
    echo "FAIL: SNAT/forward — reachable=$ok, nat packets $before → $after (no increment ⇒ not via gateway)"; RC=1
  fi
fi

echo
[ "$RC" = 0 ] && echo "MACOS GATEWAY E2E PASSED" || echo "MACOS GATEWAY E2E FAILED"
exit "$RC"
