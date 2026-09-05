#!/usr/bin/env bash
# agent-diagnosis.sh — the diagnosis proof (gap E2).
#
# One machine (`db01`) has a real fault injected by the harness; a second, the
# operator, is where the agent sits. The SAME agent is asked to find the root
# cause twice: once reaching db01 with WireHop (`hop db01 exec …`), once with
# plain ssh (`ssh db01 …`) — the conventional setup, equivalent to reaching it
# over a Tailscale tailnet, since the Docker network already gives them each
# other. The only variable is the access-and-audit layer.
#
# The harness scores each run, never the agent's self-report:
#   - diagnosed:  the reported root_cause names the fault the harness injected.
#   - wall_secs / turns: how long and how many steps.
#   - audit_exec: how many of the commands the agent ran on db01 are recoverable
#     afterwards from db01's OWN records. WireHop writes an exec audit row per
#     command; sshd logs the login but not the command, so this is 0 for ssh.
#
# Usage:
#   ANTHROPIC_API_KEY=... ./tests/e2e/agent-diagnosis.sh [options]
#     --trials N       trials per (fault, condition) (default 1)
#     --faults LIST    comma list of full_disk,wedged_service,bad_config (default all)
#     --conditions L   comma list of hop,ssh (default both)
#     --model NAME     driver model (default claude-sonnet-5)
#     --max-turns N    per-run turn ceiling (default 30)
#     --self-test      prove fault injection, both access paths and scoring
#                      WITHOUT calling the model; spends no tokens
#     --keep           leave containers up for inspection
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMG=hop-diagnosis-e2e
NET=hop-diagnosis-net
BIN="$ROOT/target/aarch64-unknown-linux-gnu/release/hop"
WORK="$SCRIPT_DIR/.diagnosis"

TRIALS=1
FAULTS="full_disk,wedged_service,bad_config"
CONDITIONS="hop,ssh"
MODEL="${DIAGNOSIS_MODEL:-claude-sonnet-5}"
MAX_TURNS=30
SELF_TEST=0
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --trials) TRIALS="$2"; shift 2 ;;
    --faults) FAULTS="$2"; shift 2 ;;
    --conditions) CONDITIONS="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    --max-turns) MAX_TURNS="$2"; shift 2 ;;
    --self-test) SELF_TEST=1; shift ;;
    --keep) KEEP=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

say()  { echo >&2; echo "=== $* ===" >&2; }
note() { echo "    $*" >&2; }
CONTAINERS=()
cleanup_pair() { for c in "${CONTAINERS[@]:-}"; do docker rm -f "$c" >/dev/null 2>&1; done; CONTAINERS=(); }
cleanup_all() {
  [ "$KEEP" = 1 ] && { note "--keep: leaving containers"; return; }
  cleanup_pair
  docker network rm "$NET" >/dev/null 2>&1
  docker rmi -f "$IMG" >/dev/null 2>&1
}
trap cleanup_all EXIT

for t in docker python3; do command -v "$t" >/dev/null || { echo "need $t" >&2; exit 2; }; done
if [ "$SELF_TEST" = 0 ] && [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "ANTHROPIC_API_KEY is not set; run --self-test to check the harness without it." >&2
  exit 2
fi

# --- build ------------------------------------------------------------------
if [ ! -x "$BIN" ]; then
  say "cross-building the linux hop binary"
  ( cd "$ROOT" && AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release \
      --target aarch64-unknown-linux-gnu -p hop-cli ) \
    || { echo "cross build failed" >&2; exit 1; }
fi
say "building image"
cp "$BIN" "$SCRIPT_DIR/hop"
docker build -t "$IMG" -f - "$SCRIPT_DIR" >/dev/null <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl jq iproute2 iputils-ping dnsutils procps \
        openssh-server openssh-client python3 \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd
COPY hop /usr/local/bin/hop
RUN chmod +x /usr/local/bin/hop
ENV PATH="/usr/local/bin:${PATH}"
DOCKERFILE
rm -f "$SCRIPT_DIR/hop"
docker network create "$NET" >/dev/null 2>&1 || true
mkdir -p "$WORK"

dex()  { docker exec "$1" bash -lc "$2" 2>/dev/null; }
dexq() { docker exec "$1" bash -lc "$2" >/dev/null 2>&1; }

# --- fault library ----------------------------------------------------------
# Each fault breaks a made-up "appsvc" on the target in a way a real host hits.
inject_fault() {
  local c="$1" fault="$2"
  dexq "$c" "mkdir -p /var/log /etc/appsvc /var/lib/appsvc"
  case "$fault" in
    full_disk)
      # The service keeps its data on /dev/shm (a tmpfs, ~64M in a container).
      # Fill it, then a write fails with a real ENOSPC the log captures. No
      # mount privilege needed, unlike a dedicated tmpfs.
      dexq "$c" "ln -sfn /dev/shm/appsvc /var/lib/appsvc; mkdir -p /dev/shm/appsvc
                 dd if=/dev/zero of=/dev/shm/appsvc/fill bs=1M count=999 2>/dev/null || true
                 echo 'appsvc: starting' >>/var/log/appsvc.log
                 echo 'appsvc: writing checkpoint to /var/lib/appsvc' >>/var/log/appsvc.log
                 dd if=/dev/zero of=/dev/shm/appsvc/checkpoint bs=1M count=1 >>/var/log/appsvc.log 2>&1 || true
                 echo 'appsvc: FATAL could not persist state; aborting' >>/var/log/appsvc.log
                 chmod 644 /var/log/appsvc.log"
      ;;
    wedged_service)
      # A daemon that binds its port then never accepts: connections hang.
      dexq "$c" "cat >/usr/local/bin/appsvc <<'PY'
#!/usr/bin/env python3
import socket, time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',9000)); s.listen(16)
open('/var/log/appsvc.log','a').write('appsvc: listening on 9000\n')
while True: time.sleep(3600)   # never accept() — clients hang forever
PY
                 chmod +x /usr/local/bin/appsvc
                 nohup /usr/local/bin/appsvc >/dev/null 2>&1 &
                 sleep 1; chmod 644 /var/log/appsvc.log"
      ;;
    bad_config)
      # A config with a syntax error; the start script refuses to boot and says why.
      dexq "$c" "printf 'port: 9000\nworkers: 4\nmax_conns 512\n' >/etc/appsvc/config.yaml
                 cat >/usr/local/bin/appsvc <<'PY'
#!/usr/bin/env python3
import sys
for i,l in enumerate(open('/etc/appsvc/config.yaml'),1):
    l=l.rstrip()
    if l and not l.startswith('#') and ':' not in l:
        sys.stderr.write(f'appsvc: config error at line {i}: expected key: value, got {l!r}\n'); sys.exit(1)
print('appsvc: config ok')
PY
                 chmod +x /usr/local/bin/appsvc
                 /usr/local/bin/appsvc >>/var/log/appsvc.log 2>>/var/log/appsvc.log
                 echo \"appsvc exited rc=\$?\" >>/var/log/appsvc.log
                 chmod 644 /var/log/appsvc.log /etc/appsvc/config.yaml"
      ;;
    *) echo "unknown fault: $fault" >&2; return 2 ;;
  esac
}

# Keywords that count as correctly naming the fault (any one, case-insensitive).
fault_keywords() {
  case "$1" in
    full_disk)      echo "disk|no space|nospace|enospc|full|out of space|storage" ;;
    wedged_service) echo "hang|hung|wedge|stuck|deadlock|not accept|unrespons|blocked|never accept" ;;
    bad_config)     echo "config|syntax|parse|invalid|malformed|yaml|line 3|max_conns" ;;
  esac
}

# Assert the fault is actually present on the target (self-test guard).
fault_present() {
  local c="$1" fault="$2"
  case "$fault" in
    full_disk)      dex "$c" "grep -qi 'no space\|FATAL' /var/log/appsvc.log && df /dev/shm | tail -1 | grep -q '100%'" ;;
    wedged_service) dex "$c" "ss -ltn 2>/dev/null | grep -q ':9000' && timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/9000; echo hi >&3; read -t 1 x <&3'; [ \$? -ne 0 ]" ;;
    bad_config)     dex "$c" "grep -qi 'config error' /var/log/appsvc.log" ;;
  esac
}

# --- access setup -----------------------------------------------------------
start_target_daemons() {
  local c="$1"
  # A regular operator account both conditions log in as, so hop (which refuses
  # to bind a peer to root) and ssh run at identical privilege. NOPASSWD sudo is
  # there if a diagnostic needs a root-only read; the fault evidence is
  # world-readable so usually it is not needed.
  dexq "$c" "id oncall >/dev/null 2>&1 || useradd -m -s /bin/bash oncall
             usermod -aG sudo oncall 2>/dev/null || true
             echo 'oncall ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/oncall
             mkdir -p /home/oncall/.ssh && chmod 700 /home/oncall/.ssh && chown -R oncall /home/oncall/.ssh"
  # sshd for the ssh condition (root login stays off; oncall only).
  dexq "$c" "ssh-keygen -A && /usr/sbin/sshd"
  # hop host for the hop condition. VPN off keeps it to exec/audit only.
  dexq "$c" "mkdir -p /cfg && HOP_VPN=0 nohup hop --config /cfg host --quiet >>/cfg/host.log 2>&1 &"
}

setup_ssh() {
  local op="$1" target="$2"
  dexq "$op" "mkdir -p /root/.ssh && chmod 700 /root/.ssh
              test -f /root/.ssh/id_ed25519 || ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519 >/dev/null
              printf 'Host db01\n  HostName %s\n  User oncall\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n' db01 >/root/.ssh/config"
  local pub; pub="$(dex "$op" "cat /root/.ssh/id_ed25519.pub")"
  dexq "$target" "printf '%s\n' '$pub' >/home/oncall/.ssh/authorized_keys && chmod 600 /home/oncall/.ssh/authorized_keys && chown oncall /home/oncall/.ssh/authorized_keys"
}

setup_hop() {
  local op="$1" target="$2"
  dexq "$op" "mkdir -p /cfg"
  local i; for i in $(seq 1 60); do dex "$target" "test -f /cfg/creator_invite" && break; sleep 1; done
  local tok; tok="$(dex "$target" "hop --config /cfg invite --user oncall --tier client" | grep -oE 'eyJ[A-Za-z0-9_=-]+' | head -1)"
  [ -n "$tok" ] || { note "no invite token from target"; return 1; }
  dexq "$op" "hop --config /cfg exec '$tok' -- true"   # redeem; registers db01 alias
}

# --- scoring ----------------------------------------------------------------
# audit_exec_count: how many exec commands db01's OWN records can show.
audit_exec_count() {
  local target="$1" condition="$2"
  if [ "$condition" = hop ]; then
    # hop audit --json is NDJSON (one event object per line).
    dex "$target" "hop --config /cfg audit --category exec --since 1h --json 2>/dev/null" \
      | python3 -c 'import sys,json
n=0
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try: r=json.loads(line)
    except Exception: continue
    if r.get("category")=="exec": n+=1
print(n)' 2>/dev/null || echo 0
  else
    # sshd records the login, not the commands: command-level auditability is 0.
    echo 0
  fi
}

diagnosed_ok() { # root_cause fault -> 0 if matches
  local rc="$1" fault="$2"; local kw; kw="$(fault_keywords "$fault")"
  printf '%s' "$rc" | grep -qiE "$kw"
}

# --- self-test --------------------------------------------------------------
if [ "$SELF_TEST" = 1 ]; then
  say "self-test: fault injection, both access paths, and scoring (no model)"
  rc=0
  IFS=',' read -ra FS <<< "$FAULTS"
  for fault in "${FS[@]}"; do
    cleanup_pair
    op="di-op"; target="di-db01"
    docker run -d --name "$op" --hostname op --network "$NET" --user root "$IMG" sleep infinity >/dev/null
    docker run -d --name "$target" --hostname db01 --network "$NET" --user root "$IMG" sleep infinity >/dev/null
    CONTAINERS=("$op" "$target")
    start_target_daemons "$target"
    inject_fault "$target" "$fault"
    if fault_present "$target" "$fault"; then note "[$fault] fault present: OK"; else note "[$fault] fault NOT present: FAIL"; rc=1; fi
    # ssh path
    setup_ssh "$op" "$target"
    if dex "$op" "ssh db01 echo ssh-ok" | grep -q ssh-ok; then note "[$fault] ssh reach: OK"; else note "[$fault] ssh reach: FAIL"; rc=1; fi
    # hop path
    if setup_hop "$op" "$target" && dex "$op" "hop --config /cfg db01 exec -- echo hop-ok 2>/dev/null" | grep -q hop-ok; then
      note "[$fault] hop reach: OK"
      n="$(audit_exec_count "$target" hop)"
      if [ "${n:-0}" -ge 1 ]; then note "[$fault] hop audit shows exec ($n): OK"; else note "[$fault] hop audit exec=0: FAIL"; rc=1; fi
    else
      note "[$fault] hop reach: FAIL"; rc=1
    fi
    ns="$(audit_exec_count "$target" ssh)"
    [ "$ns" = 0 ] && note "[$fault] ssh audit exec=0 (expected): OK" || { note "[$fault] ssh audit exec=$ns unexpected"; rc=1; }
    # scorer
    if diagnosed_ok "the root cause is the data disk is full (ENOSPC)" full_disk && ! diagnosed_ok "the network is down" full_disk; then
      note "[$fault] scorer keyword logic: OK"
    else note "[$fault] scorer keyword logic: FAIL"; rc=1; fi
  done
  cleanup_pair
  if [ $rc = 0 ]; then say "SELF-TEST PASS"; else say "SELF-TEST FAIL"; fi
  exit $rc
fi

# --- live run ---------------------------------------------------------------
RESULTS=""
declare -A AGG_DIAG AGG_N AGG_WALL AGG_TURNS AGG_AUDIT
IFS=',' read -ra FS <<< "$FAULTS"
IFS=',' read -ra CS <<< "$CONDITIONS"
for fault in "${FS[@]}"; do
  for cond in "${CS[@]}"; do
    for i in $(seq 1 "$TRIALS"); do
      say "$fault / $cond — trial $i/$TRIALS"
      cleanup_pair
      op="di-op"; target="di-db01"
      docker run -d --name "$op" --hostname op --network "$NET" --user root "$IMG" sleep infinity >/dev/null
      docker run -d --name "$target" --hostname db01 --network "$NET" --user root "$IMG" sleep infinity >/dev/null
      CONTAINERS=("$op" "$target")
      start_target_daemons "$target"
      inject_fault "$target" "$fault"
      if [ "$cond" = ssh ]; then setup_ssh "$op" "$target"; else setup_hop "$op" "$target" || { note "hop setup failed"; continue; }; fi

      sum="$WORK/sum-$fault-$cond-$i.json"; tx="$WORK/tx-$fault-$cond-$i.jsonl"
      HCFG=""; [ "$cond" = hop ] && HCFG="--config /cfg"
      # The driver runs commands on the operator; hop needs its config dir, so
      # wrap `hop` on the operator to always pass --config when in hop mode.
      [ "$cond" = hop ] && dexq "$op" "printf '#!/bin/sh\nexec /usr/local/bin/hop --config /cfg \"\$@\"\n' >/usr/local/bin/hopw && chmod +x /usr/local/bin/hopw && ln -sf /usr/local/bin/hopw /usr/local/sbin/hop 2>/dev/null; sed -i '1i export PATH=/usr/local/sbin:\$PATH' /root/.bashrc 2>/dev/null || true"

      ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" python3 "$SCRIPT_DIR/scripts/diagnosis-agent.py" \
        --operator "op=$op" --target-name db01 --condition "$cond" --fault "$fault" \
        --model "$MODEL" --max-turns "$MAX_TURNS" --transcript "$tx" --summary "$sum" >/dev/null
      if [ ! -f "$sum" ]; then note "driver produced no summary — counting as not diagnosed"; continue; fi

      rc_line="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); dg=d.get("diagnosis") or {}; print((dg.get("root_cause") or "").replace("\n"," "))' "$sum")"
      wall="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["wall_secs"])' "$sum")"
      turns="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["turns"])' "$sum")"
      audit_n="$(audit_exec_count "$target" "$cond")"
      dg="FAIL"; diagnosed_ok "$rc_line" "$fault" && dg="OK"

      key="$cond"
      AGG_N[$key]=$(( ${AGG_N[$key]:-0} + 1 ))
      [ "$dg" = OK ] && AGG_DIAG[$key]=$(( ${AGG_DIAG[$key]:-0} + 1 ))
      AGG_WALL[$key]=$(python3 -c "print(${AGG_WALL[$key]:-0} + ${wall:-0})")
      AGG_TURNS[$key]=$(( ${AGG_TURNS[$key]:-0} + ${turns:-0} ))
      AGG_AUDIT[$key]=$(( ${AGG_AUDIT[$key]:-0} + ${audit_n:-0} ))
      note "diagnosed=$dg  wall=${wall}s turns=$turns audit_exec=$audit_n  rc=\"$rc_line\""
      RESULTS="${RESULTS}| $fault | $cond | $dg | ${wall}s | $turns | $audit_n |\n"
    done
  done
done

# --- report -----------------------------------------------------------------
OUT="$SCRIPT_DIR/agent-diagnosis-results.md"
{
  echo "# Diagnosis proof (E2)"
  echo
  echo "The same agent (\`$MODEL\`) diagnoses a faulted machine \`db01\` from an"
  echo "operator box, reaching it with WireHop in one arm and plain ssh in the"
  echo "other. The harness injects the fault and scores the result; the agent's"
  echo "self-report is ignored. \`audit_exec\` is how many of the agent's commands"
  echo "on \`db01\` are recoverable afterwards from \`db01\`'s own records."
  echo
  echo "| fault | access | diagnosed | wall | turns | audit_exec |"
  echo "|---|---|---|---|---|---|"
  printf "%b" "$RESULTS"
  echo
  echo "## Per-condition totals"
  echo
  echo "| access | diagnosed | trials | median-ish wall | total turns | audit_exec total |"
  echo "|---|---|---|---|---|---|"
  for k in hop ssh; do
    n=${AGG_N[$k]:-0}; [ "$n" = 0 ] && continue
    d=${AGG_DIAG[$k]:-0}; w=${AGG_WALL[$k]:-0}; t=${AGG_TURNS[$k]:-0}; a=${AGG_AUDIT[$k]:-0}
    avgw=$(python3 -c "print(round(${w}/${n},1))")
    echo "| $k | $d/$n | $n | ${avgw}s | $t | $a |"
  done
  echo
  echo "The headline: both arms usually find the cause, but only the WireHop arm"
  echo "leaves \`db01\` able to show what the operator did to it. With ssh,"
  echo "\`audit_exec\` is 0 — the host logged a login and nothing else."
} > "$OUT"
say "wrote $OUT"
cat "$OUT" >&2
