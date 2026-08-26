#!/usr/bin/env bash
# agent-coldstart.sh — can an AI agent build a working WireHop network from
# nothing, with no human in the loop?
#
# Two bare Ubuntu containers. No `hop` binary, no config, no accounts. An agent
# whose ONLY tool is "run a shell command on machine X" is pointed at the public
# agent docs and asked for three outcomes:
#
#   1. a command from alpha executes on beta
#   2. both machines are on the same private network, each with a virtual IP
#   3. one fleet-wide command from alpha runs across that network
#
# The agent's own report is ignored. After it stops, THIS script inspects the
# containers and decides — an agent that claims success but left a dead warren
# scores zero. Everything is checked by capability, never by name, because the
# agent picks its own hostnames, roles and tags.
#
# Why this exists: the product thesis is "an agent can set this up alone."
# That is a testable claim, so it should be a test, and the pass rate should be
# published per release rather than asserted in a launch post.
#
# Usage:
#   ANTHROPIC_API_KEY=... ./tests/e2e/agent-coldstart.sh [options]
#
#   --trials N        trials per mode (default 3); the pass rate is over these
#   --mode M          assisted (default) | discovery | both
#   --live            point the agent at the PUBLISHED CDN instead of a local
#                     mirror of this working tree. Use for the number you
#                     publish; the default gates the build under test.
#   --model NAME      driver model (default claude-sonnet-5)
#   --max-turns N     agent turn ceiling (default 40)
#   --keep            leave containers up after a failing trial, for forensics
#   --self-test       build the mirror, prove a container can install from it,
#                     and exit. Spends no tokens and needs no API key — run this
#                     when the eval starts failing, to tell "the harness broke"
#                     apart from "the agent failed".
#
# Modes:
#   assisted   the prompt names WireHop and gives the llms.txt URL. Measures
#              "do our docs carry an agent from zero to working?" — the CI gate,
#              because it isolates the thing we control.
#   discovery  the prompt names nothing; the agent merely has skills/wirehop
#              loaded, as an agent with the skill installed would. Measures
#              "does the skill fire on a problem it should fire on?" Implies
#              --live, since the skill hard-codes the public URLs.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMG=hop-coldstart-e2e
NET=hop-coldstart-net
DOCS_C=cs-docs
BIN="$ROOT/target/aarch64-unknown-linux-gnu/release/hop"
VERSION="$(grep -m1 '^version' "$ROOT/Cargo.toml" | cut -d'"' -f2)"
WORK="$SCRIPT_DIR/.coldstart"

TRIALS=3
MODE=assisted
LIVE=0
MODEL="${COLDSTART_MODEL:-claude-sonnet-5}"
MAX_TURNS=40
KEEP=0
SELF_TEST=0

while [ $# -gt 0 ]; do
  case "$1" in
    --trials) TRIALS="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --live) LIVE=1; shift ;;
    --model) MODEL="$2"; shift 2 ;;
    --max-turns) MAX_TURNS="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --self-test) SELF_TEST=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Progress goes to stderr so the report on stdout stays machine-readable and
# function results can be captured without swallowing the narration.
say()  { echo >&2; echo "=== $* ===" >&2; }
note() { echo "    $*" >&2; }

CONTAINERS=()
cleanup_trial() {
  for c in "${CONTAINERS[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  CONTAINERS=()
}
cleanup_all() {
  cleanup_trial
  docker rm -f "$DOCS_C" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -f "$SCRIPT_DIR/hop"
}
trap cleanup_all EXIT

# --- preflight -------------------------------------------------------------
say "preflight"
if [ "$SELF_TEST" = 0 ] && [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "ANTHROPIC_API_KEY is not set." >&2
  echo "This gate drives a real model — there is no offline substitute that" >&2
  echo "would measure anything. Set the key, run --self-test to check the" >&2
  echo "harness itself, or skip this gate explicitly." >&2
  exit 2
fi
for t in docker python3 openssl; do
  command -v "$t" >/dev/null || { echo "missing: $t" >&2; exit 2; }
done
case "$MODE" in
  assisted|discovery|both) ;;
  *) echo "--mode must be assisted, discovery or both" >&2; exit 2 ;;
esac
if [ "$MODE" = discovery ] || [ "$MODE" = both ]; then
  # The skill points at the public site. Serving a rewritten copy would be
  # measuring a document nobody ships.
  [ "$LIVE" = 1 ] || note "discovery mode uses the PUBLISHED docs (skill URLs are hard-coded)"
fi
note "version=$VERSION model=$MODEL trials=$TRIALS mode=$MODE live=$LIVE"

# A stale target/ binary is the classic way an e2e run silently measures the
# PREVIOUS release. This gate's entire claim is about the current build, so
# check the version rather than merely the file's existence.
STALE=0
if [ -x "$BIN" ]; then
  BIN_VER=$(docker run --rm -v "$BIN:/hop:ro" ubuntu:24.04 /hop --version 2>/dev/null | awk '{print $2}')
  [ "$BIN_VER" = "$VERSION" ] || { STALE=1; note "target binary is $BIN_VER, Cargo.toml is $VERSION"; }
fi
if [ "${REBUILD:-0}" = 1 ] || [ ! -x "$BIN" ] || [ "$STALE" = 1 ]; then
  say "cross-building aarch64 linux binary ($VERSION)"
  AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target aarch64-unknown-linux-gnu -p hop-cli \
    || { echo "cross build failed" >&2; exit 1; }
fi

# --- the cold image --------------------------------------------------------
# Deliberately WITHOUT the hop binary: installing it is the agent's job, and an
# image with it pre-baked would skip the most failure-prone step. The packages
# here are what a stock Ubuntu server image already carries plus curl/jq —
# nothing WireHop-specific.
say "building cold image (no hop binary)"
cp "$BIN" "$SCRIPT_DIR/hop"
docker build -t "$IMG" -f - "$SCRIPT_DIR" >/dev/null <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl jq iproute2 iputils-ping dnsutils procps \
    && rm -rf /var/lib/apt/lists/*
# Ubuntu's /etc/skel/.profile puts ~/.local/bin on PATH for normal users, but
# root's .profile does not — and install.sh falls back to ~/.local/bin. Without
# this, a container is LESS representative than a real account, and the agent
# would burn turns on a PATH quirk that has nothing to do with the thesis.
ENV PATH="/root/.local/bin:/usr/local/bin:${PATH}"
DOCKERFILE
docker network create "$NET" >/dev/null 2>&1 || true

# --- local CDN mirror ------------------------------------------------------
# Serves this working tree's docs and binary so the gate measures the build
# under test, not whatever is published. Artifacts are signed with an EPHEMERAL
# key whose public half is patched into the served install.sh, so the agent
# exercises the real signature-verification path without needing the release
# key (and so CI can run this).
DOCS_URL=""
if [ "$LIVE" = 1 ]; then
  DOCS_URL="https://wirehop.org"
  note "using published CDN: $DOCS_URL"
else
  say "building local CDN mirror"
  rm -rf "$WORK"; mkdir -p "$WORK/srv/v$VERSION"
  "$ROOT/scripts/gen-llms-txt.sh" "$WORK/llms" >/dev/null || { echo "llms gen failed" >&2; exit 1; }
  openssl genrsa -out "$WORK/eph.pem" 3072 2>/dev/null
  openssl rsa -in "$WORK/eph.pem" -pubout -out "$WORK/eph.pub" 2>/dev/null

  cp "$BIN" "$WORK/srv/v$VERSION/hop-linux-arm64"
  # Hash ONLY — install.sh strips whitespace from the sidecar rather than
  # taking field 1, so shasum's default "<hash>  <file>" form fails the compare.
  # This mirrors what scripts/release.sh publishes (a 65-byte sidecar).
  ( cd "$WORK/srv/v$VERSION" \
    && shasum -a 256 hop-linux-arm64 | cut -d' ' -f1 > hop-linux-arm64.sha256 \
    && openssl dgst -sha256 -sign "$WORK/eph.pem" -out hop-linux-arm64.sig hop-linux-arm64 )
  printf '%s' "$VERSION" > "$WORK/srv/latest"

  # Rewrite the CDN base and the embedded pubkey in the served install.sh, and
  # repoint every published-site reference in the docs at the mirror.
  DOCS_URL="http://docs:8080"
  python3 - "$ROOT/install.sh" "$WORK/eph.pub" "$WORK/srv/install.sh" "$DOCS_URL" <<'PY'
import re, sys
src, pubpath, dst, base = sys.argv[1:5]
sh = open(src).read()
pub = open(pubpath).read().strip()
sh = sh.replace("https://wirehop.org", base)
# Replace the embedded release pubkey with the ephemeral one, preserving the
# ${HOP_PUBKEY:-...} shape so the override path still works.
# lambda repl: a literal string would have backslash escapes interpreted.
sh, n = re.subn(
    r'HOP_PUBKEY="\$\{HOP_PUBKEY:-.*?-----END PUBLIC KEY-----\}"',
    lambda _m: 'HOP_PUBKEY="${HOP_PUBKEY:-' + pub + '}"',
    sh, count=1, flags=re.S)
if n != 1:
    sys.exit("could not patch HOP_PUBKEY in install.sh — shape changed?")
open(dst, "w").write(sh)
PY
  [ $? -eq 0 ] || exit 1
  for f in llms.txt llms-full.txt; do
    sed "s|https://wirehop.org|$DOCS_URL|g" "$WORK/llms/$f" > "$WORK/srv/$f"
  done

  docker rm -f "$DOCS_C" >/dev/null 2>&1 || true
  docker run -d --name "$DOCS_C" --hostname docs --network "$NET" \
    -v "$WORK/srv:/srv:ro" -w /srv python:3-slim \
    python3 -m http.server 8080 >/dev/null
  # Prove the mirror actually serves before blaming the agent for not reading it.
  for _ in $(seq 1 30); do
    docker run --rm --network "$NET" "$IMG" \
      curl -fsS "$DOCS_URL/llms.txt" -o /dev/null 2>/dev/null && break
    sleep 1
  done || true
  docker run --rm --network "$NET" "$IMG" curl -fsS "$DOCS_URL/llms.txt" -o /dev/null 2>/dev/null \
    || { echo "local CDN mirror is not serving" >&2; exit 1; }
  note "mirror serving $VERSION at $DOCS_URL (ephemeral signing key)"
fi

# --- self-test -------------------------------------------------------------
# The eval is only meaningful if a cold container CAN install from what we
# serve. Prove that directly, so a broken mirror never gets reported as an
# agent failure.
if [ "$SELF_TEST" = 1 ]; then
  say "self-test: install from $DOCS_URL into a cold container"
  ST=cs-selftest
  CONTAINERS+=("$ST")
  docker run -d --name "$ST" --hostname selftest --network "$NET" \
    --cap-add=NET_ADMIN --device /dev/net/tun --user root \
    "$IMG" sleep infinity >/dev/null
  ST_OUT=$(docker exec "$ST" bash -lc "curl -fsSL $DOCS_URL/install.sh | bash" 2>&1)
  ST_RC=$?
  echo "$ST_OUT" | sed 's/^/    /' >&2
  ST_VER=$(docker exec "$ST" bash -lc 'hop --version' 2>/dev/null)
  echo
  if [ $ST_RC -eq 0 ] && [ "${ST_VER#hop }" = "$VERSION" ]; then
    # Signature verification is the step most likely to regress silently.
    echo "$ST_OUT" | grep -qi 'signature' \
      && note "install.sh exercised the signature path" \
      || note "NOTE: no signature line in install output — verify the pubkey patch"
    echo "SELF-TEST: PASS ($ST_VER from $DOCS_URL)"
    exit 0
  fi
  echo "SELF-TEST: FAIL (rc=$ST_RC, version='${ST_VER:-none}', expected $VERSION)"
  exit 1
fi

# --- scoring ---------------------------------------------------------------
# Every check is capability-shaped and name-agnostic: the agent chooses its own
# hostnames, roles and tags, so we discover them from the fleet roster rather
# than assuming any.
dex() { docker exec "$1" bash -lc "$2" 2>/dev/null; }

# Locate the hop binary the agent installed. It may not be on PATH, and the
# agent is free to install it anywhere — scoring must not mistake an unusual
# install location for a failed install.
hop_path() {
  local c="$1" p
  p=$(dex "$c" 'command -v hop')
  [ -n "$p" ] || p=$(dex "$c" 'ls -1 /usr/local/bin/hop /root/.local/bin/hop /usr/bin/hop 2>/dev/null | head -1')
  [ -n "$p" ] || p=$(dex "$c" 'find / -xdev -type f -name hop -perm -u+x 2>/dev/null | head -1')
  printf '%s' "$p"
}

# The agent may have driven hop with a non-default --config/HOP_CONFIG_DIR. If
# the default path yields nothing, recover the path from the running daemon's
# own command line rather than scoring a working setup as broken.
hop_env() {
  local c="$1" hp="$2" cfg
  if dex "$c" "$hp fleet list --json" | grep -q '"members"'; then echo ""; return; fi
  cfg=$(dex "$c" "pgrep -af 'hop' | grep -oE -- '--config +[^ ]+' | head -1 | awk '{print \$2}'")
  [ -n "$cfg" ] && echo "--config $cfg" || echo ""
}

score_trial() {
  # Sets: R_INSTALL R_REACH R_WARREN R_FLEET R_DETAIL
  local a="$1" b="$2" nonce="$3"
  local ha hb ea eb roster peers vip_a vip_b target role
  R_INSTALL=0; R_REACH=0; R_WARREN=0; R_FLEET=0; R_DETAIL=""

  ha=$(hop_path "$a"); hb=$(hop_path "$b")
  if [ -n "$ha" ] && [ -n "$hb" ] \
     && dex "$a" "$ha --version" | grep -q '^hop ' \
     && dex "$b" "$hb --version" | grep -q '^hop '; then
    R_INSTALL=1
  else
    R_DETAIL="hop not runnable on both (a='${ha:-none}' b='${hb:-none}')"; return
  fi

  ea=$(hop_env "$a" "$ha"); eb=$(hop_env "$b" "$hb")
  roster=$(dex "$a" "$ha $ea fleet list --json")

  # 2. reach — some peer known to alpha runs our marker and returns it.
  peers=$(printf '%s' "$roster" | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit()
out=[]
for m in d.get("members",[]):
    if not m.get("this_node") and m.get("name"): out.append(m["name"])
for h in d.get("known_hosts",[]):
    n = h.get("name") if isinstance(h,dict) else h
    if n and n not in out: out.append(n)
print("\n".join(out))
' 2>/dev/null)
  for target in $peers; do
    if dex "$a" "$ha $ea exec '$target' -- echo COLDSTART_$nonce" | grep -q "COLDSTART_$nonce"; then
      R_REACH=1; R_DETAIL="reach via '$target'"; break
    fi
  done
  [ "$R_REACH" = 0 ] && R_DETAIL="no peer of alpha ran the marker (peers: ${peers:-none})"

  # 3. private network — both hold a virtual IP and alpha carries a packet to beta's.
  vip_a=$(dex "$a" "$ha $ea fleet list --json" | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit()
for m in d.get("members",[]):
    if m.get("this_node") and m.get("vip"): print(m["vip"])
' 2>/dev/null | head -1)
  vip_b=$(dex "$b" "$hb $eb fleet list --json" | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit()
for m in d.get("members",[]):
    if m.get("this_node") and m.get("vip"): print(m["vip"])
' 2>/dev/null | head -1)
  if [ -n "$vip_a" ] && [ -n "$vip_b" ]; then
    if dex "$a" "ping -c1 -W3 $vip_b" | grep -q ' bytes from '; then
      R_WARREN=1; R_DETAIL="$R_DETAIL; warren $vip_a -> $vip_b"
    else
      R_DETAIL="$R_DETAIL; vIPs $vip_a/$vip_b but no packet"
    fi
  else
    R_DETAIL="$R_DETAIL; vIP missing (a=${vip_a:-none} b=${vip_b:-none})"
  fi

  # 4. fleet-wide — one command fans out and a REMOTE node answers. Selectors
  # are roles/tags the agent chose, so try each role on the roster.
  role=$(printf '%s' "$roster" | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit()
seen=[]
for m in d.get("members",[]):
    r=m.get("role")
    if r and r not in seen: seen.append(r)
for t in d.get("members",[]):
    for tag in (t.get("tags") or []):
        if tag not in seen: seen.append(tag)
print("\n".join(seen))
' 2>/dev/null)
  for r in $role; do
    if dex "$a" "$ha $ea fleet exec '$r' -- echo COLDSTART_$nonce" | grep -q "COLDSTART_$nonce"; then
      R_FLEET=1; R_DETAIL="$R_DETAIL; fleet exec '$r'"; break
    fi
  done
  [ "$R_FLEET" = 0 ] && R_DETAIL="$R_DETAIL; fleet exec found no working selector (${role:-none})"
}

# --- trials ----------------------------------------------------------------
RESULTS=""
MODE_PASS=""   # set by run_mode; plain string, so bash 3.2 (stock macOS) works
run_mode() {
  local mode="$1" docs="$2" pass=0 n=0 i
  local skill="$ROOT/skills/wirehop/SKILL.md"
  for i in $(seq 1 "$TRIALS"); do
    n=$((n+1))
    local nonce="${mode}${i}$$"
    local a=cs-alpha-$i b=cs-beta-$i
    say "$mode trial $i/$TRIALS"
    cleanup_trial
    # Either machine might become the warren node, so both get TUN + NET_ADMIN.
    for c in "$a:alpha" "$b:beta"; do
      local name="${c%%:*}" host="${c##*:}"
      CONTAINERS+=("$name")
      docker run -d --name "$name" --hostname "$host" --network "$NET" \
        --cap-add=NET_ADMIN --device /dev/net/tun --user root \
        "$IMG" sleep infinity >/dev/null
    done

    local tx="$WORK/transcript-$mode-$i.jsonl" sum="$WORK/summary-$mode-$i.json"
    mkdir -p "$WORK"
    python3 "$SCRIPT_DIR/scripts/coldstart-agent.py" \
      --containers "alpha=$a,beta=$b" \
      --docs-url "$docs" --mode "$mode" --skill "$skill" \
      --model "$MODEL" --max-turns "$MAX_TURNS" \
      --transcript "$tx" --summary "$sum" >/dev/null
    local rc=$?

    if [ $rc -ne 0 ]; then
      note "agent driver failed (rc=$rc) — trial counted as FAIL"
      RESULTS="${RESULTS}| ${mode} ${i} | driver error | - | - | - | FAIL | rc=$rc |\n"
      continue
    fi

    score_trial "$a" "$b" "$nonce"
    local turns wall
    turns=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["turns"])' "$sum" 2>/dev/null)
    wall=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["wall_secs"])' "$sum" 2>/dev/null)

    local ok=FAIL
    if [ "$R_INSTALL$R_REACH$R_WARREN$R_FLEET" = "1111" ]; then ok=PASS; pass=$((pass+1)); fi
    note "install=$R_INSTALL reach=$R_REACH warren=$R_WARREN fleet=$R_FLEET -> $ok  (${turns:-?} turns, ${wall:-?}s)"
    note "$R_DETAIL"
    RESULTS="${RESULTS}| ${mode} ${i} | ${turns:-?} | ${wall:-?}s | ${R_INSTALL}${R_REACH}${R_WARREN}${R_FLEET} | ${ok} | ${R_DETAIL} |\n"

    if [ "$ok" = FAIL ] && [ "$KEEP" = 1 ]; then
      note "keeping $a/$b for forensics; transcript: $tx"
      CONTAINERS=()
    fi
  done
  MODE_PASS="$pass/$n"
}

RATE_LINES=""   # "<mode> <passed>/<total>" per line
ANY_ZERO=0
if [ "$MODE" = assisted ] || [ "$MODE" = both ]; then
  run_mode assisted "$DOCS_URL"
  RATE_LINES="${RATE_LINES}assisted ${MODE_PASS}\n"
  case "$MODE_PASS" in 0/*) ANY_ZERO=1 ;; esac
fi
if [ "$MODE" = discovery ] || [ "$MODE" = both ]; then
  run_mode discovery "https://wirehop.org"
  RATE_LINES="${RATE_LINES}discovery ${MODE_PASS}\n"
  case "$MODE_PASS" in 0/*) ANY_ZERO=1 ;; esac
fi

# --- report ----------------------------------------------------------------
say "cold-start results"
OUT="$SCRIPT_DIR/agent-coldstart-results.md"
{
  echo "# Agent cold-start eval"
  echo
  echo "Generated by \`tests/e2e/agent-coldstart.sh\` on $(date -u +%Y-%m-%dT%H:%M:%SZ)."
  echo
  echo "An AI agent whose only tool is \"run a shell command on machine X\" is given two"
  echo "bare Ubuntu containers with no \`hop\` binary and no human to help, and asked for a"
  echo "working two-node private network plus a fleet-wide command. **The agent's own"
  echo "report is ignored** — this harness inspects the containers afterwards and scores"
  echo "by capability, never by name."
  echo
  echo "Model: \`$MODEL\` · WireHop \`$VERSION\` · turn ceiling $MAX_TURNS · $TRIALS trial(s) per mode"
  if [ "$LIVE" = 1 ]; then
    echo "· docs: **published CDN**"
  else
    echo "· docs: **local mirror of this working tree** (artifacts signed with an ephemeral key)"
  fi
  echo
  echo "## Pass rate"
  echo
  echo "| mode | passed |"
  echo "|---|---|"
  printf "%b" "$RATE_LINES" | while read -r m r; do
    [ -n "$m" ] && echo "| $m | $r |"
  done
  echo
  echo "## Trials"
  echo
  echo "| trial | turns | wall | install/reach/warren/fleet | result | detail |"
  echo "|---|---|---|---|---|---|"
  printf "%b" "$RESULTS"
  echo
  echo "## What each digit means"
  echo
  echo "| digit | check |"
  echo "|---|---|"
  echo "| install | \`hop --version\` succeeds on both machines |"
  echo "| reach | a command issued from alpha ran on a peer and returned a per-trial marker |"
  echo "| warren | both machines hold a virtual IP and alpha carries an ICMP packet to beta's |"
  echo "| fleet | one fleet-wide command from alpha was answered by a remote node |"
  echo
  echo "## Caveats"
  echo
  echo "- Scoring locates the \`hop\` binary wherever the agent put it, and uses the default"
  echo "  config dir, falling back to the path on a running daemon's command line. An agent"
  echo "  that used a non-default config dir for one-shot commands only could still be"
  echo "  scored as failing when it had in fact succeeded."
  echo "- The containers ship \`curl\`, \`jq\`, \`iproute2\`, \`iputils-ping\`, \`dnsutils\` and"
  echo "  \`procps\` — stock server tooling, nothing WireHop-specific."
  echo "- The image puts \`~/.local/bin\` on root's \`PATH\`. Ubuntu does this for normal"
  echo "  accounts but not for root, and \`install.sh\` falls back to that directory; without"
  echo "  it the container would be *less* representative than a real machine and the agent"
  echo "  would spend turns on a PATH quirk unrelated to what this measures."
  echo "- \`assisted\` names WireHop and hands over the llms.txt URL, so it measures the"
  echo "  docs, not discoverability. \`discovery\` measures whether the skill fires at all."
} > "$OUT"

cat "$OUT"
echo
echo "Transcripts: $WORK/transcript-*.jsonl"
echo "Wrote: $OUT"

if [ "$ANY_ZERO" = 1 ]; then
  echo
  echo "COLD START: FAIL (a mode scored 0)"
  exit 1
fi
echo
echo "COLD START: recorded"
