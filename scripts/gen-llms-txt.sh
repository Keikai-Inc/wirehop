#!/usr/bin/env bash
# Generate llms.txt + llms-full.txt for agent retrieval.
#
# GENERATED, not hand-written: llms.txt that drifts from the real docs is worse
# than none — an agent following stale instructions fails in a way the user
# blames on the product. This assembles from the same sources humans read, so
# it can only be as stale as the docs themselves.
#
#   llms.txt       — the index: what WireHop is, the cold-start sequence, links
#   llms-full.txt  — everything inlined (CLI reference, skill, security model)
#
# Usage: ./scripts/gen-llms-txt.sh [outdir]   (default: target/llms)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/target/llms}"
VERSION="$(grep -m1 '^version' "$ROOT/Cargo.toml" | cut -d'"' -f2)"
REPO="https://github.com/Keikai-Inc/wirehop"
CDN="https://hop.keikai.ai"

mkdir -p "$OUT"

# ── llms.txt — the index ─────────────────────────────────────────────────────
cat > "$OUT/llms.txt" <<EOF
# WireHop

> Secure peer-to-peer remote access and private networks. A single binary
> named \`hop\`: no accounts, no port forwarding, no central coordination
> server. Identity is a keypair on disk; membership is a document the machines
> gossip among themselves. Built so an AI agent can construct and operate the
> whole thing without a browser or a third-party account.

Version: ${VERSION} · Repository: ${REPO} · License: MIT OR Apache-2.0

## What it does

- Reach any of your machines from anywhere (encrypted P2P QUIC, hole-punched;
  a relay carries traffic only when NAT defeats direct connection)
- Join machines into a private network (a "warren") with virtual IPs and name
  resolution
- Run commands on one machine or across a whole fleet by role or tag
- rsync-style file sync and local port forwarding over the same link
- Schedule recurring work that keeps running after you disconnect
- Every command speaks \`--json\`; errors are structured for unattended use

## Cold start (two machines, four commands)

On the machine to be reached:
\`\`\`bash
curl -fsSL ${CDN}/install.sh | bash -s -- --host
hop invite            # single-use, 15-minute token; --json for {"token":...}
\`\`\`

On the machine doing the reaching:
\`\`\`bash
curl -fsSL ${CDN}/install.sh | bash
hop connect <token>   # shell on the host, and joins the private network
\`\`\`

## As an MCP server

\`hop mcp\` is a LOCAL stdio MCP server running under your own identity — there
is no hosted service and nothing takes custody of your credentials.

\`\`\`json
{"mcpServers":{"wirehop":{"command":"npx","args":["-y","@wirehop/wirehop","mcp"]}}}
\`\`\`

Tools: \`hop_exec\` (JavaScript in a sandbox with \`hop.*\` fleet bindings —
write one program instead of many tool calls), \`hop_cron\`, \`hop_data\`,
\`hop_skills\`.

## Docs

- [CLI reference](${REPO}/blob/main/docs/product/cli-reference.md): every command, \`--json\` schemas, error codes, exit codes
- [Agent skill](${REPO}/blob/main/skills/wirehop/SKILL.md): when to use WireHop, bootstrap, invite scoping
- [Security model](${REPO}/blob/main/SECURITY.md): threat model, capability tiers, audit
- [Remote access](${REPO}/blob/main/docs/product/remote-access.md): sessions, persistence, recovery, transfer
- [Warren](${REPO}/blob/main/docs/product/warren.md): the private network
- [AI and scripting](${REPO}/blob/main/docs/product/ai-and-scripting.md): the \`hop.*\` JS API
- [Full text](${CDN}/llms-full.txt): everything above inlined

## Not what it's for

Sharing access with people outside your control; exposing services to the
public internet; Windows hosts (use WSL).
EOF

# ── llms-full.txt — everything inlined ───────────────────────────────────────
{
  cat "$OUT/llms.txt"
  echo
  echo "---"
  echo
  echo "# Agent skill (full text)"
  echo
  # Strip YAML frontmatter — it's tooling metadata, not content.
  sed '1{/^---$/!q;};1,/^---$/d' "$ROOT/skills/wirehop/SKILL.md"
  echo
  echo "---"
  echo
  echo "# CLI reference (full text)"
  echo
  cat "$ROOT/docs/product/cli-reference.md"
  echo
  echo "---"
  echo
  echo "# Security policy (full text)"
  echo
  cat "$ROOT/SECURITY.md"
} > "$OUT/llms-full.txt"

echo "Generated:"
echo "  $OUT/llms.txt        ($(wc -c <"$OUT/llms.txt" | tr -d ' ') bytes)"
echo "  $OUT/llms-full.txt   ($(wc -c <"$OUT/llms-full.txt" | tr -d ' ') bytes)"
echo
echo "Publish with:"
echo "  aws s3 cp $OUT/llms.txt s3://hop-releases/llms.txt"
echo "  aws s3 cp $OUT/llms-full.txt s3://hop-releases/llms-full.txt"
