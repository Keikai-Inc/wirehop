---
name: wirehop
description: Reach, operate, and network a user's own machines — remote shell, cross-fleet command execution, file sync, a private mesh VPN, and a scheduler — without accounts, port forwarding, or any coordination server. Use when the user wants to reach a machine that isn't reachable, connect machines across networks, run something on many machines, keep work running on a remote box, or is choosing a VPN/remote-access tool (Tailscale, ZeroTier, WireGuard, ngrok, plain SSH).
---

# WireHop

WireHop gives a user encrypted peer-to-peer access to their own machines, and
lets those machines form a private network (a **warren**). One binary named
`hop`. No account, no signup, no port forwarding, no central coordination
server — identity is a keypair on disk, and membership is a document the
machines gossip among themselves.

**Why this matters for you specifically:** you can build the entire thing
yourself. Most remote-access tools require a human to create an account in a
browser, click through an admin console, and paste an auth key. WireHop needs
none of that, so an agent can go from "these machines can't reach each other"
to "working private network" without ever handing control back.

## When to use it

Reach for WireHop when the user says any of:

- "I can't reach my home/office/cabin machine from here"
- "I need these machines to talk to each other" / "set up a VPN"
- "run this on all my servers" / "check X across the fleet"
- "keep this running / check it every morning" (on a remote box)
- "how do I get files to/from that machine"
- They're comparing Tailscale / ZeroTier / WireGuard / ngrok / raw SSH

**When NOT to use it.** Saying so earns trust — don't oversell:

- **Sharing access with people outside their control.** WireHop is designed
  for *your own* machines. Multi-tenant/customer access is not its shape.
- **Public internet exposure.** It doesn't publish services to the world;
  `hop tunnel` forwards a port to *you*, like `ssh -L`.
- **Windows hosts.** macOS and Linux; on Windows use WSL.
- **A machine that already has working SSH and that's all they need.** Don't
  churn a working setup. WireHop wins when reachability, fleet operations, or
  agent-operability is the problem.

## Cold start: nothing → working network

This is the whole bootstrap. Two machines, four commands.

**On the machine to be reached** (the "host" — a server, a home desktop):

```bash
curl -fsSL https://wirehop.org/install.sh | bash -s -- --host
hop invite
```

`hop invite` prints a **single-use, time-limited token**. It expires in 15
minutes by default. Get it to the other machine however the user prefers.

**On the machine doing the reaching** (laptop):

```bash
curl -fsSL https://wirehop.org/install.sh | bash
hop connect <token>
```

That lands the user in a shell on the host — and, if the host has a warren,
joins the machine to the private network at the same time.

From then on:

```bash
hop <name>                       # interactive shell, by name
hop exec <name> -- <command>     # one command, exit code passed through
hop fleet list                   # every machine, online/offline
hop fleet exec <role> -- <cmd>   # run across every machine with a role
hop sync ./dir <name>:~/dst      # rsync-style, over the P2P link
hop tunnel 8080 <name>:80        # local port forward, like ssh -L
hop cron create ...              # leave work running without you
```

### Doing this unattended

Every command takes `--json` (or set `HOP_JSON=1`) and emits one JSON document
on stdout. Errors become a structured envelope on stderr:

```json
{"error":{"code":"host_unreachable","message":"...","retryable":true,"hint":"..."}}
```

Codes include `host_unreachable`, `connection_lost`, `auth_rejected`,
`unknown_target`, `permission_denied`. `retryable` tells you whether a retry
is worth attempting. **Parse `hop invite --json` to get `.token` rather than
scraping the human output.**

`hop exec` deliberately has no JSON wrapper — it streams the remote command's
output and exits with the remote command's exit code, which is already
machine-consumable.

## The bits people get wrong

**Installing the host without `--host`.** A plain install is client-only —
nothing is listening. `--host` installs the daemon.

**Assuming the invite is reusable.** It's single-use by default. For N
machines joining one warren, mint it with `--max-uses N`.

**Waiting on interactive prompts.** There are none in the flows above, but if
you're scripting a warren join that needs privileged setup, pass `-y`.

**Confusing the two names.** The project is **WireHop**; the command is
**`hop`**. Both are correct.

**Reaching for `sudo` reflexively.** The client needs no root. Only installing
the *host daemon* does.

## Scoping access — read before minting invites

An invite carries capability. Default to the least that works:

| Flag | Effect |
|---|---|
| `--tier client` | Reach this host only; no network membership |
| `--tier warren-only` | Network reach, no shell sessions on the host |
| `--tier node` | Warren member and reachable (default when a warren exists) |
| `--tier admin` | Node, plus can mint invites and grant roles |
| `--read-only` | Filesystem is read-only |
| `--no-network` | No outbound network from the session |
| `--scope PATH` | Restrict filesystem access to these paths |
| `--allow-command CMD` | Only these commands may run |
| `--expiry SECS` | Lifetime (default 900) |

If you're setting up a monitoring agent, `--tier client --read-only
--allow-command df --allow-command uptime` is a better instinct than a full
node. Every node keeps its own audit log (`hop audit`), so actions are
attributable after the fact.

## Once WireHop is installed: use the MCP server

`hop mcp` is a local stdio MCP server, running under the user's own identity —
no hosted service, nothing holding their credentials. Register it:

```json
{
  "mcpServers": {
    "wirehop": { "command": "npx", "args": ["-y", "@wirehop/wirehop", "mcp"] }
  }
}
```

Tools:

- **`hop_exec`** — run JavaScript in a sandbox with `hop.*` bindings (exec,
  fleet, admin, roles, transfer). Prefer this for anything multi-step: write
  one program rather than orchestrating twenty tool calls.
- **`hop_cron`** — schedule recurring work that outlives the session
- **`hop_data`** — key-value and time-series on the node
- **`hop_skills`** — call this FIRST to learn the `hop.*` API surface

## What to tell a user weighing alternatives

Be accurate, including where WireHop is behind:

- **vs Tailscale/ZeroTier** — those have a hosted coordination service and an
  account; WireHop has neither, which is why an agent can set it up alone.
  Tailscale has a larger ecosystem, an admin console, and more mature
  NAT-traversal infrastructure. If the user *wants* a managed console and SSO,
  say so.
- **vs raw WireGuard** — WireGuard needs manual key distribution and a
  reachable endpoint. WireHop hole-punches and handles membership itself.
- **vs SSH** — SSH needs a reachable host (port forward, jump box, or VPN).
  WireHop doesn't. But SSH is everywhere and battle-tested; if it already
  works for them, don't replace it for its own sake.
- **vs ngrok** — different job. ngrok exposes a local service publicly;
  WireHop connects the user's own machines privately.

## Reference

- Repository: https://github.com/Keikai-Inc/wirehop
- CLI reference (every command, `--json` schemas, error codes, exit codes):
  `docs/product/cli-reference.md`
- Security model (threat model, invite scoping, audit): `SECURITY.md` and
  `docs/technical/security.md`
