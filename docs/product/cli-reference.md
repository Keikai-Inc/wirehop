# CLI Reference

```
hop [--config <PATH>] [-v...] <command>
hop --version
```

| Global flag | Description |
|---|---|
| `--config <PATH>` | Override config directory |
| `-v`, `--verbose` | Increase log verbosity (repeat for more) |
| `-V`, `--version` | Print the hop version and exit |

---

## Connection

### `hop host`

Start hosting (listen for incoming connections).

| Flag | Description |
|---|---|
| `--quiet` | Suppress interactive output (for daemon/LaunchAgent use) |

```bash
hop host
hop host --quiet    # systemd/launchd mode
```

**Warren VPN (on by default).** A new host brings up the warren VPN by default (a
TUN device with a `100.64.0.0/10` virtual IP, role-gated reach), so a member
reaches peers by name without an extra step. Opt out with `--host --no-vpn` or
`hop config set vpn off`. (It was off by default in v0.6.37–v0.9.15 as the interim
mitigation for the warren write-authorization trust gap; that gap is now closed by
anchor-conditional author-validation **enforce** — a founder-anchored warren
rejects forged `vpn/ip/name` bindings — so the default is safe to restore. See
[security.md](security.md) and the C1 note in
[../technical/security.md](../technical/security.md).) **Backward-compat:** a host
config that predates the `vpn_enabled` field stays off, so upgrading an existing
host never silently enables the VPN. Bringup is best-effort and never blocks core
access: if a TUN can't be created (no privilege / no `/dev/net/tun`) or the CGNAT
range is already in use by another overlay (e.g. Tailscale), the VPN is skipped and
`hop exec`/shell/transfer work exactly as before.

| Control | Effect |
|---|---|
| *(default, new host)* | **VPN on** — core access (shell/exec/transfer) unaffected either way |
| `--host --no-vpn` (installer / node setup) | Opts this machine OUT of the warren VPN |
| host config predating `vpn_enabled` | **VPN off** — no silent change on upgrade |
| `vpn_enabled = true` in host config (`hop config set vpn on`) | VPN on, auto — skips on TUN failure or `100.64.0.0/10` conflict |
| `HOP_VPN=1` (env) | VPN on, **forced** past the conflict guard (overrides config) |
| `HOP_VPN=0` (env) | VPN off (overrides config; also a recovery escape hatch) |
| `HOP_VPN_JOIN_TICKET=<ticket>` (env) | Join an existing warren's namespace (federation) |

### `hop connect <target>`

Connect to a host by NodeId, invite token, or known host alias. **`hop connect`
is also how you join a warren** — there is no separate `hop warren join` (removed;
folded into `connect`).

| Flag | Description |
|---|---|
| `--name <NAME>` | Override the name saved in known_hosts |
| `--read-only` | Request read-only filesystem access |
| `--no-network` | Request blocking outbound network access |
| `--scope <PATH>` | Restrict filesystem to these paths (repeatable) |
| `--allow-command <CMD>` | Only allow these commands (repeatable) |
| `--preset <PRESET>` | Sandbox preset: `monitor`, `audit`, `deploy` |
| `-y, --yes` | Consent to the privileged node setup without prompting (headless) |
| `--on-warren-conflict <ACTION>` | Resolve a conflict with a different, populated warren: `replace` (switch), `abort` (keep) |
| `--warren` | Join the warren from the **stored** ticket (no target/invite) |

```bash
hop connect <invite-token>          # connect + (if the invite carries a warren) join it
hop connect <invite-token> --yes    # headless: also do the node setup without prompting
hop connect --warren                # put this machine on the warren from a stored ticket
hop connect myhost
hop connect myhost --read-only --scope /var/log
```

**Joining a warren.** If the invite carries a warren (any `node`/`admin`/
`warren-only` invite — not a plain `client` invite), `hop connect <invite>` puts
this machine on the warren and brings up the **node** (a daemon running as root,
for the TUN). Concretely it writes the join ticket, then:

- if a daemon is **already installed**, it **restarts it** (via sudo) so the new
  warren is imported — you're on the warren;
- if there's **no daemon yet**, it offers to set one up with sudo (interactive),
  or pass `--yes` to do it non-interactively;
- a plain `client` invite is reach-only and never joins.

Bringing up a node needs privilege (sudo / a TTY). With neither — a headless run
without `--yes`, or a declined/failed sudo — the join ticket is saved and the
shell still opens, but the machine isn't on the warren yet; finish with
`hop connect --warren --yes` or `install.sh --host`. If you're already on a
*different* warren, the invite's warren is adopted only when the current one is
solo (no other members); a populated warren is never switched without
`--on-warren-conflict replace` (or an interactive choice).

### `hop <target>` (catch-all)

Unknown subcommands are treated as connect targets.

```bash
hop myhost              # equivalent to: hop connect myhost
```

### `hop invite`

Generate a one-time invite token/URL.

| Flag | Description |
|---|---|
| `--user <USER>` | Unix username the invited peer will log in as |
| `--role <ROLE>` | Named role for the invited peer (e.g. `developer`, `ops`). Defaults to the host's configured `default_role` (`member`) |
| `--tier <TIER>` | Capability tier: `client`, `warren-only`, `node`, `admin`. Default: inferred (`node` if this host has a warren, else `client`). Warren tiers require a warren on this host |
| `--name <NAME>` | Human-readable name for this host |
| `--read-only` | Restrict to read-only filesystem access |
| `--no-network` | Block outbound network access |
| `--scope <PATH>` | Restrict filesystem to these paths (repeatable) |
| `--allow-command <CMD>` | Only allow these commands (repeatable) |
| `--preset <PRESET>` | Sandbox preset: `monitor`, `audit`, `deploy` |

```bash
hop invite --user jason
hop invite --role developer            # role decides warren reach (tags)
hop invite --tier client               # reach this host only — no warren, no daemon, no sudo
hop invite --tier warren-only          # VPN reach only — cannot open host sessions
hop invite --tier node                 # warren member + reachable (self-upgrades to a daemon)
hop invite --tier admin                # node + warren admin (mint/grant); redeems as creator
hop invite --user guest --read-only --scope /var/log
hop invite --preset monitor
```

**Tiers** (orthogonal axes — session reach, warren membership, admin — collapsed
into four): a `client` invite reaches only the issuing host and strips any warren
ticket (it can never self-upgrade). `warren-only` puts the machine on the VPN
(vIP/MagicDNS) but refuses host sessions (`network_only` role). `node` is a full
warren member. `admin` redeems with creator access. Warren tiers pin the founder
trust anchor (C1). (The read- vs write-scoped ticket split is tracked separately;
see `docs/technical/warren-internals.md` §10.)

The invited peer joins with the given role; the role's host tags decide what it
can reach over the warren VPN (default-deny). Elevate later with `hop admin
<host> grant` (below) — no re-invite needed.

> **`hop invite --creator`** prints this host's standing creator invite (admin
> tier) instead of minting a new one — useful for headless/Docker bootstrap.
> (This replaces the former `hop creator-invite` command.)

---

## Execution

### `hop exec <target> -- <command...>`

Execute a command on a remote host.

| Flag | Description |
|---|---|
| `--read-only` | Request read-only filesystem access |
| `--no-network` | Request blocking outbound network access |
| `--scope <PATH>` | Restrict filesystem to these paths (repeatable) |
| `--allow-command <CMD>` | Only allow these commands (repeatable) |
| `--preset <PRESET>` | Sandbox preset: `monitor`, `audit`, `deploy` |

```bash
hop exec myhost -- uname -a
hop exec myhost -- systemctl status nginx
hop exec myhost --read-only -- cat /etc/passwd
echo "data" | hop exec myhost -- wc -l
```

---

## Transfer

### `hop cp [-r] <paths...>`

Copy files to/from a remote host. Use `host:path` syntax for remote paths.

| Flag | Description |
|---|---|
| `-r`, `--recursive` | Copy directories recursively |

```bash
hop cp localfile.txt myhost:/tmp/
hop cp myhost:/var/log/app.log ./
hop cp -r ./project myhost:~/backup/
```

### `hop sync <source> <dest>`

Sync directories with a remote host (rsync-style with delta transfer).

| Flag | Description |
|---|---|
| `--delete` | Delete extraneous files from destination |
| `-n`, `--dry-run` | Show what would be transferred without doing it |
| `-i`, `--itemize-changes` | Show itemized list of changes per file |
| `--stats` | Show detailed transfer statistics |
| `--no-progress` | Suppress per-file progress (show only filenames) |

Hidden compatibility flags (no-ops): `-a`/`--archive`, `-z`/`--compress`, `-P`, `--progress`, `-H`/`--human-readable`.

```bash
hop sync ./src myhost:~/project/src
hop sync --delete myhost:~/data ./local-data
hop sync -n ./src myhost:~/src          # dry run
hop sync -i ./src myhost:~/src          # itemize changes
hop sync --stats ./src myhost:~/src     # detailed stats
```

---

## Port forwarding

### `hop tunnel <target> <spec>`

Forward a local TCP port to a port on a remote host, like `ssh -L`, over the
encrypted P2P link (works through NAT with no router config). Binds
`localhost:<localport>` and bridges each connection to the host's
`127.0.0.1:<remoteport>`; runs until Ctrl-C. One QUIC stream per TCP connection.

| Spec | Effect |
|---|---|
| `<port>` | `localhost:<port>` → host's `127.0.0.1:<port>` |
| `<localport>:<remoteport>` | `localhost:<localport>` → host's `127.0.0.1:<remoteport>` |

```bash
hop tunnel myserver 3000           # reach the host's :3000 at localhost:3000
hop tunnel myserver 8080:3000      # reach the host's :3000 at localhost:8080
```

Authorization is the same as `hop exec`: the peer must be authorized, and a tunnel
is **denied if the peer's session sandbox blocks network** (`--no-network`). The
target is the host's own loopback (`127.0.0.1`); reverse forwards, third-party
targets, and `--reverse` are planned.

---

## Administration

### `hop config [set <key> <value>] | path`

View or update host configuration (`host_config.json`), or print the resolved
config directory.

| Key | Values | Description |
|---|---|---|
| `session_timeout` | duration (`3600`, `1h`, `1d`) | Detached PTY session lifetime |
| `max_sessions` | integer | Max detached PTY sessions |
| `vpn` | `on` / `off` | Warren VPN data plane (default `on`) |
| `tags` | comma-separated | Host tags (drive role→tag reach + MagicDNS); empty clears |
| `default_role` | role name | Role for invites that don't specify one (default `member`) |

```bash
hop config                          # show current config
hop config set session_timeout 3600
hop config set max_sessions 10
hop config set vpn off              # disable the warren VPN
hop config set tags production,web  # tag this host
hop config set default_role developer
hop config path                     # print the host config directory
```

Changes take effect on the next `hop host` / daemon restart.

### `hop warren [status|leave]`

Inspect or tear down this machine's warren membership. **Joining is done with
[`hop connect`](#hop-connect-target)** (there is no `hop warren join`).

| Subcommand | Description |
|---|---|
| `status` | Show this machine's warren namespace membership and VPN state. |
| `leave` | Tear down this machine's warren state (namespace, tickets, store, vIP) after a backup. Does not uninstall the daemon. |

```bash
hop connect <invite>       # join a warren (the invite carries it)
hop connect --warren       # join from a stored ticket (no new invite)
hop warren status
hop warren leave
```

> A **client** install reaches hosts it's invited to with no VPN. Consuming a
> warren invite with `hop connect` upgrades it to a **node** on the warren (needs
> sudo to bring up the TUN; on a fresh machine, `install.sh --host` does the
> privileged setup). See [`hop connect`](#hop-connect-target) for the full join
> behavior and flags.

**Already on a warren?** Consuming an invite for a *different* warren resolves as:
> - **Not on a warren, or the current one is solo** (no other members) → the
>   invite's warren is **adopted automatically** — no prompt.
> - **Has other members** → it is **never switched silently**. Interactively you
>   choose **Keep** (default) or **Switch**; non-interactively you must pass
>   `--on-warren-conflict replace` (switch) or `abort`. Switching leaves the
>   current warren (backed up to `.warren-backup-*`) and joins the new one.
>   Running both at once (multi-home) is planned.

### `hop peers [remove|rename]`

List authorized peers or known hosts.

| Subcommand | Description |
|---|---|
| *(none)* | List all peers/known hosts |
| `remove <id>` | Remove an authorized peer by NodeId |
| `rename <id> <name>` | Rename a peer or known host |

```bash
hop peers
hop peers remove abc123
hop peers rename abc123 my-server
```

### `hop admin <target> <action>`

Remote administration (requires creator role).

| Subcommand | Description |
|---|---|
| `invite` | Create an invite on the remote host |
| `peers` | List authorized peers on the remote host |
| `remove-peer <id>` | Remove a peer from the remote host |
| `create-user <username>` | Create a Unix user on the remote host |
| `status` | Get status of the remote host |
| `fleet-invite` | Create a fleet invite token (orchestrator) |
| `fleet-list` | List fleet members (orchestrator) |
| `fleet-remove <id>` | Remove a fleet member (orchestrator) |
| `fleet-tag <id>` | Update tags on a fleet member (orchestrator) |
| `grant <id> <role>` | Change a peer's named role (elevation/demotion) |

#### `hop admin <target> invite`

| Flag | Description |
|---|---|
| `--user <USER>` | Unix username for the invited peer |
| `--role <ROLE>` | Named role for the invited peer (e.g. `developer`, `ops`) |
| `--creator` | Create a creator invite (admin access; sugar for the `admin` role) |
| `--read-only` | Restrict to read-only filesystem access |
| `--no-network` | Block outbound network access |
| `--scope <PATH>` | Restrict filesystem to these paths (repeatable) |
| `--allow-command <CMD>` | Only allow these commands (repeatable) |
| `--preset <PRESET>` | Sandbox preset: `monitor`, `audit`, `deploy` |

```bash
hop admin myhost invite --user alice
hop admin myhost invite --role developer
hop admin myhost invite --creator
```

#### `hop admin <target> grant <id> <role>`

Change an existing peer's named role without re-inviting. The new role's host
tags re-resolve the peer's warren reach network-wide.

```bash
hop admin myhost grant abc123 developer   # elevate
hop admin myhost grant abc123 admin       # full reach (tags ["*"])
hop admin myhost grant abc123 member      # demote to default-deny
```

#### `hop admin <target> create-user <username>`

| Flag | Description |
|---|---|
| `--sudo` | Grant sudo access |
| `--admin` | macOS admin group membership |
| `--groups <GROUPS>` | Extra Unix groups (comma-separated) |
| `--shell <SHELL>` | Override default shell |
| `--invite` | Also generate an invite for this user |

```bash
hop admin myhost create-user bob --sudo --invite
hop admin myhost create-user alice --groups docker,www-data
```

#### `hop admin <target> fleet-invite`

| Flag | Description |
|---|---|
| `--tags <TAGS>` | Tags for fleet members (comma-separated) |
| `--max-uses <N>` | Maximum number of uses (0 = unlimited, default: 0) |
| `--expiry <SECS>` | Expiry in seconds (default: 86400) |
| `--tier <TIER>` | Capability tier for redeemers: `client`, `warren-only`, `node`, `admin`. Default: `admin` (legacy). Warren tiers require a warren on the host |

```bash
hop admin orch fleet-invite --tags web,staging
hop admin orch fleet-invite --tags db --max-uses 5
hop admin orch fleet-invite --tags web --tier node   # provision servers as nodes, not admins
```

The `--tier` mirrors `hop invite --tier`: `node`/`warren-only` redeemers join the
warren without admin rights; `client` strips the warren ticket; `admin` (default)
keeps the legacy orchestrator-trusted behaviour.

#### `hop admin <target> fleet-list`

| Flag | Description |
|---|---|
| `--tag <TAG>` | Filter by tag |

```bash
hop admin orch fleet-list
hop admin orch fleet-list --tag web
```

#### `hop admin <target> fleet-remove <id>`

```bash
hop admin orch fleet-remove abc123
```

#### `hop admin <target> fleet-tag <id>`

| Flag | Description |
|---|---|
| `--add <TAGS>` | Tags to add (comma-separated) |
| `--remove <TAGS>` | Tags to remove (comma-separated) |

```bash
hop admin orch fleet-tag abc123 --add production --remove staging
```

#### `hop admin <target> role <action>`

| Subcommand | Description |
|---|---|
| `create <name>` | Create a new role |
| `list` | List all roles |
| `update <name>` | Update an existing role |
| `delete <name>` | Delete a role |

**`role create` flags:**

| Flag | Description |
|---|---|
| `--tags <TAGS>` | Host tags this role can access (comma-separated) |
| `--shared` | Use shared Unix accounts (default: individual) |
| `--sudo` | Grant sudo access |
| `--admin` | macOS admin group membership |
| `--groups <GROUPS>` | Extra Unix groups (comma-separated) |
| `--shell <SHELL>` | Override default shell |

```bash
hop admin orch role create developer --tags developer,staging --shared
hop admin orch role list
hop admin orch role update developer --add-tags production
hop admin orch role delete intern
```

**`role update` flags:** `--add-tags`, `--remove-tags`, `--sudo <bool>`, `--admin <bool>`

---

## Fleet

### `hop fleet <action>`

Fleet management (host-side).

| Subcommand | Description |
|---|---|
| `status` | Show fleet registration status |
| `list [group]` | List warren members (by node-id, name, role, vIP) + known hosts. Members show their **hostname**; this node is marked `(this node)`. |
| `exec <group> -- <command...>` | Execute a command on all hosts in a group |
| `add <name> --tags <TAGS>` | Add a known host to the daemon's fleet store |

```bash
hop fleet status
hop fleet list web
hop fleet exec developer -- apt update
hop fleet add my-server --tags web,production
```

**`fleet status` flag:** `--fleet <NAME>` (required only if registered with multiple fleets)

---

## Capabilities

### `hop cap <action>`

Manage built-in capabilities (health monitoring, log search, security baseline).

| Subcommand | Description |
|---|---|
| `list` | List available capabilities |
| `enable <id>` | Enable a capability (creates a cron job) |
| `disable <id>` | Disable a capability (removes its cron job) |
| `status` | Show status of enabled capabilities |
| `run <id>` | Run a capability once (on-demand) |
| `deploy <id>` | Deploy a capability to remote nodes |

```bash
hop cap list
hop cap enable health --targets web
hop cap enable health --schedule "0 */10 * * * *"
hop cap run log-search --targets web --param query=error
hop cap deploy health --targets production
hop cap disable health
hop cap status
```

**`cap enable` flags:** `--targets <TAG>`, `--schedule <CRON>`
**`cap run` flags:** `--targets <TAG>`, `--param <KEY=VALUE>` (repeatable)
**`cap deploy` flags:** `--targets <TAG>` (required)

---

## Datastore

### `hop kv <action>`

Read/write key-value data from the daemon datastore.

| Subcommand | Description |
|---|---|
| `get <key>` | Get a value by key |
| `list [prefix]` | List keys matching an optional prefix |
| `set <key> <value>` | Set a key-value pair |

```bash
hop kv set mykey "hello world"
hop kv get mykey
hop kv get mykey --raw           # output raw value (for piping)
hop kv list
hop kv list "config:"
```

### `hop secrets <action>`

Manage encrypted secrets in the daemon datastore.

| Subcommand | Description |
|---|---|
| `get <name>` | Get a secret's value |
| `set <name> [value]` | Set a secret (reads from stdin if value omitted) |
| `list` | List all secret names |
| `delete <name>` | Delete a secret |

```bash
hop secrets set API_KEY sk-xxx123
hop secrets set DB_PASSWORD          # enter interactively
hop secrets get API_KEY
hop secrets list
hop secrets delete API_KEY
```

### `hop ts <action>`

Query time-series data from the daemon datastore.

| Subcommand | Description |
|---|---|
| `latest <metric>` | Get the most recent data point |
| `query <metric>` | Query time-series data for a metric |

```bash
hop ts latest health.load
hop ts query health.mem_pct --last 1h
hop ts query health.disk_pct --last 7d
```

**`ts query` flag:** `--last <DURATION>` (e.g., `1h`, `30m`, `7d`; default: `1h`)

### `hop cron <action>`

Manage cron jobs on the daemon.

| Subcommand | Description |
|---|---|
| `list` | List all cron jobs |
| `get <id>` | Show full details of a cron job |
| `create` | Create a new cron job |
| `delete <id>` | Delete a cron job |
| `enable <id>` | Enable a cron job |
| `disable <id>` | Disable a cron job |
| `run <id>` | Trigger immediate execution |

**`cron create` flags:**

| Flag | Description |
|---|---|
| `--name <NAME>` | Job name (required) |
| `--schedule <CRON>` | Cron schedule expression (required) |
| `--script <JS>` | Inline JavaScript source |
| `--file <PATH>` | Read script from a file |
| `--targets <TAG>` | Fleet target tag (injected as `hop.targets`) |
| `--tags <TAGS>` | Tags for this job (comma-separated) |

```bash
hop cron list
hop cron create --name "health" --schedule "0 */5 * * * *" --script "hop.log('ok')"
hop cron create --name "backup" --schedule "0 0 3 * * *" --file backup.js --targets web
hop cron get abc123
hop cron run abc123
hop cron disable abc123
hop cron delete abc123
```

---

## System

### `hop id`

Print this node's identity (NodeId).

```bash
hop id
```

### `hop mcp`

Start MCP server (Model Context Protocol) for AI agent integration. Communicates over stdio using JSON-RPC 2.0.

```bash
hop mcp
```

### `hop agent [--daemon] [--config <PATH>]`

Manage the connection multiplexer agent.

| Subcommand | Description |
|---|---|
| *(none)* | Start the agent |
| `stop` | Stop the running agent |
| `status` | Check agent status |

| Flag | Description |
|---|---|
| `--daemon` | Start agent in background (daemon mode) |
| `--config <PATH>` | Override config directory |

```bash
hop agent --daemon
hop agent status
hop agent stop
```

---

## Debugging

Profiling tools for the host daemon. They use each platform's **native** profiler,
so they work on the normal release binary and (for CPU) on the running daemon
without a restart. Run with `sudo` (they inspect the system daemon).

### `hop debug cpu-profile [--secs N] [--pid P] [--out F]`

Sample the running host daemon's CPU and render a **function-level flame graph
SVG** plus a hottest-functions text report. No restart needed — run it *while* the
daemon is busy. Auto-targets the busiest `hop host` process (the privsep worker).

| Flag | Description |
|---|---|
| `--secs <N>` | Seconds to sample (default: 10) |
| `--pid <P>` | Profile this PID instead of auto-detecting |
| `--out <F>` | Report path (default: `/tmp/hop-cpu-<pid>-<ts>.txt`; SVG alongside) |

Sampler: `sample(1)` on macOS, `perf record`/`perf script` on Linux; folded to SVG
in-process via [inferno](https://github.com/jonhoo/inferno).

```bash
sudo hop debug cpu-profile --secs 15   # writes /tmp/hop-cpu-<pid>-<ts>.{txt,svg}
```

### `hop debug mem-profile <on | snapshot | off>`

Heap-profile the daemon to find a leak. `on` restarts it in profiling mode (the
native allocator profiler armed: `MallocStackLogging` on macOS, jemalloc `prof` on
Linux), as a single root process at full speed that serves traffic normally; a
self-restoring watchdog brings the normal daemon back after a deadline regardless.

| Subcommand | Description |
|---|---|
| `on` | Restart the daemon in memory-profiling mode |
| `snapshot [--out F]` | Sorted, symbolized heap report from the **live** daemon (repeatable) |
| `off` | Restore the normal privsep daemon |

`snapshot` runs `malloc_history -allBySize` + `leaks` (macOS) or `prof.dump` +
`jeprof` (Linux). It tracks only `malloc`, so mmap'd redb/blob memory is excluded.
`SIGUSR2` on the daemon also writes a snapshot (`kill -USR2 <pid>`).

```bash
sudo hop debug mem-profile on        # restart in profiling mode (serves traffic)
# ... reproduce the leak (e.g. a VNC session) ...
sudo hop debug mem-profile snapshot  # repeat as RSS grows
sudo hop debug mem-profile off       # restore the normal daemon
```

### `hop debug net-stats [--watch] [--interval N] [--json]`

Show the **VPN data-plane counters** from the running daemon — the live forwarding
pipeline, with no restart. Answers three operational questions:

- **Are packets being dropped?** — a counter at every drop site (reach-denied, no
  route/endpoint, send conn-closed, unknown peer, source-spoofed, wrong
  destination, TUN-write error), as totals and (with `--watch`) per-second rates.
- **Are queues filling / backing up?** — egress send-backpressure counters: how
  often and how long the forwarder waited for QUIC datagram send-buffer space.
  Zero = the pipe keeps up.
- **How long do we hold a packet?** — a log2 histogram of per-packet handling
  latency (TUN→send on egress, recv→TUN on ingress) with p50/p99.

The counters are always-on, lock-free atomics in the worker (no measurable cost),
served over the daemon socket. An operator-group user can read them **without
sudo** (the socket is group-restricted, like other operator-admin ops).

| Flag | Description |
|---|---|
| `--watch` | Refresh continuously, showing per-second rates (Ctrl-C to stop) |
| `--interval <N>` | Seconds between refreshes in `--watch` mode (default: 2) |
| `--json` | Emit the raw snapshot as JSON instead of the formatted report |

```bash
hop debug net-stats              # one-shot totals + latency histograms
hop debug net-stats --watch      # live drop/throughput rates, refreshed every 2s
hop debug net-stats --json       # machine-readable snapshot
```

---

## Internal Commands

These commands are hidden from `--help` and used internally by hop.

| Command | Description |
|---|---|
| `__sandbox-shell --policy <JSON> -- <shell_args...>` | Apply sandbox policy and exec a shell (Linux PTY sandboxing) |
| `__ps` | List processes without setuid (works inside macOS sandbox) |
| `__transfer-helper --mode <MODE> --dest <PATH> [--compression <SPEC>] [--chunk-size <N>]` | Privilege-separated transfer helper (runs as target user) |

**`__transfer-helper` modes:** `receive`, `send`, `sync-receive`

*Last updated: v0.6.33*
