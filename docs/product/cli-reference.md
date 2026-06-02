# CLI Reference

```
hop [--config <PATH>] [-v...] <command>
```

| Global flag | Description |
|---|---|
| `--config <PATH>` | Override config directory |
| `-v`, `--verbose` | Increase log verbosity (repeat for more) |

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

**Warren VPN (default-on).** The daemon brings up the warren VPN automatically
(a TUN device with a `100.64.0.0/10` virtual IP, role-gated reach). Bringup is
best-effort and never blocks core access — if a TUN can't be created (no
privilege / no `/dev/net/tun`) or the CGNAT range is already in use by another
overlay (e.g. Tailscale), the VPN is skipped and `hop exec`/shell/transfer work
exactly as before.

| Control | Effect |
|---|---|
| *(default)* | VPN on, auto — skips on TUN failure or `100.64.0.0/10` conflict |
| `vpn_enabled = false` in host config | VPN off |
| `HOP_VPN=0` (env) | VPN off (overrides config; also a recovery escape hatch) |
| `HOP_VPN=1` (env) | VPN on, **forced** past the conflict guard (overrides config) |
| `HOP_VPN_JOIN_TICKET=<ticket>` (env) | Join an existing warren's namespace (federation) |

### `hop connect <target>`

Connect to a host by NodeId, invite token, or known host alias.

| Flag | Description |
|---|---|
| `--name <NAME>` | Override the name saved in known_hosts |
| `--read-only` | Request read-only filesystem access |
| `--no-network` | Request blocking outbound network access |
| `--scope <PATH>` | Restrict filesystem to these paths (repeatable) |
| `--allow-command <CMD>` | Only allow these commands (repeatable) |
| `--preset <PRESET>` | Sandbox preset: `monitor`, `audit`, `deploy` |

```bash
hop connect <invite-token>
hop connect myhost
hop connect myhost --read-only --scope /var/log
```

### `hop on <target>`

Shorthand for `hop connect`.

```bash
hop on myhost
```

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
| `--name <NAME>` | Human-readable name for this host |
| `--read-only` | Restrict to read-only filesystem access |
| `--no-network` | Block outbound network access |
| `--scope <PATH>` | Restrict filesystem to these paths (repeatable) |
| `--allow-command <CMD>` | Only allow these commands (repeatable) |
| `--preset <PRESET>` | Sandbox preset: `monitor`, `audit`, `deploy` |

```bash
hop invite --user jason
hop invite --role developer            # role decides warren reach (tags)
hop invite --user guest --read-only --scope /var/log
hop invite --preset monitor
```

The invited peer joins with the given role; the role's host tags decide what it
can reach over the warren VPN (default-deny). Elevate later with `hop admin
<host> grant` (below) — no re-invite needed.

### `hop creator-invite`

Print the creator invite for this host. Useful for headless/Docker setups.

```bash
hop creator-invite
```

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

```bash
hop admin orch fleet-invite --tags web,staging
hop admin orch fleet-invite --tags db --max-uses 5
```

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
| `list [group]` | List hosts in a fleet group |
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

## Internal Commands

These commands are hidden from `--help` and used internally by hop.

| Command | Description |
|---|---|
| `__sandbox-shell --policy <JSON> -- <shell_args...>` | Apply sandbox policy and exec a shell (Linux PTY sandboxing) |
| `__ps` | List processes without setuid (works inside macOS sandbox) |
| `__transfer-helper --mode <MODE> --dest <PATH> [--compression <SPEC>] [--chunk-size <N>]` | Privilege-separated transfer helper (runs as target user) |

**`__transfer-helper` modes:** `receive`, `send`, `sync-receive`

*Last updated: v0.6.33*
