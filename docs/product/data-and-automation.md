# Data & Automation

The on-device datastore (KV, time-series, cron, secrets), the built-in `hop cap` capability system, and the orchestration bindings (HTTP, OAuth proxy, email monitoring).


---

## Datastore

hop embeds a persistent datastore (redb) on every host. It provides key-value storage, time-series metrics, encrypted secrets, and cron-scheduled JavaScript execution. Data survives restarts and is accessible via CLI, JavaScript bindings, and the MCP `hop_data`/`hop_cron` tools.

### Key-Value Store

Namespaced key-value storage with content-type metadata.

#### Data Model

| Field | Type | Description |
|---|---|---|
| `namespace` | string | Logical grouping (e.g. `"config"`, `"cache"`) |
| `key` | string | Unique within namespace |
| `value` | bytes | Arbitrary payload |
| `content_type` | string | MIME type hint (`application/json`, `text/plain`) |
| `updated_at` | u64 | Unix timestamp in milliseconds |

Namespaces isolate keys -- a key in `"config"` is independent of the same key in `"cache"`.

#### CLI: `hop kv`

```bash
# Set a value (stored as text/plain)
hop kv set mykey "hello world"

# Get a value
hop kv get mykey
hop kv get mykey --raw          # unwrap JSON strings for piping

# List keys (optional prefix filter)
hop kv list
hop kv list "metric:"
```

The CLI uses a default namespace. The `--raw` flag on `get` strips JSON string quotes for shell piping.

#### JavaScript: `hop.kv.*`

```javascript
await hop.kv.set("config", "ttl", { value: 3600 });
const entry = await hop.kv.get("config", "ttl");
const items = await hop.kv.list("config", "");         // all keys in namespace
const items = await hop.kv.list("config", "metric:");  // prefix filter
await hop.kv.delete("config", "ttl");
```

#### MCP: `hop_data` tool

| Action | Required params | Description |
|---|---|---|
| `kv_get` | `namespace`, `key` | Get a value |
| `kv_set` | `namespace`, `key`, `value` | Set a value (content_type defaults to `application/json`) |
| `kv_delete` | `namespace`, `key` | Delete a key |
| `kv_list` | `namespace` | List keys; optional `prefix` filter |

---

### Time-Series

Append-only metric storage with tag-based filtering. Each data point is a `(timestamp, value, tags)` tuple keyed by metric name.

#### Data Model

| Field | Type | Description |
|---|---|---|
| `metric` | string | Metric name (e.g. `"cpu.usage"`, `"mem.free"`) |
| `value` | f64 | Numeric measurement |
| `tags` | map | Optional key-value labels (e.g. `{"host": "web-01", "cpu": "0"}`) |
| `timestamp` | u64 | Unix ms; auto-set on insert, or explicit |

#### Query Parameters

| Field | Type | Description |
|---|---|---|
| `metric` | string | Required |
| `start` | u64 | Start of range (unix ms, inclusive) |
| `end` | u64 | End of range (unix ms, inclusive) |
| `tags_filter` | map | Only return points matching all specified tags |
| `limit` | usize | Max results |

#### CLI: `hop ts`

```bash
# Most recent data point
hop ts latest cpu.usage

# Query a time range (default: last 1 hour)
hop ts query cpu.usage
hop ts query cpu.usage --last 30m
hop ts query cpu.usage --last 7d
```

#### JavaScript: `hop.ts.*`

```javascript
await hop.ts.insert("cpu.usage", 72.5, { host: "web-01" });
const latest = await hop.ts.latest("cpu.usage");
const points = await hop.ts.query("cpu.usage", {
  start: Date.now() - 3600000,
  end: Date.now(),
  tags: { host: "web-01" },
  limit: 100,
});
```

#### MCP: `hop_data` tool

| Action | Required params | Optional params | Description |
|---|---|---|---|
| `ts_insert` | `metric`, `value` (number) | `tags` | Insert a data point at current time |
| `ts_latest` | `metric` | | Most recent point |
| `ts_query` | `metric` | `start`, `end`, `tags`, `limit` | Range query |

---

### Cron Scheduling

Persistent cron jobs that execute JavaScript in hop's sandboxed runtime. Jobs survive restarts.

#### CronJob Fields

| Field | Type | Description |
|---|---|---|
| `id` | string | Auto-generated hex ID (e.g. `cron_1a2b3c`) |
| `name` | string | Human-readable label |
| `schedule` | string | 6-field cron expression: `sec min hour day month weekday` |
| `script` | string | JavaScript source code |
| `enabled` | bool | Whether the scheduler runs this job |
| `last_run` | u64? | Unix ms of last successful execution |
| `next_run` | u64 | Unix ms of next scheduled execution |
| `created_at` | u64 | Unix ms |
| `tags` | vec | Fleet targeting tags (e.g. `["fleet:web", "role:monitor"]`) |
| `targets` | string? | Fleet target tag; matching hosts injected as `hop.targets` |
| `catalog_id` | string? | Dedup key for idempotent `ensure` operations |
| `sandbox` | SandboxPolicy? | Restricts `hop.exec()`, `hop.fleet.exec()`, `hop.local()` in the script |

The schedule uses a **6-field cron format**: `sec min hour day month weekday`. Examples:
- `0 */5 * * * *` -- every 5 minutes
- `*/5 * * * * *` -- every 5 seconds
- `0 0 * * * *` -- every hour

#### CLI: `hop cron`

```bash
# Create a job (inline script or from file)
hop cron create --name "health check" --schedule "0 */5 * * * *" --script "return hop.exec('uptime')"
hop cron create --name "deploy" --schedule "0 0 2 * * *" --file ./scripts/deploy.js
hop cron create --name "fleet metrics" --schedule "0 */1 * * * *" --targets "web" --tags fleet,metrics

# List / inspect
hop cron list
hop cron get <job-id>

# Lifecycle
hop cron enable <job-id>
hop cron disable <job-id>
hop cron run <job-id>       # trigger immediate execution
hop cron delete <job-id>
```

#### JavaScript: `hop.cron.list`

```javascript
const jobs = await hop.cron.list();
```

#### MCP: `hop_cron` tool

| Action | Required params | Optional params | Description |
|---|---|---|---|
| `create` | `name`, `schedule`, `script` | `tags`, `targets`, `catalog_id`, `sandbox_preset` | Create a job |
| `ensure` | `catalog_id`, `name`, `schedule`, `script` | `tags`, `targets`, `sandbox_preset` | Idempotent create (skips if catalog_id exists) |
| `list` | | `tag_filter` | List jobs |
| `get` | `job_id` | | Full details |
| `enable` | `job_id` | | Enable (recomputes next_run) |
| `disable` | `job_id` | | Disable |
| `delete` | `job_id` | | Remove |

The `ensure` action prevents duplicate jobs when an agent creates the same logical job multiple times. If a job with the given `catalog_id` already exists, the existing job is returned.

The `sandbox_preset` parameter accepts `monitor`, `audit`, or `deploy` to restrict what commands the job's scripts can execute.

---

### Secrets

Encrypted secret storage using ChaCha20-Poly1305 with a per-host key derived from the node identity. Values are encrypted at rest; only names are queryable without decryption.

#### Data Model

| Field | Type | Description |
|---|---|---|
| `name` | string | Secret identifier (e.g. `API_KEY`) |
| `ciphertext` | bytes | ChaCha20-Poly1305 encrypted value + 16-byte auth tag |
| `nonce` | [u8; 12] | Random nonce per encryption |
| `updated_at` | u64 | Unix ms |

#### CLI: `hop secrets`

```bash
hop secrets set API_KEY "sk-test-123"
hop secrets set DB_PASSWORD                  # reads from stdin if value omitted
hop secrets get API_KEY
hop secrets list                             # names only, not values
hop secrets delete API_KEY
```

#### JavaScript: `hop.secrets.*`

```javascript
await hop.secrets.set("API_KEY", "sk-test-123");
const value = await hop.secrets.get("API_KEY");
const names = await hop.secrets.list();
await hop.secrets.delete("API_KEY");
```

#### MCP: `hop_data` tool

| Action | Required params | Description |
|---|---|---|
| `secrets_get` | `name` | Decrypt and return value |
| `secrets_set` | `name`, `value` | Encrypt and store |
| `secrets_delete` | `name` | Remove |
| `secrets_list` | | List names only |

---

### Retention Policies

Time-series data supports TTL-based cleanup via `ts_purge_before(metric, timestamp)`. This removes all data points for a metric older than the given timestamp. Purge is a local-only operation (daemon-internal housekeeping); it is not exposed over remote connections.

```rust
// Delete all cpu.usage points older than 7 days
let cutoff = now_ms - (7 * 24 * 3600 * 1000);
datastore.ts_purge_before("cpu", cutoff)?;
```

KV and secrets entries do not have automatic expiry; delete them explicitly when no longer needed.

### Per-node Audit & Flow Log

Each machine keeps its own append-only logbook of security- and connection-relevant
events — who connected, what they ran, what flowed, and membership/config changes.
It is **datastore-backed and local**: no central collector. Query it with
[`hop audit`](cli-reference.md#hop-audit); export to external SIEM/metrics systems
is a planned layer (roadmap G22).

**Schema (OpenTelemetry-aligned).** Each event (`crate::audit::AuditEvent`) has a
fixed field set that maps 1:1 onto OTel log attributes, so external export is a
lossless field rename rather than a reshape:

| Field | OTel attribute | Notes |
|---|---|---|
| `ts_ms` | `Timestamp` | unix ms |
| `category` | `event.domain` | `connection` / `session` / `exec` / `transfer` / `reach` / `flow` / `membership` / `config` |
| `action` | `event.name` | e.g. `connection.authorized`, `member.join`, `exec` |
| `outcome` | `event.outcome` | `success` / `failure` / `allow` / `deny` / `info` |
| `actor` / `actor_user` | `source.node_id` / `enduser.id` | acting node-id / unix user |
| `target` / `peer` | `destination.address` / `network.peer.node_id` | |
| `bytes_tx` / `bytes_rx` | `network.io.bytes` | flow summaries |
| `path` | `network.type` | `direct` / `relay` / `mixed` |
| `detail` | `event.description` | short free text |

**Storage.** Events live in the `audit` redb table under a single time-ordered series,
keyed `(ts_ms << 20) | seq` so same-millisecond events never collide. Values are
stored as **JSON** (not bincode) so the schema can gain fields across upgrades without
breaking old records (`#[serde(default)]` fills the gaps). API:
`audit_append(&event)`, `audit_query(&AuditQuery)` (most-recent-first; category/time/
actor/limit filters), and `audit_purge_before(before_ms)`.

**Verbosity + retention.** Recording is gated by `audit_level` in the host config
(`off` / `security` / `connections` *(default)* / `flows`), overridable with
`HOP_AUDIT_LEVEL`. A drain thread keeps recording off the hot path. Events older than
`HOP_AUDIT_RETENTION_DAYS` (default 30) are purged hourly. Per-packet reach decisions
are deliberately **not** recorded (that's the VPN forwarding hot path); denials show
up in aggregate in the periodic flow summary's drop counts.

*Last updated: v0.6.33*


---

## Capabilities

Capabilities are self-contained monitoring, operations, and security scripts that ship with hop. Each capability includes a JavaScript script, a sandbox permission tier, a trigger mode, and a data storage pattern. The framework handles enabling (as cron jobs), disabling, deploying to fleet nodes, and on-demand execution.

### CLI Commands

```bash
hop cap list                        # list all available capabilities
hop cap enable <id>                 # enable as a cron job (default schedule)
hop cap enable <id> --targets web   # enable with fleet targeting
hop cap enable <id> --schedule "0 */10 * * * *"  # custom schedule
hop cap disable <id>                # remove the cron job
hop cap status                      # show which capabilities are enabled
hop cap run <id>                    # run once (on-demand)
hop cap run <id> --targets web      # run against fleet group
hop cap run <id> --param query=OOM  # pass parameters
hop cap deploy <id> --targets prod  # deploy to remote nodes
```

### Built-in Capabilities

| ID | Name | Description | Tier | Trigger | Default Schedule | Category | Data Pattern |
|---|---|---|---|---|---|---|---|
| `health` | Health Monitor | CPU load, memory, disk usage, uptime. Dual-mode: orchestrator fans out to targets, or node monitors itself locally. | Observe | Scheduled | `0 */5 * * * *` (every 5 min) | monitor | Push |
| `log-search` | Log Search | Searches system logs across fleet nodes. Each node greps locally, returns matching lines. | Observe | OnDemand | -- | operations | FanOut |
| `security-baseline` | Security Baseline | Audits SUID binaries, open ports, failed auth, SSH keys, world-writable files. Dual-mode with push. | Audit | Both | `0 0 3 * * *` (daily 3 AM) | security | Push |
| `email-monitor` | Email Monitor | Daily Gmail triage and morning briefing. Classifies emails as URGENT/ACTION/FYI using Claude, sends briefing, marks FYI as read. | Connect | Both | `0 0 7 * * *` (daily 7 AM) | automation | Push |
| `event-webhook` | Event Webhook | Fires a local HTTP POST to a secret-stored URL on warren events: a new member joins, this node's device posture fails, or rejected/denied activity crosses a threshold. Polls this node's audit log; no central collector. | Connect | Both | `0 */5 * * * *` (every 5 min) | automation | Push |
| `log-insights` | Log Insights (AI) | AI-aggregated federated log search: fans a read-only search across target nodes (each greps its own logs), then reduces the matches with Claude into one summary of patterns/anomalies. | Connect | OnDemand | -- | operations | FanOut |

#### Parameters

| Capability | Parameter | Required | Default | Description |
|---|---|---|---|---|
| `log-search` | `query` | Yes | -- | Search term to grep for in system logs |
| `event-webhook` | `deny_threshold` | No | `5` | Fire a summary alert when this many rejected/denied events accumulate since the last run |
| `log-insights` | `query` | Yes | -- | Search pattern (literal substring) to find across nodes |
| `log-insights` | `source` | No | `system` | Where each node searches: `audit`, `system`, or a file path |

### Permission Tiers

Each capability declares a `PermissionTier` that maps to a sandbox preset. This controls what the capability's JS script can do on the host.

| Tier | Sandbox Preset | Filesystem | Network | Use Case |
|---|---|---|---|---|
| **Observe** | `monitor` | Read-only, system paths only | Blocked | Health checks, metrics collection |
| **Audit** | `audit` | Read-only, full filesystem read | Blocked | Security scanning, log analysis |
| **Connect** | `connect` | Read-only, full filesystem read | Allowed | API integrations, email monitoring |
| **Operate** | `deploy` | Write + network allowed, deny destructive | Allowed | Deployments, service management |

### Trigger Modes

| Mode | Can Schedule | Can Run On-Demand | Description |
|---|---|---|---|
| `Scheduled` | Yes | No | Runs only on a cron schedule. `hop cap enable` creates the job. |
| `OnDemand` | No | Yes | Runs only via `hop cap run`. Cannot be enabled as a cron job. |
| `Both` | Yes | Yes | Can be scheduled and also run ad-hoc. Has a default schedule. |

### Data Patterns

| Pattern | Description |
|---|---|
| **Push** | Node collects data locally, pushes summary to orchestrator's datastore (KV + time-series). |
| **FanOut** | Orchestrator dispatches query to all target nodes. Each node filters locally and returns results. |

### How Capabilities Work

#### Enabling

`hop cap enable health` creates a cron job with:
- **Name:** derived from the capability name
- **Schedule:** the capability's default (overridable with `--schedule`)
- **Script:** the capability's built-in JS source
- **Catalog ID:** `cap:<id>` (e.g., `cap:health`) for tracking

#### Deploying

`hop cap deploy health --targets production` pushes the capability's cron job to all fleet members matching the `production` tag. Each node then runs the capability locally on its own schedule.

#### On-Demand Execution

`hop cap run log-search --targets web --param query=OOM` executes the capability's script immediately. Parameters are injected as `hop.params` in the JS runtime. Fleet targets are injected as `hop.targets`.

### Capability Scripts

#### health.js

Collects hostname, OS, load average, memory (total/free), disk usage, and uptime. Works on both macOS and Linux. Stores metrics in time-series (`health.load`, `health.mem_pct`, `health.disk_pct`) and latest snapshot in KV (`cap:health:<hostname>:latest`).

**Dual-mode:** When `hop.targets` is empty, monitors the local node. When targets are provided, fans out via `hop.exec()` to each target.

#### log_search.js

Searches `/var/log/syslog`, `/var/log/system.log`, `/var/log/messages`, and `/var/log/auth.log` on each target node. Requires the `query` parameter. Returns matching lines (up to 20 per log file per host).

**Fan-out only:** Requires `--targets`. Each node greps locally -- logs never leave the node unless they match.

#### security_baseline.js

Audits five areas on each host:
1. SUID binaries (`find / -perm -4000`)
2. Open listening ports (`ss -tlnp` or `netstat -tlnp`)
3. Failed auth attempts (last 24h from journal or auth.log)
4. SSH authorized keys (count per user)
5. World-writable files in `/etc` and `/usr`

Stores full report in KV (`cap:security:<hostname>:latest`).

**Dual-mode:** Runs locally or fans out to targets.

#### email_monitor.js

Daily Gmail monitoring with AI-powered triage:

1. Refreshes OAuth token inline (using `hop.secrets` for token storage)
2. Fetches up to 50 unread messages via Gmail API
3. Sends email list to Claude for classification (URGENT / ACTION / FYI)
4. Generates a structured morning briefing grouped by priority
5. Sends briefing email to self via Gmail API
6. Marks FYI messages as read; URGENT and ACTION stay unread
7. Archives briefing to KV (`briefings:<date>`)

**Setup required:** See [Email Monitor Setup](#email-monitor-setup) below.

#### event_webhook.js

A local, no-central-collector notifier. Each run polls **this node's** per-node
audit log (G4) and POSTs a JSON payload to a secret-stored URL for three event
types:

| Trigger | Detected from the audit log | Payload `hop_event` |
|---|---|---|
| **New member joins** | category `membership` (e.g. `member.join`) | `membership` |
| **Posture fails** | action `posture.fail` (this node booted with disk encryption / firewall / screen-lock reported **off**) | `posture_fail` |
| **Denial spike** | `>= deny_threshold` events with outcome `deny`/`failure` (rejected connections, reach denials) since the last run | `denial_threshold` |

Each node reports **its own** events (federated; the membership events come from the
admitting node, the posture event from the node itself). State is a watermark in KV
(`event-webhook`/`last_ts`) so each run only acts on newer events. Delivery is
best-effort (failures are logged; the watermark still advances).

**Setup:**

```bash
hop secrets set webhook_url "https://hooks.example.com/your-endpoint"
hop cap enable event-webhook                       # every 5 min (default)
hop cap enable event-webhook --schedule "0 * * * * *"   # every minute
hop cap enable event-webhook --param deny_threshold=10
hop cap run event-webhook                          # run once now
```

The URL **must be public** (`https`): the cap runs under the restricted `connect`
sandbox, whose SSRF guard blocks loopback / private / CGNAT targets. (Slack,
PagerDuty, Discord, or your own internet-facing endpoint all work.)

#### log_insights.js

AI-aggregated federated log search — the executable companion to
[`hop fleet grep`](cli-reference.md#hop-fleet-grep-selector-pattern). Fans a
**read-only** search across the `--targets` group (each node greps its own logs
locally), collects the matches, and asks Claude to reduce them into one summary of
patterns, anomalies, and the key finding — **no central collector**.

```bash
hop auth anthropic                                              # one-time
hop cap run log-insights --targets web --param query="failed password"
hop cap run log-insights --targets prod --param query=OOM --param source=system
```

`source` is `system` (default — per-OS system logs), `audit` (the structured hop
audit log), or a file path. Connect tier (network) because `hop.claude` needs it;
the per-node search is read-only (grep/journalctl/cat only). Without an Anthropic
credential it still returns the raw per-host aggregation, just no AI summary.

### Email Monitor Setup

#### Prerequisites

1. Google Cloud project with Gmail API enabled
2. OAuth 2.0 credentials (Web application type)
3. Anthropic API key

#### Step-by-Step

```bash
# 1. Store Google OAuth credentials
hop secrets set google_client_id YOUR_CLIENT_ID
hop secrets set google_client_secret YOUR_CLIENT_SECRET

# 2. Get OAuth tokens (one-time browser flow)
#    Open this URL in your browser (replace YOUR_CLIENT_ID):
#    https://accounts.google.com/o/oauth2/v2/auth?client_id=YOUR_CLIENT_ID&
#      redirect_uri=http://localhost:8080/callback&response_type=code&
#      scope=https://www.googleapis.com/auth/gmail.readonly+
#      https://www.googleapis.com/auth/gmail.modify+
#      https://www.googleapis.com/auth/gmail.send&
#      access_type=offline&prompt=consent
#
#    After consent, exchange the auth code:
#    curl -s -X POST https://oauth2.googleapis.com/token \
#      -d "code=AUTH_CODE&client_id=YOUR_CLIENT_ID&\
#      client_secret=YOUR_CLIENT_SECRET&\
#      redirect_uri=http://localhost:8080/callback&\
#      grant_type=authorization_code"

# 3. Store tokens from the response
hop secrets set gmail_refresh_token REFRESH_TOKEN
hop secrets set gmail_access_token ACCESS_TOKEN
hop secrets set gmail_token_expiry 0

# 4. Store Anthropic API key
hop secrets set ANTHROPIC_API_KEY sk-ant-...

# 5. Enable the capability
hop cap enable email-monitor

# 6. Test it
hop cap run email-monitor
```

#### Token Lifecycle

The script handles token refresh automatically:
- Checks access token expiry before each run (5-minute buffer)
- Refreshes via Google's token endpoint using the stored refresh token
- Stores new access token and expiry back in secrets
- Retries on 401 (force refresh if token expired mid-run)
- Refresh tokens don't expire — runs indefinitely without re-authentication

#### Retrieving Briefings

```bash
hop kv get briefings 2026-03-30   # specific date
```

*Last updated: v0.6.33*


---

## Orchestration and Automation

hop's cron system, JS runtime, fleet management, and MCP integration make it a personal cloud orchestration platform. Install hop on a cloud instance, and it becomes an always-on automation backend: periodic tasks, external API integrations, AI workflows, and fleet-wide operations.

### Architecture

```
+-------------------------------------------------------------------+
|  YOUR LAPTOP (client)                                             |
|                                                                   |
|  hop myserver secrets set ANTHROPIC_API_KEY sk-ant-...            |
|  hop myserver cap enable email-monitor                            |
|  hop myserver cap status                                          |
|  hop mcp   (AI agent creates/manages jobs remotely)               |
+-------------------------------------------------------------------+
          | QUIC (P2P, encrypted)
          v
+-------------------------------------------------------------------+
|  CLOUD DAEMON (EC2, Hetzner, etc.)                                |
|                                                                   |
|  hop host (systemd/launchd daemon)                                |
|  +-- Secrets Store (encrypted KV, per-service credentials)        |
|  +-- Cron Scheduler (JS jobs with hop.* + hop.http() + secrets)   |
|  +-- Capabilities (health, security-baseline, email-monitor)      |
|  +-- MCP Server (AI agents create/manage jobs remotely)           |
|  +-- Fleet (optional: fan out to other machines)                  |
+-------------------------------------------------------------------+
```

### Remote Management

Any authenticated peer can manage secrets, capabilities, KV, and cron on remote hosts. The host name always comes first:

```bash
hop myserver secrets set API_KEY value       # store secret on myserver
hop myserver secrets list                    # list secret names on myserver
hop myserver cap enable email-monitor        # enable capability on myserver
hop myserver cap status                      # check enabled capabilities
hop myserver kv get briefings 2026-03-30     # read KV data
hop myserver cron list                       # list cron jobs
```

No Creator role required — any peer with `hop connect` access can use these. Secrets travel over the encrypted QUIC connection and never appear in shell history or process listings.

### Shipped Features

#### 1. Encrypted Secrets Store (v0.4.3)

Credentials are encrypted at rest using ChaCha20-Poly1305 with a key derived from the host's Ed25519 identity. Secrets never leave the host unencrypted.

##### CLI

```bash
hop secrets set ANTHROPIC_API_KEY sk-ant-xxx123
hop secrets set GITHUB_TOKEN ghp_xxx
hop secrets set DB_PASSWORD            # reads from stdin
hop secrets get ANTHROPIC_API_KEY
hop secrets list
hop secrets delete ANTHROPIC_API_KEY

# Remote (from laptop to cloud server)
hop myserver secrets set API_KEY value
hop myserver secrets get API_KEY
```

##### JS Runtime

```javascript
var key = hop.secrets.get("ANTHROPIC_API_KEY");   // returns string or null
hop.secrets.set("token", "new-value");
hop.secrets.delete("old_token");
var names = hop.secrets.list();                    // returns string[]
```

##### MCP

Exposed via the `hop_data` tool with `secrets_set`, `secrets_get`, `secrets_delete`, and `secrets_list` actions. AI agents can store credentials on behalf of the user.

##### Design Notes

- Encryption key derived from the host's Ed25519 secret key (already in `identity.json`)
- Only decrypted in-memory during job execution
- Not included in backup/export unless explicitly requested
- Per-secret ACL possible in the future

#### 2. Native HTTP (v0.4.3)

The JS runtime includes a built-in HTTP client powered by `reqwest::blocking`. No need to shell out to curl.

##### API

```javascript
// Basic request
var resp = hop.http("https://api.example.com/data", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: "test" })
});
var data = resp.json();
// resp.status  → number
// resp.headers → object
// resp.body    → string
// resp.json()  → parsed object

// Bearer auth shorthand
var resp = hop.http.get("https://api.example.com", {
    bearer: hop.secrets.get("API_KEY")
});

// Convenience methods
hop.http.get(url, opts)
hop.http.post(url, opts)
hop.http.put(url, opts)
hop.http.delete(url, opts)

// JSON body shorthand (auto-sets Content-Type)
hop.http.post("https://api.example.com", {
    json: { key: "value" }
});
```

##### Options Object

| Field | Type | Description |
|---|---|---|
| `method` | string | HTTP method (default: `GET`) |
| `headers` | object | Request headers |
| `bearer` | string | Sets `Authorization: Bearer <value>` header |
| `body` | string | Raw request body |
| `json` | any | JSON body (auto-serialized, sets Content-Type) |

##### Security

- Respects sandbox policy: if `no_network` is set, `hop.http()` throws an error
- 30-second timeout per request
- Supported methods: GET, POST, PUT, DELETE, PATCH, HEAD
- DNS resolution happens on the daemon (daemon's network is the egress point)

#### 3. Email Monitor Capability (v0.4.4)

A built-in capability that performs daily AI-powered email triage. See [Capabilities](#capabilities) for the full setup guide.

##### What It Does

Every morning at 7 AM (configurable):

1. **Refreshes Gmail token** — inline OAuth refresh using stored refresh_token
2. **Fetches unread emails** — up to 50 messages via Gmail API
3. **Claude triage** — classifies each email as:
   - **URGENT** — time-sensitive, needs immediate response (stays unread)
   - **ACTION** — needs a response but not urgent (stays unread)
   - **FYI** — informational, newsletters, notifications (marked as read)
4. **Sends briefing email** — structured summary grouped by priority, delivered to your inbox
5. **Marks FYI as read** — only routine messages. Urgent and action-required stay unread in your inbox
6. **Archives briefing** — stored in KV datastore for later retrieval

##### Enable It

```bash
# From your laptop
hop myserver secrets set google_client_id YOUR_CLIENT_ID
hop myserver secrets set google_client_secret YOUR_CLIENT_SECRET
hop myserver secrets set gmail_refresh_token YOUR_REFRESH_TOKEN
hop myserver secrets set ANTHROPIC_API_KEY sk-ant-...
hop myserver cap enable email-monitor

# Test immediately
hop myserver cap run email-monitor

# Check status
hop myserver cap status

# Retrieve past briefings
hop myserver kv get briefings 2026-03-30
```

##### Token Lifecycle

The script handles token refresh automatically:
- Checks access token expiry before each run (5-minute buffer)
- Refreshes via Google's token endpoint using the stored refresh token
- Stores new access token and expiry back in secrets
- Retries on 401 (force refresh if token expired mid-run)
- Refresh tokens don't expire — runs indefinitely without re-authentication

#### 4. Remote Peer Operations (v0.4.4)

Any authenticated peer can manage secrets, KV, cron, and capabilities on remote hosts over the encrypted QUIC connection. Uses the `PeerRequest`/`PeerResponse` protocol — no Creator role required.

```bash
hop myserver secrets set/get/list/delete    # manage secrets
hop myserver cap list/enable/disable/status  # manage capabilities
hop myserver kv get/set/list                 # read/write KV
hop myserver cron list/get                   # inspect cron jobs
```

### OAuth Proxy Flow (`hop auth`) — Shipped

Initiates OAuth on the client machine (where there is a browser) and stores resulting tokens on the remote daemon.

```bash
hop myserver auth gmail
# → Opens browser locally for OAuth consent
# → Tokens sent to myserver via QUIC
# → Stored encrypted in daemon's secrets store
# → "Authenticated with Gmail on myserver."
```

### Planned Features

#### 6. `hop.ai()` Convenience Binding (Planned)

Syntactic sugar over `hop.http()` + `hop.secrets.get()` for LLM calls.

```javascript
var result = hop.ai({
    provider: "anthropic",
    model: "claude-sonnet-4-20250514",
    prompt: "Summarize these emails: " + JSON.stringify(emails),
    max_tokens: 1024,
});
```

#### 7. Interactive Setup Wizard (Planned)

```bash
hop myserver cap setup email-monitor
# → Opens browser for Gmail auth (via hop auth)
# → Prompts for Anthropic API key
# → Enables the capability
# → "Email monitor active on myserver. Next briefing: 7:00 AM UTC"
```

### Implementation Status

| Phase | Feature | Status | Notes |
|---|---|---|---|
| 1 | Encrypted secrets store | **Shipped** (v0.4.3) | ChaCha20-Poly1305, CLI + JS + MCP |
| 2 | Native `hop.http()` in JS | **Shipped** (v0.4.3) | reqwest::blocking, sandbox-aware |
| 3 | Email monitor capability | **Shipped** (v0.4.4) | AI triage, briefing, selective mark-as-read |
| 4 | Remote peer operations | **Shipped** (v0.4.4) | `hop myhost secrets/cap/kv/cron` over QUIC |
| 5 | OAuth proxy (`hop auth`) | **Shipped** | Browser flow on the client, tokens stored on the daemon |
| 6 | `hop.ai()` convenience | Planned | Sugar over hop.http + hop.secrets |
| 7 | Interactive setup wizard | Planned | `hop myhost cap setup email-monitor` |

*Last updated: v0.6.33*
