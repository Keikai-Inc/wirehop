# AI & Scripting

The MCP server (tools, skills, AI-agent integration) and the complete `hop.*` JS runtime API.


---

## MCP Server

hop includes an MCP (Model Context Protocol) server for AI agent integration. It exposes hop's capabilities as structured tools over JSON-RPC 2.0 on stdio.

### Starting the Server

```bash
hop mcp
```

This starts the MCP server on stdin/stdout, suitable for use as a subprocess by AI agent frameworks (e.g. Claude Desktop, Cursor).

### Tools

The server registers up to 4 tools. The `hop_data` and `hop_cron` tools are only available when a datastore is present (host mode).

#### hop_exec

Execute JavaScript in a sandboxed runtime with `hop.*` fleet management bindings.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `code` | string | yes | JavaScript code; top-level `await` supported |
| `timeout_secs` | integer | no | Execution timeout (default: 30, max: 300) |

The `hop` global object provides access to `exec()`, `fleet`, `admin`, `roles`, and file transfer APIs. Call `hop_skills` first to learn the available API.

**Error handling**: timeout errors suggest increasing `timeout_secs`; memory errors indicate the 64 MB limit was hit.

```json
{
  "name": "hop_exec",
  "arguments": {
    "code": "const result = await hop.exec('web-01', 'uptime'); return result;",
    "timeout_secs": 60
  }
}
```

#### hop_data

Store and query data in hop's embedded datastore. Supports key-value, time-series, and encrypted secrets.

| Parameter | Type | Required for | Description |
|---|---|---|---|
| `action` | string | all | Operation (see table below) |
| `namespace` | string | kv_* | KV namespace |
| `key` | string | kv_get/set/delete | KV key |
| `value` | any | kv_set, ts_insert, secrets_set | Value to store |
| `content_type` | string | | MIME type (default: `application/json`) |
| `prefix` | string | | Key prefix filter for kv_list |
| `metric` | string | ts_* | Metric name |
| `start` | integer | | Start timestamp (unix ms) |
| `end` | integer | | End timestamp (unix ms) |
| `tags` | object | | Tags for ts_insert or filter for ts_query |
| `limit` | integer | | Max results for ts_query |
| `name` | string | secrets_* | Secret name |

**Actions**:

| Action | Description |
|---|---|
| `kv_get` | Get a KV entry by namespace + key |
| `kv_set` | Set a KV entry |
| `kv_delete` | Delete a KV entry |
| `kv_list` | List KV entries in a namespace (optional prefix) |
| `ts_insert` | Insert a time-series data point (value must be a number) |
| `ts_query` | Query time-series range |
| `ts_latest` | Get most recent data point for a metric |
| `secrets_get` | Decrypt and return a secret |
| `secrets_set` | Encrypt and store a secret |
| `secrets_delete` | Delete a secret |
| `secrets_list` | List secret names (not values) |

```json
{
  "name": "hop_data",
  "arguments": {
    "action": "kv_set",
    "namespace": "config",
    "key": "deploy_target",
    "value": "production"
  }
}
```

#### hop_cron

Manage scheduled cron jobs that execute JavaScript in hop's sandboxed runtime.

| Parameter | Type | Required for | Description |
|---|---|---|---|
| `action` | string | all | Operation (see table below) |
| `job_id` | string | get/delete/enable/disable | Job ID |
| `name` | string | create/ensure | Human-readable name |
| `schedule` | string | create/ensure | 6-field cron expression |
| `script` | string | create/ensure | JavaScript source |
| `tags` | array | | Fleet targeting tags |
| `tag_filter` | string | | Filter for list |
| `targets` | string | | Fleet target tag; matching hosts injected as `hop.targets` |
| `catalog_id` | string | ensure (required) | Dedup identifier |
| `sandbox_preset` | string | | `monitor`, `audit`, or `deploy` |

**Actions**:

| Action | Description |
|---|---|
| `create` | Create a new cron job |
| `ensure` | Idempotent create -- returns existing job if `catalog_id` matches |
| `list` | List jobs (optional `tag_filter`) |
| `get` | Get full job details |
| `enable` | Enable a job (recomputes next_run) |
| `disable` | Disable a job |
| `delete` | Remove a job |

```json
{
  "name": "hop_cron",
  "arguments": {
    "action": "ensure",
    "catalog_id": "fleet-health",
    "name": "Fleet Health Check",
    "schedule": "0 */5 * * * *",
    "script": "const hosts = await hop.fleet.list(); for (const h of hosts) { await hop.ts.insert('health.' + h.hostname, 1); }",
    "targets": "web",
    "sandbox_preset": "monitor"
  }
}
```

#### hop_skills

Look up hop documentation, code examples, and operational recipes. Call this before writing `hop_exec` code to understand available APIs.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `query` | string | no | Natural language search (e.g. `"check disk usage across fleet"`) |
| `category` | string | no | Browse by category (see list below) |
| `skill_id` | string | no | Direct lookup (e.g. `"monitor/cpu-usage"`) |

**Priority**: `skill_id` > `category` > `query`. With no arguments, lists all categories.

```json
{
  "name": "hop_skills",
  "arguments": {
    "query": "deploy application to fleet"
  }
}
```

---

### Skills Library

The skills library is an embedded reference system with operational recipes and code examples. Skills are organized into categories and searchable by keyword.

#### Categories

| Category | Description |
|---|---|
| `getting-started` | First-time setup and basic usage |
| `fleet` | Fleet operations and management |
| `roles` | RBAC role configuration |
| `admin` | Remote administration |
| `discover` | Host discovery and inventory |
| `install` | Package installation (multi-OS) |
| `services` | Service management |
| `monitor` | System monitoring and metrics |
| `security` | Security auditing and baselines |
| `files` | File transfer and management |
| `troubleshoot` | Debugging and diagnostics |
| `recipes` | Multi-step operational workflows |
| `datastore` | KV, time-series, and secrets usage |

#### Skill Structure

Each skill contains:

| Field | Description |
|---|---|
| `id` | Unique identifier (e.g. `monitor/cpu-usage`) |
| `category` | Category name |
| `title` | Human-readable title |
| `description` | What the skill covers |
| `tags` | Search keywords |
| `prerequisites` | Required skills or setup |
| `examples` | Code examples with expected output |
| `pitfalls` | Common mistakes to avoid |
| `related` | Links to related skills |
| `sub_skills` | Child skills (for intent/parent skills) |

#### How Agents Use Skills

1. Call `hop_skills` with no arguments to see available categories
2. Browse a category or search by keyword to find relevant skills
3. Look up a specific skill by ID to get code examples
4. Use the examples to write `hop_exec` code

Parent skills (like `install/package`) automatically inline their sub-skills (e.g. `install/package-apt`, `install/package-brew`) when looked up by ID.

#### Search

Keyword search scores matches across title (3x), ID (2.5x), tags (2x), description (1x), and example code (0.5x). Returns top N results ranked by relevance.

*Last updated: v0.6.33*


---

## JavaScript API Reference

hop embeds a QuickJS runtime that exposes the `hop.*` global object. Scripts run in cron jobs and MCP `hop_exec` invocations. All calls are synchronous (no async/await).

### Availability Matrix

| Binding group | Requires backend | Requires datastore | Available in cron | Available in MCP |
|---|---|---|---|---|
| Execution (`hop.exec`, `hop.local`) | Yes / No | No | Yes (local only without backend) | Yes |
| Fleet/Admin/Roles | Yes | No | No (stub) | Yes |
| Datastore (KV/TS/Cron/Secrets) | No | Yes | Yes | Yes |
| HTTP | No | No | Yes | Yes |
| Utility (`hop.log`, `hop.sleep`, `hop.id`) | No | No | Yes | Yes |
| Metrics | Yes | No | No (stub) | Yes |

**Sandbox restrictions:** When a `SandboxPolicy` is active:
- `hop.exec()` uses `exec_sandboxed` on the remote host
- `hop.local()` validates commands against the policy and applies OS-level sandboxing (macOS sandbox-exec, Linux Landlock; `no_network` enforced via Landlock TCP rules on kernel 6.7+)
- `hop.readFile()` / `hop.writeFile()` are confined to the policy's `allowed_paths`; `hop.writeFile()` additionally refuses to write under a `read_only` policy (v0.6.37)
- `hop.http()` throws if `no_network` is set; for any restricted (non-empty) policy it also blocks SSRF to internal/metadata addresses and does not follow redirects (see [`hop.http`](#hophttpurl-options) below)

**Removed globals:** `require`, `process`, `Deno`, `Bun` are removed from the JS context.

---

### Execution

#### `hop.exec(host, command)`

Execute a shell command on a remote host.

| Param | Type | Description |
|---|---|---|
| `host` | string | Host alias, NodeId, or invite token |
| `command` | string | Shell command (passed to `/bin/sh -c`) |

**Returns:** `{ stdout: string, stderr: string, exit_code: number }`

**Requires:** backend

```javascript
var r = hop.exec("myhost", "uname -a");
hop.log(r.stdout);            // "Linux myhost 5.15..."
if (r.exit_code !== 0) hop.log("ERROR: " + r.stderr);
```

#### `hop.local(command)`

Execute a shell command on the local machine (where the daemon runs).

| Param | Type | Description |
|---|---|---|
| `command` | string | Shell command (passed to `/bin/sh -c`) |

**Returns:** `{ stdout: string, stderr: string, exit_code: number }`

**Requires:** nothing (always available)

```javascript
var r = hop.local("df -h /");
hop.log(r.stdout);
```

---

### Fleet

#### `hop.fleet.list(tag?)`

List fleet members, optionally filtered by tag.

| Param | Type | Description |
|---|---|---|
| `tag` | string (optional) | Filter by tag |

**Returns:** array of fleet member objects

**Requires:** backend

```javascript
var hosts = hop.fleet.list("web");
for (var i = 0; i < hosts.length; i++) {
    hop.log(hosts[i].name);
}
```

#### `hop.fleet.exec(group, command)`

Execute a command on all hosts in a fleet group.

| Param | Type | Description |
|---|---|---|
| `group` | string | Group/role name |
| `command` | string | Shell command |

**Returns:** array of execution results

**Requires:** backend

```javascript
var results = hop.fleet.exec("web", "systemctl status nginx");
```

---

### Admin

#### `hop.admin.status(host)`

Get status of a remote host.

| Param | Type | Description |
|---|---|---|
| `host` | string | Host alias or NodeId |

**Returns:** status object (version, peer count, active sessions)

**Requires:** backend

```javascript
var s = hop.admin.status("myhost");
hop.log("Version: " + s.version);
```

#### `hop.admin.peers(host)`

List authorized peers on a remote host.

| Param | Type | Description |
|---|---|---|
| `host` | string | Host alias or NodeId |

**Returns:** array of peer objects

**Requires:** backend

```javascript
var peers = hop.admin.peers("myhost");
```

#### `hop.admin.invite(host, username?, role?)`

Create an invite token on a remote host.

| Param | Type | Description |
|---|---|---|
| `host` | string | Host alias or NodeId |
| `username` | string (optional) | Unix username for the invite |
| `role` | string (optional) | Role name |

**Returns:** string (invite token)

**Requires:** backend

```javascript
var token = hop.admin.invite("myhost", "alice");
```

#### `hop.admin.removePeer(host, prefix)`

Remove a peer from a remote host.

| Param | Type | Description |
|---|---|---|
| `host` | string | Host alias or NodeId |
| `prefix` | string | NodeId prefix of the peer to remove |

**Returns:** `{ success: boolean }`

**Requires:** backend

```javascript
hop.admin.removePeer("myhost", "abc123");
```

---

### Roles

#### `hop.roles.list(host)`

List all roles on a remote host.

| Param | Type | Description |
|---|---|---|
| `host` | string | Host alias or NodeId |

**Returns:** array of role objects

**Requires:** backend

```javascript
var roles = hop.roles.list("orch");
```

#### `hop.roles.delete(host, name)`

Delete a role on a remote host.

| Param | Type | Description |
|---|---|---|
| `host` | string | Host alias or NodeId |
| `name` | string | Role name |

**Returns:** void

**Requires:** backend

```javascript
hop.roles.delete("orch", "intern");
```

---

### Datastore: Key-Value

#### `hop.kv.get(namespace, key)`

Get a value by key.

| Param | Type | Description |
|---|---|---|
| `namespace` | string | Namespace (e.g., `"default"`) |
| `key` | string | Key to look up |

**Returns:** parsed JSON value, or `null` if not found

**Requires:** datastore

```javascript
var val = hop.kv.get("default", "config:theme");
```

#### `hop.kv.set(namespace, key, value, contentType?)`

Set a key-value pair.

| Param | Type | Description |
|---|---|---|
| `namespace` | string | Namespace |
| `key` | string | Key |
| `value` | any | Value (will be JSON-serialized) |
| `contentType` | string (optional) | MIME type (default: `application/json`) |

**Returns:** void

**Requires:** datastore

```javascript
hop.kv.set("default", "config:theme", "dark");
hop.kv.set("default", "stats:today", { visits: 42, errors: 0 });
```

#### `hop.kv.delete(namespace, key)`

Delete a key.

| Param | Type | Description |
|---|---|---|
| `namespace` | string | Namespace |
| `key` | string | Key to delete |

**Returns:** boolean

**Requires:** datastore

```javascript
hop.kv.delete("default", "temp:data");
```

#### `hop.kv.list(namespace, prefix?)`

List entries matching an optional prefix.

| Param | Type | Description |
|---|---|---|
| `namespace` | string | Namespace |
| `prefix` | string (optional) | Key prefix to filter by |

**Returns:** array of `{ key, value, contentType, updatedAt }`

**Requires:** datastore

```javascript
var entries = hop.kv.list("default", "cap:health:");
```

---

### Datastore: Time Series

#### `hop.ts.insert(metric, value, tags?)`

Insert a data point.

| Param | Type | Description |
|---|---|---|
| `metric` | string | Metric name (e.g., `"health.load"`) |
| `value` | number | Numeric value |
| `tags` | object (optional) | Key-value tags for filtering |

**Returns:** void

**Requires:** datastore

```javascript
hop.ts.insert("health.load", 1.5, { host: "web-01" });
hop.ts.insert("requests", 42);
```

#### `hop.ts.query(metric, start, end, options?)`

Query data points in a time range.

| Param | Type | Description |
|---|---|---|
| `metric` | string | Metric name |
| `start` | number | Start timestamp (ms since epoch) |
| `end` | number | End timestamp (ms since epoch) |
| `options` | object (optional) | `{ limit?: number, tags?: object }` |

**Returns:** array of `{ timestamp, value, tags }`

**Requires:** datastore

```javascript
var now = Date.now();
var points = hop.ts.query("health.load", now - 3600000, now);
var filtered = hop.ts.query("health.load", now - 3600000, now, {
    tags: { host: "web-01" },
    limit: 100
});
```

#### `hop.ts.latest(metric)`

Get the most recent data point.

| Param | Type | Description |
|---|---|---|
| `metric` | string | Metric name |

**Returns:** `{ timestamp, value, tags }` or `null`

**Requires:** datastore

```javascript
var latest = hop.ts.latest("health.load");
if (latest) hop.log("Current load: " + latest.value);
```

---

### Datastore: Cron

#### `hop.cron.list()`

List all cron jobs.

**Returns:** array of `{ id, name, schedule, enabled }`

**Requires:** datastore

```javascript
var jobs = hop.cron.list();
for (var i = 0; i < jobs.length; i++) {
    hop.log(jobs[i].name + " [" + (jobs[i].enabled ? "on" : "off") + "]");
}
```

---

### Secrets

#### `hop.secrets.get(name)`

Get a secret's decrypted value.

| Param | Type | Description |
|---|---|---|
| `name` | string | Secret name |

**Returns:** string, or `null` if not found

**Requires:** datastore

```javascript
var key = hop.secrets.get("ANTHROPIC_API_KEY");
```

#### `hop.secrets.set(name, value)`

Store an encrypted secret.

| Param | Type | Description |
|---|---|---|
| `name` | string | Secret name |
| `value` | string | Secret value |

**Returns:** void

**Requires:** datastore

```javascript
hop.secrets.set("gmail_access_token", newToken);
```

#### `hop.secrets.delete(name)`

Delete a secret.

| Param | Type | Description |
|---|---|---|
| `name` | string | Secret name |

**Returns:** boolean

**Requires:** datastore

```javascript
hop.secrets.delete("old_token");
```

#### `hop.secrets.list()`

List all secret names (not values).

**Returns:** string[]

**Requires:** datastore

```javascript
var names = hop.secrets.list();
```

---

### HTTP

#### `hop.http(url, options?)`

Make an HTTP request.

| Param | Type | Description |
|---|---|---|
| `url` | string | Request URL |
| `options` | object (optional) | See options table below |

**Returns:** `{ status: number, headers: object, body: string, json: function }`

**Requires:** nothing (blocked if `no_network` sandbox policy)

**SSRF protection (restricted peers, v0.6.37):** when the caller runs under any
restricted (non-empty) `SandboxPolicy`, `hop.http` is hardened against
server-side request forgery:
- Only `http`/`https` URLs are allowed.
- The request is **rejected** if the host resolves to a loopback
  (`127.0.0.0/8`, `::1`), private (`10/8`, `172.16/12`, `192.168/16`, IPv6 ULA
  `fc00::/7`), link-local (`169.254.0.0/16` incl. the `169.254.169.254` cloud
  metadata endpoint, IPv6 `fe80::/10`), CGNAT (`100.64.0.0/10`, hop's own VPN
  range), or unspecified address — including IPv4-mapped IPv6 forms.
- Redirects are **not** followed (a redirect could otherwise escape the
  destination check).

Unrestricted (owner/full-access) automation is unchanged and may still reach
internal services intentionally.

##### Options

| Field | Type | Description |
|---|---|---|
| `method` | string | HTTP method (default: `"GET"`) |
| `headers` | object | Request headers |
| `bearer` | string | Sets `Authorization: Bearer <value>` |
| `body` | string | Raw request body |
| `json` | any | JSON body (auto-serialized, sets Content-Type) |

```javascript
// GET with bearer auth
var resp = hop.http("https://api.example.com/data", {
    bearer: hop.secrets.get("API_KEY")
});
var data = resp.json();

// POST with JSON body
var resp = hop.http("https://api.example.com/submit", {
    method: "POST",
    json: { name: "test" }
});
```

#### `hop.http.get(url, options?)`

Shorthand for `hop.http(url, { method: "GET", ...options })`.

#### `hop.http.post(url, options?)`

Shorthand for `hop.http(url, { method: "POST", ...options })`.

#### `hop.http.put(url, options?)`

Shorthand for `hop.http(url, { method: "PUT", ...options })`.

#### `hop.http.delete(url, options?)`

Shorthand for `hop.http(url, { method: "DELETE", ...options })`.

Supported methods: GET, POST, PUT, DELETE, PATCH, HEAD. Timeout: 30 seconds per request.

---

### Metrics

#### `hop.metrics.push(points)`

Push metric points to the orchestrator.

| Param | Type | Description |
|---|---|---|
| `points` | array | Array of `{ metric, value, tags }` objects |

**Returns:** `{ count: number }`

**Requires:** backend

```javascript
hop.metrics.push([
    { metric: "deploy.duration", value: 12.5, tags: { app: "web" } }
]);
```

---

### Utility

#### `hop.log(message...)`

Write a message to stderr (visible to the operator, not to the MCP client).

| Param | Type | Description |
|---|---|---|
| `message` | any (variadic) | Values to log (joined with space) |

**Returns:** void

```javascript
hop.log("Processing", items.length, "items");
// Output: [hop.log] Processing 5 items
```

#### `hop.sleep(ms)`

Sleep for the specified number of milliseconds.

| Param | Type | Description |
|---|---|---|
| `ms` | number | Milliseconds to sleep |

**Returns:** void

```javascript
hop.sleep(1000);  // sleep 1 second
```

#### `hop.id()`

Get the current node's identity.

**Returns:** string (NodeId)

**Requires:** backend (returns placeholder without backend)

```javascript
var nodeId = hop.id();
```

---

### File System (Planned)

#### `hop.fs.push()` (Planned)

Push files to a remote host. Not yet implemented in MCP mode.

#### `hop.fs.pull()` (Planned)

Pull files from a remote host. Not yet implemented in MCP mode.

---

### Injected Globals

These are set by the cron scheduler before script execution, not by user code:

| Global | Type | Description |
|---|---|---|
| `hop.targets` | array | Fleet targets injected from `--targets` flag. Each: `{ name, tags }` |
| `hop.params` | object | Parameters injected from `--param key=value` flags |

```javascript
var targets = hop.targets || [];
if (targets.length === 0) {
    // local-only mode
    var r = hop.local("uptime");
} else {
    // fleet fan-out mode
    for (var i = 0; i < targets.length; i++) {
        var r = hop.exec(targets[i].name, "uptime");
    }
}
```

*Last updated: v0.6.33*
