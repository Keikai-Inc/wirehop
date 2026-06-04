# JavaScript API Reference

hop embeds a QuickJS runtime that exposes the `hop.*` global object. Scripts run in cron jobs and MCP `hop_exec` invocations. All calls are synchronous (no async/await).

## Availability Matrix

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

## Execution

### `hop.exec(host, command)`

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

### `hop.local(command)`

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

## Fleet

### `hop.fleet.list(tag?)`

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

### `hop.fleet.exec(group, command)`

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

## Admin

### `hop.admin.status(host)`

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

### `hop.admin.peers(host)`

List authorized peers on a remote host.

| Param | Type | Description |
|---|---|---|
| `host` | string | Host alias or NodeId |

**Returns:** array of peer objects

**Requires:** backend

```javascript
var peers = hop.admin.peers("myhost");
```

### `hop.admin.invite(host, username?, role?)`

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

### `hop.admin.removePeer(host, prefix)`

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

## Roles

### `hop.roles.list(host)`

List all roles on a remote host.

| Param | Type | Description |
|---|---|---|
| `host` | string | Host alias or NodeId |

**Returns:** array of role objects

**Requires:** backend

```javascript
var roles = hop.roles.list("orch");
```

### `hop.roles.delete(host, name)`

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

## Datastore: Key-Value

### `hop.kv.get(namespace, key)`

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

### `hop.kv.set(namespace, key, value, contentType?)`

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

### `hop.kv.delete(namespace, key)`

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

### `hop.kv.list(namespace, prefix?)`

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

## Datastore: Time Series

### `hop.ts.insert(metric, value, tags?)`

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

### `hop.ts.query(metric, start, end, options?)`

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

### `hop.ts.latest(metric)`

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

## Datastore: Cron

### `hop.cron.list()`

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

## Secrets

### `hop.secrets.get(name)`

Get a secret's decrypted value.

| Param | Type | Description |
|---|---|---|
| `name` | string | Secret name |

**Returns:** string, or `null` if not found

**Requires:** datastore

```javascript
var key = hop.secrets.get("ANTHROPIC_API_KEY");
```

### `hop.secrets.set(name, value)`

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

### `hop.secrets.delete(name)`

Delete a secret.

| Param | Type | Description |
|---|---|---|
| `name` | string | Secret name |

**Returns:** boolean

**Requires:** datastore

```javascript
hop.secrets.delete("old_token");
```

### `hop.secrets.list()`

List all secret names (not values).

**Returns:** string[]

**Requires:** datastore

```javascript
var names = hop.secrets.list();
```

---

## HTTP

### `hop.http(url, options?)`

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

#### Options

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

### `hop.http.get(url, options?)`

Shorthand for `hop.http(url, { method: "GET", ...options })`.

### `hop.http.post(url, options?)`

Shorthand for `hop.http(url, { method: "POST", ...options })`.

### `hop.http.put(url, options?)`

Shorthand for `hop.http(url, { method: "PUT", ...options })`.

### `hop.http.delete(url, options?)`

Shorthand for `hop.http(url, { method: "DELETE", ...options })`.

Supported methods: GET, POST, PUT, DELETE, PATCH, HEAD. Timeout: 30 seconds per request.

---

## Metrics

### `hop.metrics.push(points)`

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

## Utility

### `hop.log(message...)`

Write a message to stderr (visible to the operator, not to the MCP client).

| Param | Type | Description |
|---|---|---|
| `message` | any (variadic) | Values to log (joined with space) |

**Returns:** void

```javascript
hop.log("Processing", items.length, "items");
// Output: [hop.log] Processing 5 items
```

### `hop.sleep(ms)`

Sleep for the specified number of milliseconds.

| Param | Type | Description |
|---|---|---|
| `ms` | number | Milliseconds to sleep |

**Returns:** void

```javascript
hop.sleep(1000);  // sleep 1 second
```

### `hop.id()`

Get the current node's identity.

**Returns:** string (NodeId)

**Requires:** backend (returns placeholder without backend)

```javascript
var nodeId = hop.id();
```

---

## File System (Planned)

### `hop.fs.push()` (Planned)

Push files to a remote host. Not yet implemented in MCP mode.

### `hop.fs.pull()` (Planned)

Pull files from a remote host. Not yet implemented in MCP mode.

---

## Injected Globals

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
