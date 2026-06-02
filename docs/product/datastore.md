# Datastore

hop embeds a persistent datastore (redb) on every host. It provides key-value storage, time-series metrics, encrypted secrets, and cron-scheduled JavaScript execution. Data survives restarts and is accessible via CLI, JavaScript bindings, and the MCP `hop_data`/`hop_cron` tools.

## Key-Value Store

Namespaced key-value storage with content-type metadata.

### Data Model

| Field | Type | Description |
|---|---|---|
| `namespace` | string | Logical grouping (e.g. `"config"`, `"cache"`) |
| `key` | string | Unique within namespace |
| `value` | bytes | Arbitrary payload |
| `content_type` | string | MIME type hint (`application/json`, `text/plain`) |
| `updated_at` | u64 | Unix timestamp in milliseconds |

Namespaces isolate keys -- a key in `"config"` is independent of the same key in `"cache"`.

### CLI: `hop kv`

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

### JavaScript: `hop.kv.*`

```javascript
await hop.kv.set("config", "ttl", { value: 3600 });
const entry = await hop.kv.get("config", "ttl");
const items = await hop.kv.list("config", "");         // all keys in namespace
const items = await hop.kv.list("config", "metric:");  // prefix filter
await hop.kv.delete("config", "ttl");
```

### MCP: `hop_data` tool

| Action | Required params | Description |
|---|---|---|
| `kv_get` | `namespace`, `key` | Get a value |
| `kv_set` | `namespace`, `key`, `value` | Set a value (content_type defaults to `application/json`) |
| `kv_delete` | `namespace`, `key` | Delete a key |
| `kv_list` | `namespace` | List keys; optional `prefix` filter |

---

## Time-Series

Append-only metric storage with tag-based filtering. Each data point is a `(timestamp, value, tags)` tuple keyed by metric name.

### Data Model

| Field | Type | Description |
|---|---|---|
| `metric` | string | Metric name (e.g. `"cpu.usage"`, `"mem.free"`) |
| `value` | f64 | Numeric measurement |
| `tags` | map | Optional key-value labels (e.g. `{"host": "web-01", "cpu": "0"}`) |
| `timestamp` | u64 | Unix ms; auto-set on insert, or explicit |

### Query Parameters

| Field | Type | Description |
|---|---|---|
| `metric` | string | Required |
| `start` | u64 | Start of range (unix ms, inclusive) |
| `end` | u64 | End of range (unix ms, inclusive) |
| `tags_filter` | map | Only return points matching all specified tags |
| `limit` | usize | Max results |

### CLI: `hop ts`

```bash
# Most recent data point
hop ts latest cpu.usage

# Query a time range (default: last 1 hour)
hop ts query cpu.usage
hop ts query cpu.usage --last 30m
hop ts query cpu.usage --last 7d
```

### JavaScript: `hop.ts.*`

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

### MCP: `hop_data` tool

| Action | Required params | Optional params | Description |
|---|---|---|---|
| `ts_insert` | `metric`, `value` (number) | `tags` | Insert a data point at current time |
| `ts_latest` | `metric` | | Most recent point |
| `ts_query` | `metric` | `start`, `end`, `tags`, `limit` | Range query |

---

## Cron Scheduling

Persistent cron jobs that execute JavaScript in hop's sandboxed runtime. Jobs survive restarts.

### CronJob Fields

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

### CLI: `hop cron`

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

### JavaScript: `hop.cron.list`

```javascript
const jobs = await hop.cron.list();
```

### MCP: `hop_cron` tool

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

## Secrets

Encrypted secret storage using ChaCha20-Poly1305 with a per-host key derived from the node identity. Values are encrypted at rest; only names are queryable without decryption.

### Data Model

| Field | Type | Description |
|---|---|---|
| `name` | string | Secret identifier (e.g. `API_KEY`) |
| `ciphertext` | bytes | ChaCha20-Poly1305 encrypted value + 16-byte auth tag |
| `nonce` | [u8; 12] | Random nonce per encryption |
| `updated_at` | u64 | Unix ms |

### CLI: `hop secrets`

```bash
hop secrets set API_KEY "sk-test-123"
hop secrets set DB_PASSWORD                  # reads from stdin if value omitted
hop secrets get API_KEY
hop secrets list                             # names only, not values
hop secrets delete API_KEY
```

### JavaScript: `hop.secrets.*`

```javascript
await hop.secrets.set("API_KEY", "sk-test-123");
const value = await hop.secrets.get("API_KEY");
const names = await hop.secrets.list();
await hop.secrets.delete("API_KEY");
```

### MCP: `hop_data` tool

| Action | Required params | Description |
|---|---|---|
| `secrets_get` | `name` | Decrypt and return value |
| `secrets_set` | `name`, `value` | Encrypt and store |
| `secrets_delete` | `name` | Remove |
| `secrets_list` | | List names only |

---

## Retention Policies

Time-series data supports TTL-based cleanup via `ts_purge_before(metric, timestamp)`. This removes all data points for a metric older than the given timestamp. Purge is a local-only operation (daemon-internal housekeeping); it is not exposed over remote connections.

```rust
// Delete all cpu.usage points older than 7 days
let cutoff = now_ms - (7 * 24 * 3600 * 1000);
datastore.ts_purge_before("cpu", cutoff)?;
```

KV and secrets entries do not have automatic expiry; delete them explicitly when no longer needed.

*Last updated: v0.6.33*
