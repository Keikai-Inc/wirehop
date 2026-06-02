# MCP Server

hop includes an MCP (Model Context Protocol) server for AI agent integration. It exposes hop's capabilities as structured tools over JSON-RPC 2.0 on stdio.

## Starting the Server

```bash
hop mcp
```

This starts the MCP server on stdin/stdout, suitable for use as a subprocess by AI agent frameworks (e.g. Claude Desktop, Cursor).

## Tools

The server registers up to 4 tools. The `hop_data` and `hop_cron` tools are only available when a datastore is present (host mode).

### hop_exec

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

### hop_data

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

### hop_cron

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

### hop_skills

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

## Skills Library

The skills library is an embedded reference system with operational recipes and code examples. Skills are organized into categories and searchable by keyword.

### Categories

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

### Skill Structure

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

### How Agents Use Skills

1. Call `hop_skills` with no arguments to see available categories
2. Browse a category or search by keyword to find relevant skills
3. Look up a specific skill by ID to get code examples
4. Use the examples to write `hop_exec` code

Parent skills (like `install/package`) automatically inline their sub-skills (e.g. `install/package-apt`, `install/package-brew`) when looked up by ID.

### Search

Keyword search scores matches across title (3x), ID (2.5x), tags (2x), description (1x), and example code (0.5x). Returns top N results ranked by relevance.

*Last updated: v0.6.33*
