# Security Architecture: Cron Scheduler & Backend Bindings

This document captures known security considerations for the cron scheduler's
access to the `OrchestratorBackend` (specifically `LocalBackend`). Written as a
reference for future hardening work.

Last updated: 2026-03-09

---

## Current Architecture

The daemon's cron scheduler (`spawn_cron_scheduler`) receives an
`Arc<LocalBackend>` that connects through the mux agent (`agent.sock`). When a
cron job fires:

1. A fresh QuickJS runtime is created (64 MB memory limit, 1 MB stack, 30s timeout).
2. `install_live_raw_bindings()` wires the full set of `hop.*` JS bindings.
3. The script executes with the daemon's cryptographic identity.
4. The runtime is dropped — no state persists between executions.

### What the JS runtime can do with a backend

| Binding | Capability |
|---|---|
| `hop.exec(host, cmd)` | Shell command on a single host |
| `hop.fleet.exec(group, cmd)` | Parallel shell commands across a fleet group |
| `hop.fleet.list(tag?)` | Enumerate fleet hosts |
| `hop.admin.status(host)` | Query host status |
| `hop.admin.peers(host)` | List authorized peers |
| `hop.admin.invite(host, ...)` | Mint new invite tokens |
| `hop.admin.removePeer(host, ...)` | Revoke peer authorization |
| `hop.roles.list/delete(host, ...)` | RBAC role management |
| `hop.metrics.push(host, ...)` | Push metrics to a host |
| `hop.kv.*` | Full key-value datastore read/write |
| `hop.ts.*` | Full time-series read/write |

### What the JS runtime cannot do

- No filesystem access (QuickJS has no `fs` module; `require`/`process`/`Deno`/`Bun` are removed)
- No raw network access (no sockets, no fetch — only the `hop.*` bindings)
- No process spawning from JS
- No access to the daemon's private key or config files

---

## Trust Model

### Current trust boundary

Access to the cron system requires one of:

1. **MCP client** connected to `hop mcp` (stdio) — can call `hop_cron` tool
2. **Unix socket** (`daemon.sock`, mode `0o660`) — can send `DsRequest::CronAdd`
3. **Direct file access** to `datastore.redb` — can write serialized `CronJob` records

All three require local shell access as the daemon's user/group. There is no
network-facing cron API.

### Implicit assumption

> If an attacker has local shell as the daemon's user, they already have access
> to the daemon's identity key and `agent.sock`, so cron is not an escalation
> path.

This assumption holds for single-operator deployments. It breaks if:
- MCP is ever exposed over a network transport
- Multi-user access is added to the fleet management layer
- Untrusted or third-party cron scripts are loaded

---

## Known Gaps

### 1. No per-job capability scoping

**Risk:** A monitoring job that only needs `hop.fleet.exec("relay", "uptime")`
also has access to `hop.admin.removePeer()`, `hop.admin.invite()`, and every
other binding.

**Mitigation idea:** Add an optional `capabilities` field to `CronJob` (e.g.
`["exec", "kv"]`). At runtime, only install the bindings the job declares.
Undeclared bindings get stubs that throw. Default to full access for backward
compatibility, but allow locking jobs down.

### 2. McpPolicy not enforced in the cron execution path

**Risk:** The `McpPolicy` system (command blocklists, per-host exec/read/write
restrictions in `policy.rs`) exists but is never checked during
`execute_cron_job`. Cron jobs bypass all policy restrictions.

**Mitigation idea:** Thread `McpPolicy` into the cron execution context. Apply
the same command validation and host restrictions that would apply to an
interactive MCP session. Alternatively, define a separate `CronPolicy` that can
be stricter.

### 3. No audit trail for cron mutations

**Risk:** `AuditEntry` infrastructure exists (`audit.rs`) but is not called from
cron job creation, modification, deletion, or execution. There is no record of
who created a job, when it was changed, or what it produced.

**Mitigation idea:** Log `AuditEntry` events for:
- Job creation/update/deletion (with actor identity if available)
- Job execution start, completion, and failure (with script hash and output summary)

### 4. No script integrity verification

**Risk:** Cron scripts are stored as plain text in the redb datastore. A
corrupted or tampered datastore file could inject arbitrary code that runs with
daemon authority. There is no signing or hash-at-rest.

**Mitigation idea:** Store a SHA-256 hash at creation time. Before execution,
recompute the hash and compare. Log a warning (or refuse to execute) on
mismatch. This detects tampering but doesn't prevent it — signing would require
a key management story.

### 5. No namespace isolation for datastore access

**Risk:** Every cron job can read/write any KV key and any time-series metric.
A buggy monitoring script could overwrite data belonging to a different job, or
a malicious script could exfiltrate data from the entire datastore.

**Mitigation idea:** Prefix-scope KV and TS access per job. For example, a job
with `id: "relay-monitor"` could be restricted to keys under
`cron/relay-monitor/` unless explicitly granted broader access.

### 6. No rate limiting on cron job creation

**Risk:** An MCP client or socket connection could create thousands of cron jobs
(e.g. every-15-second schedules) that overwhelm the scheduler and the fleet.

**Mitigation idea:** Cap the total number of enabled cron jobs (e.g. 100). Rate
limit job creation per time window.

---

## Priority Order for Hardening

If and when the trust model expands beyond single-operator:

1. **Per-job capability scoping** — highest value, limits blast radius of any single job
2. **McpPolicy enforcement in cron path** — leverages existing infrastructure
3. **Audit logging** — visibility into what's happening
4. **Script integrity hashing** — tamper detection
5. **Namespace isolation** — defense in depth for multi-job scenarios
6. **Rate limiting** — DoS prevention

---

## References

- Cron scheduler: `crates/hop-mcp/src/cron.rs`
- JS runtime & bindings: `crates/hop-mcp/src/js/mod.rs`, `crates/hop-mcp/src/js/bindings.rs`
- LocalBackend: `crates/hop-mcp/src/backend/local.rs`
- McpPolicy: `crates/hop-mcp/src/policy.rs`
- Datastore cron storage: `crates/hop-core/src/datastore/cron.rs`
- Daemon entry point: `crates/hop-cli/src/main.rs` (line ~379)
