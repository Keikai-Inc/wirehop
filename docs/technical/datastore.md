# Datastore

## Overview

The embedded datastore provides KV, time-series, cron job storage, and encrypted secrets. It operates in two modes depending on the caller:

```rust
pub struct Datastore {
    inner: Arc<DatastoreInner>,  // Thread-safe, clone freely
}

pub(crate) enum DatastoreInner {
    Local {
        db: redb::Database,              // Direct redb access
        secrets_key: Option<[u8; 32]>,   // ChaCha20-Poly1305 AEAD key
    },
    Remote(socket::DaemonConnection),    // IPC to daemon's Unix socket
}
```

- **Local mode**: used by the daemon (`hop host`). Direct access to the redb database file.
- **Remote mode**: used by `hop mcp` and other out-of-process consumers. Connects to the daemon's Unix socket and sends requests over IPC.

### Opening

```rust
Datastore::open(path)                    // Local, no secrets support
Datastore::open_with_secrets(path, key)  // Local, with AEAD key for secrets
Datastore::connect(config_dir)           // Remote, connects to daemon.sock
```

On macOS/Linux, if the parent directory has the setgid bit (0o2000), the database file permissions are set to 0660 so unprivileged users in the same group can access it.

## redb Tables

The tables are defined in `crates/hop-core/src/datastore/tables.rs` (plus a user-scoped `secrets_v2`):

```rust
// KV store: composite key (namespace, key) -> bincode-encoded KvEntry
const KV_TABLE: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("kv");

// Time-series: composite key (metric_name, unix_ms) -> bincode-encoded MetricPoint
const TS_TABLE: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("ts");

// Cron jobs: job_id -> bincode-encoded CronJob
const CRON_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("cron");

// Metadata: key -> bincode-encoded value (schema version, retention, etc.)
const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

// Encrypted secrets: secret_name -> bincode-encoded SealedSecret
const SECRETS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("secrets");

// Per-node audit & flow log: (series, packed_id) -> JSON-encoded AuditEvent.
// packed_id = (ts_ms << 20) | seq keeps same-ms events distinct + time-ordered.
const AUDIT_TABLE: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("audit");
```

Most values are stored as `&[u8]` (bincode-encoded). Tables are created lazily on first write. Reads on non-existent tables return empty results via `TableDoesNotExist` error handling. **Exception:** `AUDIT_TABLE` values are **JSON**-encoded (not bincode) so the audit-event schema can gain fields across upgrades without breaking old records — bincode is non-self-describing and would fail to decode an older record once a field is added. See `crate::audit` (the OTel-aligned schema) and `datastore::audit` (`audit_append` / `audit_query` / `audit_purge_before`).

## Data Types

Defined in `crates/hop-core/src/datastore/types.rs`:

```rust
pub struct KvEntry {
    pub value: Vec<u8>,           // Raw bytes
    pub content_type: String,     // MIME type hint ("application/json", "text/plain")
    pub updated_at: u64,          // Unix timestamp in milliseconds
}

pub struct MetricPoint {
    pub value: f64,
    pub tags: BTreeMap<String, String>,  // e.g. {"host": "web-01", "cpu": "0"}
}

pub struct CronJob {
    pub id: String,
    pub name: String,
    pub schedule: String,         // Cron expression: "*/5 * * * *"
    pub script: String,           // JavaScript source code
    pub enabled: bool,
    pub last_run: Option<u64>,    // Unix ms of last successful run
    pub next_run: u64,            // Unix ms of next scheduled run
    pub created_at: u64,
    pub tags: Vec<String>,        // Fleet targeting: ["fleet:web"]
    pub targets: Option<String>,  // Fleet target tag for host resolution
    pub catalog_id: Option<String>,  // Dedup identifier
    pub sandbox: Option<SandboxPolicy>,
}

pub struct SealedSecret {
    pub ciphertext: Vec<u8>,      // ChaCha20-Poly1305 ciphertext + 16-byte auth tag
    pub nonce: [u8; 12],          // Random nonce
    pub updated_at: u64,          // Unix ms
}

pub struct TimeSeriesQuery {
    pub metric: String,
    pub start: u64,               // Unix ms, inclusive
    pub end: u64,                 // Unix ms, inclusive
    pub tags_filter: Option<BTreeMap<String, String>>,
    pub limit: Option<usize>,
}
```

## IPC Protocol

### DsRequest

Sent by Remote clients to the daemon over the Unix socket:

```rust
pub enum DsRequest {
    // KV operations
    KvGet { ns: String, key: String },
    KvSet { ns: String, key: String, entry: KvEntry },
    KvDelete { ns: String, key: String },
    KvList { ns: String, prefix: String },

    // Time-series operations
    TsInsert { metric: String, point: MetricPoint },
    TsInsertAt { metric: String, ts: u64, point: MetricPoint },
    TsQuery { query: TimeSeriesQuery },
    TsLatest { metric: String },

    // Cron operations
    CronAdd { job: CronJob },
    CronRemove { id: String },
    CronList,
    CronGet { id: String },
    CronFindByCatalogId { catalog_id: String },
    CronGetDue { now_ms: u64 },
    CronUpdateLastRun { id: String, ts: u64, next_run: u64 },

    // Secrets operations
    SecretsGet { name: String },
    SecretsSet { name: String, value: Vec<u8> },
    SecretsDelete { name: String },
    SecretsList,
}
```

### DsResponse

```rust
pub enum DsResponse {
    Ok,
    Bool(bool),
    Error(String),
    KvEntry(Option<KvEntry>),
    KvEntries(Vec<(String, KvEntry)>),
    TsPoints(Vec<(u64, MetricPoint)>),
    TsLatest(Option<(u64, MetricPoint)>),
    CronJob(Box<Option<CronJob>>),
    CronJobs(Vec<CronJob>),
    SecretValue(Option<Vec<u8>>),
    SecretNames(Vec<String>),
}
```

## Unix Socket Transport

### Socket Path

```
<config_dir>/daemon.sock
```

The socket is created by `spawn_listener()` when the daemon starts and cleaned up on shutdown. Stale sockets from previous crashes are removed on bind. Permissions are set to **0660** (owner + group).

### Frame Format

Both client and server use the same framing:

```
+--4 bytes (BE)--+--N bytes--+
|    length      |  payload  |
+----------------+-----------+
```

- **Length**: 4-byte big-endian `u32`
- **Payload**: bincode-encoded `DsRequest` or `DsResponse`
- **Max frame size**: 16 MiB (16 * 1024 * 1024 bytes). Frames exceeding this are rejected.

### Client (`DaemonConnection`)

```rust
pub struct DaemonConnection {
    stream: Mutex<UnixStream>,  // Mutex for thread-safety
}
```

The client is **synchronous** (`std::os::unix::net::UnixStream`), used by the JS runtime which runs on a dedicated OS thread. The `request()` method serializes a `DsRequest`, sends the frame, reads the response frame, and deserializes a `DsResponse`.

### Server (`spawn_listener`)

The server is **async** (tokio `UnixListener`). Each accepted connection spawns a per-connection handler task. Request dispatch to the datastore uses `tokio::task::spawn_blocking()` since redb operations are synchronous.

```
accept loop
  └─ per-connection task
       └─ read request frame
       └─ spawn_blocking(dispatch_request)
       └─ write response frame
       └─ loop
```

## remote_dispatch! Macro

Methods on `Datastore` use this macro to transparently route to the daemon socket in Remote mode:

```rust
macro_rules! remote_dispatch {
    ($self:ident, $req:expr, $pat:pat => $val:expr) => {
        if let DatastoreInner::Remote(conn) = $self.inner.as_ref() {
            let resp = conn.request(&$req)?;
            return match resp {
                $pat => Ok($val),
                DsResponse::Error(msg) => Err(anyhow!("{msg}")),
                other => Err(anyhow!("unexpected response: {other:?}")),
            };
        }
    };
}
```

Usage pattern: at the top of each `Datastore` method, the macro checks if the inner mode is Remote and short-circuits with an IPC call. If Local, execution falls through to the direct redb access below.

```rust
pub fn kv_get(&self, ns: &str, key: &str) -> Result<Option<KvEntry>> {
    remote_dispatch!(self,
        DsRequest::KvGet { ns: ns.into(), key: key.into() },
        DsResponse::KvEntry(e) => e
    );
    // ... local redb access ...
}
```

## Retention

Time-series data purging is implemented in `crates/hop-core/src/datastore/retention.rs`.

### Purge Mechanism

```rust
pub fn ts_purge_before(&self, metric: &str, before: u64) -> Result<u64>
```

Two-phase purge to avoid holding a write transaction while iterating:

1. **Phase 1 (read)**: open a read transaction, range-scan `TS_TABLE` from `(metric, 0)` to `(metric, before)`, collect all timestamps to delete.
2. **Phase 2 (write)**: open a write transaction, remove each collected key, commit.

Returns the number of deleted points.

**Constraints**:
- Local mode only -- `Remote` mode returns an error (daemon-internal housekeeping).
- The `before` timestamp is exclusive -- points at exactly `before` are retained.
- Non-existent metrics or empty tables return 0 without error.

*Last updated: v0.6.33*
