//! redb table definitions for the embedded datastore.

use redb::TableDefinition;

/// KV store: (namespace, key) → bincode-encoded KvEntry.
pub const KV_TABLE: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("kv");

/// Time-series: (metric_name, unix_timestamp_ms) → bincode-encoded MetricPoint.
pub const TS_TABLE: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("ts");

/// Per-node audit & flow log: (series, packed_id) → bincode-encoded AuditEvent.
/// `series` is a single constant ([`AUDIT_SERIES`]) so all events live in one
/// time-ordered range; `packed_id = (ts_ms << 20) | seq` keeps same-millisecond
/// events distinct while preserving time order (see `crate::audit::pack_id`).
pub const AUDIT_TABLE: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("audit");

/// The single logical series all audit events are stored under.
pub const AUDIT_SERIES: &str = "ev";

/// Cron jobs: job_id → bincode-encoded CronJob.
pub const CRON_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("cron");

/// Metadata: key → bincode-encoded value (schema version, retention policies, etc.).
pub const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

/// Encrypted secrets (legacy, unscoped): secret_name → bincode-encoded SealedSecret.
/// Migrated to SECRETS_V2_TABLE on first access.
pub const SECRETS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("secrets");

/// Encrypted secrets (user-scoped): (username, secret_name) → bincode-encoded SealedSecret.
pub const SECRETS_V2_TABLE: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("secrets_v2");
