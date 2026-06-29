//! Per-node audit & flow log.
//!
//! Each machine keeps its own append-only logbook of security- and connection-
//! relevant events — who connected, what they ran, what flowed, and what the
//! warren's reach engine allowed or denied. There is **no central collector**: the
//! log lives in this node's datastore and is queried locally with `hop audit`. A
//! designated collector / external SIEM is an opt-in export layer on top (roadmap
//! G22), not a dependency.
//!
//! ## Schema is OpenTelemetry-aligned (on purpose)
//!
//! [`AuditEvent`]'s fields map 1:1 onto OTel log/semantic-convention attributes so
//! the export layer (G22) is a lossless field rename, not a reshape:
//!
//! | `AuditEvent` field | OTel attribute |
//! |--------------------|----------------|
//! | `ts_ms`            | `Timestamp` (unix ms) |
//! | `action`           | `event.name` |
//! | `category`         | `event.domain` |
//! | `outcome`          | `event.outcome` (`success`/`failure`) |
//! | `actor`            | `source.node_id` (hop node-id) |
//! | `actor_user`       | `enduser.id` |
//! | `target`           | `destination.address` / `resource` |
//! | `peer`             | `network.peer.node_id` |
//! | `bytes_tx`/`bytes_rx` | `network.io.bytes` (sent/received) |
//! | `path`             | `network.type` (`direct`/`relay`/`mixed`) |
//! | `detail`           | `event.description` (short free text) |
//!
//! The JSON encoding (`hop audit --json`) emits exactly these field names and IS the
//! G22 export contract — a unit test pins them so a rename can't silently break it.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// What kind of event this is (OTel `event.domain`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    /// A peer connection was authorized or rejected.
    Connection,
    /// An interactive shell session started/ended.
    Session,
    /// A remote command ran.
    Exec,
    /// A file transfer ran.
    Transfer,
    /// The warren reach engine allowed or denied a path.
    Reach,
    /// A periodic flow summary (bytes over the VPN data plane).
    Flow,
    /// Warren membership changed (join/admit/revoke).
    Membership,
    /// Host configuration changed.
    Config,
}

impl AuditCategory {
    /// Stable wire/key string (also the datastore sub-key and the `--category` value).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Connection => "connection",
            Self::Session => "session",
            Self::Exec => "exec",
            Self::Transfer => "transfer",
            Self::Reach => "reach",
            Self::Flow => "flow",
            Self::Membership => "membership",
            Self::Config => "config",
        }
    }

    /// Parse a `--category` value.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "connection" => Self::Connection,
            "session" => Self::Session,
            "exec" => Self::Exec,
            "transfer" => Self::Transfer,
            "reach" => Self::Reach,
            "flow" => Self::Flow,
            "membership" => Self::Membership,
            "config" => Self::Config,
            _ => return None,
        })
    }
}

/// The outcome of the event (OTel `event.outcome`, extended with authz allow/deny).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
    Allow,
    Deny,
    Info,
}

impl AuditOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Info => "info",
        }
    }
}

/// Recording verbosity, ordered cheapest→most. The host records an event iff the
/// configured level is **at least** the event's [`AuditEvent::level`].
///
/// - `Off` — record nothing.
/// - `Security` — auth rejections, reach denials, membership + config changes.
/// - `Connections` — the above **plus** accepted connections, sessions, exec, transfers.
/// - `Flows` — the above **plus** periodic per-node flow summaries and reach *allows*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLevel {
    Off,
    Security,
    Connections,
    Flows,
}

impl AuditLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Security => "security",
            Self::Connections => "connections",
            Self::Flows => "flows",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "off" | "none" => Self::Off,
            "security" => Self::Security,
            "connections" | "connection" => Self::Connections,
            "flows" | "flow" | "verbose" => Self::Flows,
            _ => return None,
        })
    }
}

/// A single audit/flow log record. Construct via [`AuditEvent::new`] + the `with_*`
/// builders, then hand to [`record`]; the host writes it best-effort (it never
/// blocks or fails the caller).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event time, unix milliseconds.
    pub ts_ms: u64,
    pub category: AuditCategory,
    /// OTel `event.name`, dotted (e.g. `connection.authorized`, `reach.deny`).
    pub action: String,
    pub outcome: AuditOutcome,
    /// Acting hop node-id (source), if known.
    #[serde(default)]
    pub actor: Option<String>,
    /// Unix username the action ran as / bound to, if known.
    #[serde(default)]
    pub actor_user: Option<String>,
    /// Target: host name, target user, file path, or `vip:port`.
    #[serde(default)]
    pub target: Option<String>,
    /// Counterpart node-id (for flows / reach).
    #[serde(default)]
    pub peer: Option<String>,
    #[serde(default)]
    pub bytes_tx: Option<u64>,
    #[serde(default)]
    pub bytes_rx: Option<u64>,
    /// Network path type: `direct` / `relay` / `mixed`.
    #[serde(default)]
    pub path: Option<String>,
    /// Short free-text detail (a command, a deny reason).
    #[serde(default)]
    pub detail: Option<String>,
}

impl AuditEvent {
    /// New event stamped at the current wall-clock time.
    pub fn new(category: AuditCategory, action: impl Into<String>, outcome: AuditOutcome) -> Self {
        Self {
            ts_ms: now_ms(),
            category,
            action: action.into(),
            outcome,
            actor: None,
            actor_user: None,
            target: None,
            peer: None,
            bytes_tx: None,
            bytes_rx: None,
            path: None,
            detail: None,
        }
    }

    pub fn actor(mut self, v: impl Into<String>) -> Self {
        self.actor = Some(v.into());
        self
    }
    pub fn actor_opt(mut self, v: Option<impl Into<String>>) -> Self {
        self.actor_user = v.map(Into::into);
        self
    }
    pub fn user(mut self, v: impl Into<String>) -> Self {
        self.actor_user = Some(v.into());
        self
    }
    pub fn user_opt(mut self, v: Option<&str>) -> Self {
        self.actor_user = v.map(|s| s.to_string());
        self
    }
    pub fn target(mut self, v: impl Into<String>) -> Self {
        self.target = Some(v.into());
        self
    }
    pub fn peer(mut self, v: impl Into<String>) -> Self {
        self.peer = Some(v.into());
        self
    }
    pub fn detail(mut self, v: impl Into<String>) -> Self {
        self.detail = Some(v.into());
        self
    }
    pub fn bytes(mut self, tx: u64, rx: u64) -> Self {
        self.bytes_tx = Some(tx);
        self.bytes_rx = Some(rx);
        self
    }
    pub fn path(mut self, v: impl Into<String>) -> Self {
        self.path = Some(v.into());
        self
    }

    /// The minimum configured [`AuditLevel`] at which this event is recorded.
    pub fn level(&self) -> AuditLevel {
        match self.category {
            AuditCategory::Flow => AuditLevel::Flows,
            AuditCategory::Reach => match self.outcome {
                AuditOutcome::Deny => AuditLevel::Security,
                _ => AuditLevel::Flows, // allows are chatty → verbose only
            },
            AuditCategory::Connection => match self.outcome {
                AuditOutcome::Deny | AuditOutcome::Failure => AuditLevel::Security,
                _ => AuditLevel::Connections,
            },
            AuditCategory::Membership | AuditCategory::Config => AuditLevel::Security,
            AuditCategory::Session | AuditCategory::Exec | AuditCategory::Transfer => {
                AuditLevel::Connections
            }
        }
    }
}

/// Query filter for [`crate::datastore::Datastore::audit_query`] and `hop audit`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Restrict to one category (None = all).
    pub category: Option<AuditCategory>,
    /// Inclusive lower/upper time bounds, unix ms.
    pub since_ms: Option<u64>,
    pub until_ms: Option<u64>,
    /// Substring match against `actor` or `actor_user`.
    pub actor: Option<String>,
    /// Max rows to return (most recent first).
    pub limit: Option<usize>,
}

/// Unix milliseconds now.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Pack `(ts_ms, seq)` into the monotonic, time-ordered datastore key id. 20 bits of
/// sequence (≈1M events/ms headroom) keep same-millisecond events from colliding
/// while preserving time order in a range scan. 44 bits of ms ≈ year 2527.
pub fn pack_id(ts_ms: u64, seq: u64) -> u64 {
    (ts_ms << 20) | (seq & 0xF_FFFF)
}

/// The ms floor of a packed id (for time-range scans).
pub fn id_floor(ts_ms: u64) -> u64 {
    ts_ms << 20
}

// ── process-global sink ──────────────────────────────────────────────────────

struct Sink {
    tx: std::sync::mpsc::Sender<AuditEvent>,
    level: AuditLevel,
}

static SINK: OnceLock<Sink> = OnceLock::new();

/// Install the global audit sink: events at or below `level` are buffered on an
/// unbounded channel and drained by `drain` on a dedicated thread (so callers in
/// hot paths never touch redb). Idempotent — a second call is ignored. No-op
/// contexts (the client CLI, tests) simply never call this, so [`record`] is inert.
pub fn init<F>(level: AuditLevel, drain: F)
where
    F: FnMut(AuditEvent) + Send + 'static,
{
    if level == AuditLevel::Off {
        return; // recording disabled — leave the sink uninstalled so record() is inert
    }
    let (tx, rx) = std::sync::mpsc::channel::<AuditEvent>();
    let mut drain = drain;
    std::thread::Builder::new()
        .name("hop-audit".into())
        .spawn(move || {
            while let Ok(ev) = rx.recv() {
                drain(ev);
            }
        })
        .ok();
    let _ = SINK.set(Sink { tx, level });
}

/// Record an event — cheap and non-blocking. Dropped if recording is off, the
/// event is below the configured level, or the channel is somehow gone. Safe to
/// call from anywhere (sync or async), including before [`init`] (then it's a no-op).
pub fn record(event: AuditEvent) {
    let Some(sink) = SINK.get() else { return };
    if sink.level < event.level() {
        return;
    }
    let _ = sink.tx.send(event);
}

/// Whether recording is active at `level` or finer (lets callers skip building an
/// event they'd only throw away).
pub fn enabled(min: AuditLevel) -> bool {
    SINK.get().is_some_and(|s| s.level >= min)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_gating_matches_intent() {
        let reject = AuditEvent::new(AuditCategory::Connection, "connection.rejected", AuditOutcome::Deny);
        assert_eq!(reject.level(), AuditLevel::Security);
        let accept = AuditEvent::new(AuditCategory::Connection, "connection.authorized", AuditOutcome::Allow);
        assert_eq!(accept.level(), AuditLevel::Connections);
        let flow = AuditEvent::new(AuditCategory::Flow, "flow.summary", AuditOutcome::Info);
        assert_eq!(flow.level(), AuditLevel::Flows);
        let reach_deny = AuditEvent::new(AuditCategory::Reach, "reach.deny", AuditOutcome::Deny);
        assert_eq!(reach_deny.level(), AuditLevel::Security);
        let reach_allow = AuditEvent::new(AuditCategory::Reach, "reach.allow", AuditOutcome::Allow);
        assert_eq!(reach_allow.level(), AuditLevel::Flows);

        // Security level records denials but not accepted connections or flows.
        assert!(AuditLevel::Security >= reject.level());
        assert!(AuditLevel::Security < accept.level());
        assert!(AuditLevel::Security < flow.level());
        // Connections records accepts but still not flows.
        assert!(AuditLevel::Connections >= accept.level());
        assert!(AuditLevel::Connections < flow.level());
    }

    #[test]
    fn pack_id_is_time_ordered_and_collision_safe() {
        let a = pack_id(1000, 0);
        let b = pack_id(1000, 1);
        let c = pack_id(1001, 0);
        assert!(a < b, "same ms, later seq sorts after");
        assert!(b < c, "later ms always sorts after earlier ms regardless of seq");
        assert!(id_floor(1001) <= c && c < id_floor(1002));
    }

    /// The JSON field names are the G22 export contract — pin them so a rename
    /// can't silently break downstream OTLP/syslog/SIEM mapping.
    #[test]
    fn json_field_names_are_stable() {
        let ev = AuditEvent::new(AuditCategory::Reach, "reach.deny", AuditOutcome::Deny)
            .actor("nodeA")
            .user("alice")
            .target("100.64.0.5:22")
            .peer("nodeB")
            .bytes(10, 20)
            .path("relay")
            .detail("no tag overlap");
        let j: serde_json::Value = serde_json::to_value(&ev).unwrap();
        for key in [
            "ts_ms", "category", "action", "outcome", "actor", "actor_user", "target", "peer",
            "bytes_tx", "bytes_rx", "path", "detail",
        ] {
            assert!(j.get(key).is_some(), "missing stable field `{key}`");
        }
        assert_eq!(j["category"], "reach");
        assert_eq!(j["outcome"], "deny");
        // Fixed schema: every field is always present (None → JSON null), so an
        // OTLP/SIEM mapping can rely on a stable key set. (No skip_serializing_if:
        // it would break bincode round-trips on the IPC + storage paths.)
        let min = AuditEvent::new(AuditCategory::Config, "config.change", AuditOutcome::Info);
        let jm: serde_json::Value = serde_json::to_value(&min).unwrap();
        assert!(jm.get("actor").is_some_and(|v| v.is_null()), "absent field is null, not missing");
    }
}
