//! Per-node audit & flow log storage on the embedded datastore.
//!
//! Append-only, time-ordered, queryable locally. See [`crate::audit`] for the
//! (OTel-aligned) event schema and the recording sink.

use anyhow::Result;
#[allow(unused_imports)]
use redb::ReadableTable;

use std::sync::atomic::{AtomicU64, Ordering};

use super::Datastore;
use super::protocol::{DsRequest, DsResponse};
use super::remote_dispatch;
use super::tables::{AUDIT_SERIES, AUDIT_TABLE};
use crate::audit::{AuditEvent, AuditQuery, id_floor, pack_id};

/// Process-wide monotonic sequence for the packed key id, so same-millisecond
/// appends never collide. Independent of the recording sink (the datastore owns
/// its own ordering; this module is also exercised directly in tests).
static AUDIT_SEQ: AtomicU64 = AtomicU64::new(0);

impl Datastore {
    /// Append an audit event. The packed key id is `(ts_ms << 20) | seq`, so
    /// same-millisecond events never collide and the table stays time-ordered.
    pub fn audit_append(&self, event: &AuditEvent) -> Result<()> {
        remote_dispatch!(self,
            DsRequest::AuditAppend { event: Box::new(event.clone()) },
            DsResponse::Ok => ()
        );
        let id = pack_id(event.ts_ms, AUDIT_SEQ.fetch_add(1, Ordering::Relaxed));
        // JSON (not bincode) for durability: the audit log must survive schema
        // additions across upgrades, and JSON is self-describing + `#[serde(default)]`
        // fills new fields when decoding older records. bincode (non-self-describing)
        // would fail to decode an old record once a field is added.
        let bytes = serde_json::to_vec(event)?;
        let txn = self.local_db().begin_write()?;
        {
            let mut table = txn.open_table(AUDIT_TABLE)?;
            table.insert((AUDIT_SERIES, id), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Query the audit log, **most-recent-first**, applying the category / time /
    /// actor / limit filters in [`AuditQuery`].
    pub fn audit_query(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>> {
        remote_dispatch!(self,
            DsRequest::AuditQuery { query: query.clone() },
            DsResponse::AuditEvents(evs) => evs
        );
        let txn = self.local_db().begin_read()?;
        let table = match txn.open_table(AUDIT_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        // Range over the packed-id space implied by the time bounds.
        let lo = id_floor(query.since_ms.unwrap_or(0));
        let hi = match query.until_ms {
            Some(until) => pack_id(until, 0xF_FFFF),
            None => u64::MAX,
        };
        let iter = table.range((AUDIT_SERIES, lo)..=(AUDIT_SERIES, hi))?;

        let actor_needle = query.actor.as_deref();
        let mut out: Vec<AuditEvent> = Vec::new();
        for item in iter {
            let (key_guard, val_guard) = item?;
            let (series, _id) = key_guard.value();
            if series != AUDIT_SERIES {
                break;
            }
            let ev: AuditEvent = serde_json::from_slice(val_guard.value())?;
            if let Some(cat) = query.category
                && ev.category != cat
            {
                continue;
            }
            if let Some(needle) = actor_needle {
                let hit = ev.actor.as_deref().is_some_and(|a| a.contains(needle))
                    || ev.actor_user.as_deref().is_some_and(|u| u.contains(needle));
                if !hit {
                    continue;
                }
            }
            out.push(ev);
        }
        // Most recent first, then apply the limit.
        out.reverse();
        if let Some(limit) = query.limit {
            out.truncate(limit);
        }
        Ok(out)
    }

    /// Purge audit events older than `before_ms`. Returns the number removed.
    /// (Retention; mirrors `ts_purge_before`.)
    pub fn audit_purge_before(&self, before_ms: u64) -> Result<u64> {
        let cutoff = id_floor(before_ms);
        let txn = self.local_db().begin_write()?;
        let mut removed = 0u64;
        {
            let mut table = match txn.open_table(AUDIT_TABLE) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
                Err(e) => return Err(e.into()),
            };
            // Collect keys below the cutoff, then remove (avoid mutating mid-iter).
            let mut doomed: Vec<u64> = Vec::new();
            for item in table.range((AUDIT_SERIES, 0u64)..(AUDIT_SERIES, cutoff))? {
                let (k, _) = item?;
                let (series, id) = k.value();
                if series != AUDIT_SERIES {
                    break;
                }
                doomed.push(id);
            }
            for id in doomed {
                if table.remove((AUDIT_SERIES, id))?.is_some() {
                    removed += 1;
                }
            }
        }
        txn.commit()?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditCategory, AuditOutcome};

    fn ev(ts: u64, cat: AuditCategory, action: &str, outcome: AuditOutcome) -> AuditEvent {
        let mut e = AuditEvent::new(cat, action, outcome);
        e.ts_ms = ts;
        e
    }

    #[test]
    fn append_query_filter_limit() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("a.redb")).unwrap();

        ds.audit_append(&ev(1000, AuditCategory::Connection, "connection.authorized", AuditOutcome::Allow).actor("nodeA").user("alice")).unwrap();
        ds.audit_append(&ev(2000, AuditCategory::Reach, "reach.deny", AuditOutcome::Deny).actor("nodeB")).unwrap();
        ds.audit_append(&ev(3000, AuditCategory::Exec, "exec", AuditOutcome::Info).user("bob").detail("ls -la")).unwrap();

        // All, most-recent-first.
        let all = ds.audit_query(&AuditQuery::default()).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].ts_ms, 3000);
        assert_eq!(all[2].ts_ms, 1000);

        // Category filter.
        let reach = ds.audit_query(&AuditQuery { category: Some(AuditCategory::Reach), ..Default::default() }).unwrap();
        assert_eq!(reach.len(), 1);
        assert_eq!(reach[0].action, "reach.deny");

        // Time window (inclusive).
        let win = ds.audit_query(&AuditQuery { since_ms: Some(1500), until_ms: Some(2500), ..Default::default() }).unwrap();
        assert_eq!(win.len(), 1);
        assert_eq!(win[0].ts_ms, 2000);

        // Actor substring (matches node-id or username).
        let by_user = ds.audit_query(&AuditQuery { actor: Some("alice".into()), ..Default::default() }).unwrap();
        assert_eq!(by_user.len(), 1);
        assert_eq!(by_user[0].actor.as_deref(), Some("nodeA"));

        // Limit.
        let one = ds.audit_query(&AuditQuery { limit: Some(1), ..Default::default() }).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].ts_ms, 3000);
    }

    #[test]
    fn same_millisecond_events_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("b.redb")).unwrap();
        for i in 0..5 {
            ds.audit_append(&ev(7000, AuditCategory::Flow, "flow.summary", AuditOutcome::Info).detail(format!("n{i}"))).unwrap();
        }
        let all = ds.audit_query(&AuditQuery::default()).unwrap();
        assert_eq!(all.len(), 5, "5 events in the same ms must all persist");
    }

    #[test]
    fn purge_before_drops_old() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("c.redb")).unwrap();
        ds.audit_append(&ev(1000, AuditCategory::Config, "config.change", AuditOutcome::Info)).unwrap();
        ds.audit_append(&ev(5000, AuditCategory::Config, "config.change", AuditOutcome::Info)).unwrap();
        let removed = ds.audit_purge_before(3000).unwrap();
        assert_eq!(removed, 1);
        let all = ds.audit_query(&AuditQuery::default()).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].ts_ms, 5000);
    }
}
