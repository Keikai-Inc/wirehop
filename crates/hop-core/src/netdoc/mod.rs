//! Network document — the decentralized membership/role store.
//!
//! Phase 1 of the P2P private network (see `docs/technical/p2p-network.md`).
//! Wraps an `iroh-docs` CRDT namespace (replicated peer-to-peer via gossip +
//! set-reconciliation, content-addressed through blobs) behind a typed API so
//! the rest of hop never touches iroh-docs directly.
//!
//! Entry key scheme (one namespace per hop network):
//!   `peer/<node_id_hex>`        -> serialized [`crate::config::Peer`]
//!   `role/<name>`               -> serialized [`crate::proto::RoleDefinition`]
//!   `revocation/<node_id_hex>`  -> serialized [`Revocation`]
//!
//! Values are JSON for debuggability; entries are small. A deleted entry has an
//! empty value and is skipped on read.

use std::path::Path;

use anyhow::{Context, Result};
use futures_lite::StreamExt;
use iroh::Endpoint;
use iroh::protocol::Router;
use iroh_blobs::BlobsProtocol;
use iroh_blobs::store::fs::FsStore;
use iroh_docs::api::Doc;
use iroh_docs::api::protocol::{AddrInfoOptions, ShareMode};
use iroh_docs::protocol::Docs;
use iroh_docs::store::Query;
use iroh_docs::{AuthorId, DocTicket, NamespaceId};
use iroh_gossip::net::Gossip;
use serde::{Deserialize, Serialize};

use crate::config::Peer;
use crate::proto::RoleDefinition;

/// A coarse timestamp (epoch seconds as a string) for revocation/audit fields.
fn now_timestamp() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default()
}

const KEY_PEER_PREFIX: &str = "peer/";
const KEY_ROLE_PREFIX: &str = "role/";
const KEY_REVOCATION_PREFIX: &str = "revocation/";
const KEY_IP_PREFIX: &str = "ip/";

/// Base of the CGNAT range `100.64.0.0/10` (Tailscale-style), as a u32.
const CGNAT_BASE: u32 = 0x6440_0000; // 100.64.0.0
/// Number of host addresses in a /10 (2^22).
const CGNAT_SIZE: u32 = 1 << 22;
/// Cap on linear-probe attempts when claiming a virtual IP.
const MAX_IP_PROBES: u32 = 256;

/// Deterministic candidate virtual IP for a node id (stable "home" address).
///
/// `hash(node_id)` mapped into `100.64.0.0/10`, avoiding the network/broadcast
/// edges. The doc-coordinated claim (below) resolves the rare collision.
pub fn deterministic_ip(node_id: &str) -> std::net::Ipv4Addr {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(node_id.as_bytes());
    let raw = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
    let offset = 1 + (raw % (CGNAT_SIZE - 2));
    std::net::Ipv4Addr::from(CGNAT_BASE + offset)
}

/// Persisted pointer to the host's network namespace (`netdoc.json`).
#[derive(Debug, Serialize, Deserialize)]
struct NetDocMeta {
    namespace: NamespaceId,
}

/// A revocation entry: marks a peer as no longer authorized network-wide.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    pub node_id: String,
    pub reason: String,
    pub revoked_at: String,
}

/// How to obtain the network namespace when spawning.
pub enum Bootstrap {
    /// Create a brand-new network namespace (this node is the write owner).
    Create,
    /// Re-open an existing namespace already present in the local docs store.
    Open(NamespaceId),
    /// Join an existing network by importing a ticket from an invite.
    Import(Box<DocTicket>),
}

/// The network document handle: an open replicated namespace plus the iroh-docs
/// protocol stack (docs + gossip + blobs) running on a `Router`.
pub struct NetDoc {
    /// Keeps the docs/gossip/blobs accept loop alive. Dropping aborts it.
    _router: Router,
    /// Owns the persistent blobs backing store; also used to read entry values.
    fs_store: FsStore,
    doc: Doc,
    author: AuthorId,
    namespace: NamespaceId,
}

impl NetDoc {
    /// Spawn the docs stack on `endpoint`, persisting under `store_dir`, and
    /// open the network namespace per `bootstrap`.
    ///
    /// NOTE: this builds a dedicated `Router` over `endpoint`. Daemon
    /// integration (folding hop's own ALPNs into one Router) happens in a later
    /// Phase 1 step; until then this is used standalone and in tests.
    pub async fn spawn(endpoint: Endpoint, store_dir: &Path, bootstrap: Bootstrap) -> Result<Self> {
        std::fs::create_dir_all(store_dir)
            .with_context(|| format!("creating netdoc store dir {}", store_dir.display()))?;

        let fs_store = FsStore::load(store_dir.join("blobs"))
            .await
            .context("loading blobs store")?;
        let blobs = (*fs_store).clone();

        let gossip = Gossip::builder().spawn(endpoint.clone());

        let docs = Docs::persistent(store_dir.to_path_buf())
            .spawn(endpoint.clone(), blobs.clone(), gossip.clone())
            .await
            .context("spawning iroh-docs")?;

        let author = docs.author_default().await.context("default author")?;

        let doc = match bootstrap {
            Bootstrap::Create => docs.create().await.context("creating namespace")?,
            Bootstrap::Open(id) => docs
                .open(id)
                .await
                .context("opening namespace")?
                .with_context(|| format!("namespace {id} not found in local store"))?,
            Bootstrap::Import(ticket) => {
                docs.import(*ticket).await.context("importing namespace")?
            }
        };
        let namespace = doc.id();

        let router = Router::builder(endpoint)
            .accept(iroh_docs::ALPN, docs.clone())
            .accept(iroh_gossip::ALPN, gossip.clone())
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&blobs, None))
            .spawn();

        Ok(Self {
            _router: router,
            fs_store,
            doc,
            author,
            namespace,
        })
    }

    /// The network's namespace id (persist this to re-open later).
    pub fn namespace(&self) -> NamespaceId {
        self.namespace
    }

    /// Open the host's network namespace, creating it on first run.
    ///
    /// The namespace id is persisted to `meta_path` so subsequent starts re-open
    /// the same network. Returns `(net, created)` where `created` is true on the
    /// very first run (caller should then migrate existing peers/roles).
    pub async fn open_or_create(
        endpoint: Endpoint,
        store_dir: &Path,
        meta_path: &Path,
    ) -> Result<(Self, bool)> {
        let existing = std::fs::read_to_string(meta_path)
            .ok()
            .and_then(|s| serde_json::from_str::<NetDocMeta>(&s).ok())
            .map(|m| m.namespace);

        let (net, created) = match existing {
            Some(id) => match Self::spawn(endpoint.clone(), store_dir, Bootstrap::Open(id)).await {
                Ok(net) => (net, false),
                Err(e) => {
                    tracing::warn!(
                        "netdoc: saved namespace {id} could not be opened ({e}); creating fresh"
                    );
                    (Self::spawn(endpoint, store_dir, Bootstrap::Create).await?, true)
                }
            },
            None => (Self::spawn(endpoint, store_dir, Bootstrap::Create).await?, true),
        };

        if created {
            let meta = NetDocMeta {
                namespace: net.namespace,
            };
            let json = serde_json::to_string_pretty(&meta).context("serializing netdoc meta")?;
            std::fs::write(meta_path, json)
                .with_context(|| format!("writing netdoc meta to {}", meta_path.display()))?;
        }
        Ok((net, created))
    }

    /// Idempotently migrate peers into the doc (skips ones already present or
    /// revoked). Returns the number newly written.
    pub async fn ensure_peers(&self, peers: &[Peer]) -> Result<usize> {
        let mut n = 0;
        for p in peers {
            if self.get_peer(&p.node_id).await?.is_none() && !self.is_revoked(&p.node_id).await? {
                self.put_peer(p).await?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Idempotently migrate roles into the doc (skips ones already present).
    /// Returns the number newly written.
    pub async fn ensure_roles(&self, roles: &[RoleDefinition]) -> Result<usize> {
        let existing: std::collections::HashSet<String> =
            self.list_roles().await?.into_iter().map(|r| r.name).collect();
        let mut n = 0;
        for r in roles {
            if !existing.contains(&r.name) {
                self.put_role(r).await?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Make the document match the given peers/roles (the host's local
    /// peers.json/roles.json). Adds new peers, **revokes** peers that are no
    /// longer present, and upserts/removes roles. Idempotent and self-healing.
    ///
    /// SAFETY: this assumes a per-host namespace — i.e. the document only
    /// contains peers this host manages. With cross-host federation (a shared
    /// namespace), revoking "doc peers not in my local peers.json" would wrongly
    /// revoke peers owned by other hosts; that model requires per-host ownership
    /// scoping before reconcile can run against a shared namespace.
    pub async fn reconcile(&self, peers: &[Peer], roles: &[RoleDefinition]) -> Result<()> {
        use std::collections::HashSet;

        let desired_peers: HashSet<&str> = peers.iter().map(|p| p.node_id.as_str()).collect();

        // Adds: present locally, missing from the doc, not already revoked.
        for p in peers {
            if !self.is_revoked(&p.node_id).await? && self.get_peer(&p.node_id).await?.is_none() {
                self.put_peer(p).await?;
            }
        }
        // Removals: in the doc but no longer present locally → revoke.
        for existing in self.list_peers().await? {
            if !desired_peers.contains(existing.node_id.as_str()) {
                self.revoke(&existing.node_id, "removed", &now_timestamp()).await?;
            }
        }

        // Roles: upsert all desired (handles create + update), delete the rest.
        let desired_roles: HashSet<&str> = roles.iter().map(|r| r.name.as_str()).collect();
        for r in roles {
            self.put_role(r).await?;
        }
        for er in self.list_roles().await? {
            if !desired_roles.contains(er.name.as_str()) {
                self.del_role(&er.name).await?;
            }
        }
        Ok(())
    }

    // ── Virtual IPs (Phase 2) ────────────────────────────────────────────

    /// Claim a stable virtual IP for `node_id` in `100.64.0.0/10`, idempotently.
    ///
    /// Returns the already-claimed address if present, else claims the
    /// deterministic candidate (linear-probing on collision) in the doc's
    /// `ip/<addr> -> node_id` allocation table. On a concurrent claim of the same
    /// slot (only possible once federated), the lower node_id wins and the loser
    /// re-probes.
    pub async fn claim_virtual_ip(&self, node_id: &str) -> Result<std::net::Ipv4Addr> {
        if let Some(ip) = self.get_virtual_ip(node_id).await? {
            return Ok(ip);
        }
        let start = u32::from(deterministic_ip(node_id));
        for i in 0..MAX_IP_PROBES {
            // Wrap within the /10 range.
            let off = ((start.wrapping_sub(CGNAT_BASE)).wrapping_add(i)) % CGNAT_SIZE;
            let cand = std::net::Ipv4Addr::from(CGNAT_BASE + off);
            let key = format!("{KEY_IP_PREFIX}{cand}");
            match self.lookup_ip_owner(&key).await? {
                Some(owner) if owner == node_id => return Ok(cand),
                Some(_) => continue, // taken by another node — probe next
                None => {
                    self.doc
                        .set_bytes(self.author, key.clone().into_bytes(), node_id.as_bytes().to_vec())
                        .await
                        .context("claiming virtual IP")?;
                    // Resolve a concurrent claim deterministically: re-read; if a
                    // lower node_id also claimed this slot, yield and re-probe.
                    if let Some(owner) = self.lookup_ip_owner(&key).await?
                        && owner != node_id
                    {
                        continue;
                    }
                    return Ok(cand);
                }
            }
        }
        anyhow::bail!("no free virtual IP after {MAX_IP_PROBES} probes")
    }

    /// The virtual IP currently allocated to `node_id`, if any.
    pub async fn get_virtual_ip(&self, node_id: &str) -> Result<Option<std::net::Ipv4Addr>> {
        for (addr, owner) in self.list_virtual_ips().await? {
            if owner == node_id {
                return Ok(Some(addr));
            }
        }
        Ok(None)
    }

    /// All `(addr, node_id)` virtual-IP allocations in the document.
    pub async fn list_virtual_ips(&self) -> Result<Vec<(std::net::Ipv4Addr, String)>> {
        let query = Query::key_prefix(KEY_IP_PREFIX.as_bytes()).build();
        let stream = self.doc.get_many(query).await.context("get_many ip")?;
        let mut stream = std::pin::pin!(stream);
        let mut out = Vec::new();
        while let Some(entry) = stream.next().await {
            let entry = entry.context("reading ip entry")?;
            if entry.content_len() == 0 {
                continue;
            }
            let key = String::from_utf8_lossy(entry.key());
            let Some(addr_str) = key.strip_prefix(KEY_IP_PREFIX) else { continue };
            let Ok(addr) = addr_str.parse::<std::net::Ipv4Addr>() else { continue };
            let bytes = self.fs_store.get_bytes(entry.content_hash()).await?;
            out.push((addr, String::from_utf8_lossy(&bytes).into_owned()));
        }
        Ok(out)
    }

    async fn lookup_ip_owner(&self, key: &str) -> Result<Option<String>> {
        let query = Query::single_latest_per_key().key_exact(key.as_bytes()).build();
        let Some(entry) = self.doc.get_one(query).await.context("get_one ip")? else {
            return Ok(None);
        };
        if entry.content_len() == 0 {
            return Ok(None);
        }
        let bytes = self.fs_store.get_bytes(entry.content_hash()).await?;
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }

    /// Delete a role entry (tombstone).
    pub async fn del_role(&self, name: &str) -> Result<()> {
        let key = format!("{KEY_ROLE_PREFIX}{name}");
        self.doc
            .del(self.author, key.into_bytes())
            .await
            .context("deleting role entry")?;
        Ok(())
    }

    /// Produce a read-capability ticket for embedding in an invite, so a new
    /// peer can import and replicate the network document.
    pub async fn read_ticket(&self) -> Result<String> {
        let ticket = self
            .doc
            .share(ShareMode::Read, AddrInfoOptions::RelayAndAddresses)
            .await
            .context("sharing read ticket")?;
        Ok(ticket.to_string())
    }

    // ── Peers ────────────────────────────────────────────────────────────

    /// Insert or update a peer entry (keyed by `node_id`).
    pub async fn put_peer(&self, peer: &Peer) -> Result<()> {
        let key = format!("{KEY_PEER_PREFIX}{}", peer.node_id);
        let value = serde_json::to_vec(peer).context("serializing peer")?;
        self.doc
            .set_bytes(self.author, key.into_bytes(), value)
            .await
            .context("writing peer entry")?;
        Ok(())
    }

    /// Fetch a single peer by node id, if present (and not tombstoned).
    pub async fn get_peer(&self, node_id: &str) -> Result<Option<Peer>> {
        let key = format!("{KEY_PEER_PREFIX}{node_id}");
        let query = Query::single_latest_per_key().key_exact(key.as_bytes()).build();
        let Some(entry) = self.doc.get_one(query).await.context("get_one peer")? else {
            return Ok(None);
        };
        self.decode_entry(&entry).await
    }

    /// List all (non-tombstoned) peer entries.
    pub async fn list_peers(&self) -> Result<Vec<Peer>> {
        self.list_prefix(KEY_PEER_PREFIX).await
    }

    // ── Roles ────────────────────────────────────────────────────────────

    pub async fn put_role(&self, role: &RoleDefinition) -> Result<()> {
        let key = format!("{KEY_ROLE_PREFIX}{}", role.name);
        let value = serde_json::to_vec(role).context("serializing role")?;
        self.doc
            .set_bytes(self.author, key.into_bytes(), value)
            .await
            .context("writing role entry")?;
        Ok(())
    }

    pub async fn list_roles(&self) -> Result<Vec<RoleDefinition>> {
        self.list_prefix(KEY_ROLE_PREFIX).await
    }

    // ── Revocations ──────────────────────────────────────────────────────

    /// Record a revocation for a peer (and tombstone its peer entry).
    pub async fn revoke(&self, node_id: &str, reason: &str, revoked_at: &str) -> Result<()> {
        let rev = Revocation {
            node_id: node_id.to_string(),
            reason: reason.to_string(),
            revoked_at: revoked_at.to_string(),
        };
        let key = format!("{KEY_REVOCATION_PREFIX}{node_id}");
        let value = serde_json::to_vec(&rev).context("serializing revocation")?;
        self.doc
            .set_bytes(self.author, key.into_bytes(), value)
            .await
            .context("writing revocation entry")?;
        // Tombstone the peer entry so it no longer authorizes.
        let peer_key = format!("{KEY_PEER_PREFIX}{node_id}");
        self.doc
            .del(self.author, peer_key.into_bytes())
            .await
            .context("deleting peer entry on revoke")?;
        Ok(())
    }

    /// Whether a peer has been revoked.
    pub async fn is_revoked(&self, node_id: &str) -> Result<bool> {
        let key = format!("{KEY_REVOCATION_PREFIX}{node_id}");
        let query = Query::single_latest_per_key().key_exact(key.as_bytes()).build();
        Ok(self.doc.get_one(query).await.context("get_one revocation")?.is_some())
    }

    // ── Internals ────────────────────────────────────────────────────────

    /// Decode an entry's content into `T`, returning `None` for tombstones.
    async fn decode_entry<T: for<'de> Deserialize<'de>>(
        &self,
        entry: &iroh_docs::Entry,
    ) -> Result<Option<T>> {
        if entry.content_len() == 0 {
            return Ok(None); // tombstone
        }
        let bytes = self
            .fs_store
            .get_bytes(entry.content_hash())
            .await
            .context("reading entry content from blobs")?;
        let value = serde_json::from_slice(&bytes).context("deserializing entry value")?;
        Ok(Some(value))
    }

    /// Collect all live entries under `prefix`, decoded into `T`.
    async fn list_prefix<T: for<'de> Deserialize<'de>>(&self, prefix: &str) -> Result<Vec<T>> {
        let query = Query::key_prefix(prefix.as_bytes()).build();
        let stream = self.doc.get_many(query).await.context("get_many")?;
        let mut stream = std::pin::pin!(stream);
        let mut out = Vec::new();
        while let Some(entry) = stream.next().await {
            let entry = entry.context("reading entry from stream")?;
            if let Some(value) = self.decode_entry::<T>(&entry).await? {
                out.push(value);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PeerRole;
    use crate::sandbox::SandboxPolicy;

    async fn test_endpoint() -> Endpoint {
        // Empty builder: no relay, no discovery — purely local, fine for a
        // single-node round-trip test of the schema layer.
        iroh::endpoint::Builder::empty()
            .bind()
            .await
            .expect("bind test endpoint")
    }

    fn sample_peer(id: &str, name: &str) -> Peer {
        Peer {
            node_id: id.to_string(),
            name: name.to_string(),
            authorized_at: "2026-01-01T00:00:00Z".to_string(),
            last_seen: None,
            username: None,
            role: PeerRole::Peer,
            sandbox: SandboxPolicy::default(),
        }
    }

    #[tokio::test]
    async fn peer_roundtrip_and_revoke() {
        let dir = tempfile::tempdir().unwrap();
        let ep = test_endpoint().await;
        let net = NetDoc::spawn(ep, dir.path(), Bootstrap::Create)
            .await
            .expect("spawn netdoc");

        let p1 = sample_peer("aaaa", "alice");
        let p2 = sample_peer("bbbb", "bob");
        net.put_peer(&p1).await.unwrap();
        net.put_peer(&p2).await.unwrap();

        let got = net.get_peer("aaaa").await.unwrap().expect("alice present");
        assert_eq!(got.name, "alice");

        let mut all = net.list_peers().await.unwrap();
        all.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].node_id, "aaaa");
        assert_eq!(all[1].node_id, "bbbb");

        // Revoke alice → peer entry gone, revocation present.
        net.revoke("aaaa", "test", "2026-01-02T00:00:00Z").await.unwrap();
        assert!(net.is_revoked("aaaa").await.unwrap());
        assert!(net.get_peer("aaaa").await.unwrap().is_none());
        assert_eq!(net.list_peers().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn reconcile_adds_and_revokes() {
        let dir = tempfile::tempdir().unwrap();
        let ep = test_endpoint().await;
        let net = NetDoc::spawn(ep, dir.path(), Bootstrap::Create)
            .await
            .expect("spawn netdoc");

        let alice = sample_peer("a1", "alice");
        let bob = sample_peer("b2", "bob");

        // Reconcile to {alice, bob} → both present.
        net.reconcile(&[alice.clone(), bob.clone()], &[]).await.unwrap();
        assert_eq!(net.list_peers().await.unwrap().len(), 2);

        // Reconcile to {alice} → bob revoked and dropped.
        net.reconcile(&[alice.clone()], &[]).await.unwrap();
        let peers = net.list_peers().await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].node_id, "a1");
        assert!(net.is_revoked("b2").await.unwrap());
        assert!(!net.is_revoked("a1").await.unwrap());
    }

    #[test]
    fn deterministic_ip_in_cgnat_range_and_stable() {
        let ip = deterministic_ip("somenodeid");
        let o = ip.octets();
        // 100.64.0.0/10 → first octet 100, second in 64..=127.
        assert_eq!(o[0], 100);
        assert!((64..=127).contains(&o[1]), "second octet {} out of /10", o[1]);
        // Deterministic.
        assert_eq!(deterministic_ip("somenodeid"), ip);
        assert_ne!(deterministic_ip("othernode"), ip);
    }

    #[tokio::test]
    async fn claim_virtual_ip_is_idempotent_and_unique() {
        let dir = tempfile::tempdir().unwrap();
        let ep = test_endpoint().await;
        let net = NetDoc::spawn(ep, dir.path(), Bootstrap::Create)
            .await
            .expect("spawn netdoc");

        let ip_a1 = net.claim_virtual_ip("a1").await.unwrap();
        // Idempotent.
        assert_eq!(net.claim_virtual_ip("a1").await.unwrap(), ip_a1);
        // Different node → different IP.
        let ip_b2 = net.claim_virtual_ip("b2").await.unwrap();
        assert_ne!(ip_a1, ip_b2);
        // Lookups agree.
        assert_eq!(net.get_virtual_ip("a1").await.unwrap(), Some(ip_a1));
        assert_eq!(net.list_virtual_ips().await.unwrap().len(), 2);
    }
}
