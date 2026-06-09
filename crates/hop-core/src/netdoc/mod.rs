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
use iroh::EndpointAddr;
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
const KEY_VPN_PREFIX: &str = "vpn/";

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
    /// Whether this namespace was joined from another host (federation). Kept so
    /// a rejoined host stays additive-only on reconcile across restarts.
    #[serde(default)]
    federated: bool,
    /// This node's own self-doc namespace (per-member self-document model). `None`
    /// for stores created before self-docs — a fresh one is minted + persisted.
    #[serde(default)]
    self_namespace: Option<NamespaceId>,
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

/// Cached Cedar reach engine paired with the instant it was built.
type ReachCache =
    std::sync::Arc<tokio::sync::RwLock<Option<(std::time::Instant, std::sync::Arc<crate::vpn::cedar::AclEngine>)>>>;

/// The network document handle: an open replicated namespace plus the iroh-docs
/// protocol stack (docs + gossip + blobs) running on a `Router`.
pub struct NetDoc {
    /// Keeps the docs/gossip/blobs (+ vpn) accept loop alive. Dropping aborts it.
    _router: Router,
    /// Owns the persistent blobs backing store; also used to read entry values.
    fs_store: FsStore,
    /// The docs engine, retained so member self-docs can be imported at runtime
    /// (per-member self-document model, C1 write-isolation).
    docs: Docs,
    doc: Doc,
    /// This node's own self-doc (member-owned — this node is the sole writer).
    /// Self-state (`ip/ vpn/ name/ tag/ posture/`) is published here, physically
    /// isolated from other members. Created/opened at startup.
    self_doc: Doc,
    /// Lazily-imported, read-only member self-docs keyed by node_id (lazy/on-
    /// demand sync). Populated by `member_self_doc` on first reach; cached here.
    member_docs: tokio::sync::RwLock<std::collections::HashMap<String, Doc>>,
    author: AuthorId,
    namespace: NamespaceId,
    /// The endpoint the docs/vpn stack runs on (for opening VPN connections).
    endpoint: Endpoint,
    /// True when this namespace was joined from another host (federation). In
    /// that case reconcile is additive-only — it must not revoke peers owned by
    /// other hosts in the shared namespace.
    federated: bool,
    /// Active TUN device when the VPN is enabled (Phase 3, opt-in). `None` = off.
    #[cfg(unix)]
    vpn_tun: crate::vpn::TunSlot,
    /// `endpoint-id-hex → vIP` for ingress authentication (security-audit C2),
    /// shared with the `VpnInbound` handler; refreshed from the `vpn/` table.
    #[cfg(unix)]
    vpn_peer_ips: crate::vpn::VpnPeerIps,
    /// This host's own vIP (the only legitimate ingress destination).
    #[cfg(unix)]
    vpn_local_ip: crate::vpn::VpnLocalIp,
    /// Signalled by `VpnInbound` when a datagram arrives from a peer whose vIP
    /// isn't in `vpn_peer_ips` yet; the consumer in `enable_vpn` refreshes the
    /// map so a just-rebooted peer reconverges fast (rate-limited).
    #[cfg(unix)]
    vpn_refresh: crate::vpn::VpnRefresh,
    /// Cached Cedar reach engine + when it was built. Rebuilt lazily when older
    /// than `REACH_CACHE_TTL` so the per-packet forwarding path never rebuilds
    /// the policy/entity set inline.
    reach_cache: ReachCache,
    /// Author-validation mode (security-audit C1, Phase 0a). `Observe` (default)
    /// only logs anomalies; `Off` disables; `Enforce` rejects forged entries.
    /// Set via `HOP_NETDOC_VALIDATION`; interior-mutable so tests can override
    /// per instance without global env races.
    validation_mode: std::sync::Mutex<ValidationMode>,
    /// First-seen iroh-docs author per doc key, used to detect an entry whose
    /// author changed — the signature of a member forging/hijacking another
    /// node's `vpn`/`name`/`ip` registration (C1). Log-only in `Observe` mode.
    entry_authors: std::sync::Mutex<std::collections::HashMap<Vec<u8>, AuthorId>>,
    /// The trusted admin (founder) author — the C1 trust anchor. For the founder
    /// this is its own author; a federated node sets it from the invite's
    /// `founder_author`. In enforce mode, admin-owned entries (`peer/ role/
    /// revocation/ acl/ network/`) are honored only if authored by it.
    founder_author: std::sync::Mutex<Option<AuthorId>>,
    /// The set of authors trusted to write admin-owned keys under enforce: the
    /// founder plus every co-admin author the founder has vouched (a
    /// founder-authored `peer/` entry with the admin/creator role whose
    /// `netdoc_author` binding is known). Refreshed from founder-authored peer
    /// entries (see `refresh_admin_authors`), so a co-admin can't elevate itself
    /// — only the founder grants admin authority. Always contains the founder.
    admin_authors: std::sync::Mutex<std::collections::HashSet<AuthorId>>,
}

/// Author-validation enforcement level for replicated doc entries (C1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValidationMode {
    /// No author checks (legacy behavior).
    Off,
    /// Log author anomalies; take no action. The safe default — it cannot
    /// partition a warren, only surface forgery attempts.
    #[default]
    Observe,
    /// Reject entries that fail author validation. **Not yet wired** — needs the
    /// founder-author trust anchor; see install-and-invite-tiers.md §9.
    Enforce,
}

impl ValidationMode {
    fn from_env() -> Self {
        match std::env::var("HOP_NETDOC_VALIDATION").as_deref() {
            Ok("off") => ValidationMode::Off,
            Ok("enforce") => ValidationMode::Enforce,
            _ => ValidationMode::Observe,
        }
    }
}

/// How long a built reach engine is reused before a rebuild. Membership changes
/// converge within this window on the enforcement path.
const REACH_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3);

impl NetDoc {
    /// Spawn the docs stack on `endpoint`, persisting under `store_dir`, and
    /// open the network namespace per `bootstrap`.
    ///
    /// NOTE: this builds a dedicated `Router` over `endpoint`. Daemon
    /// integration (folding hop's own ALPNs into one Router) happens in a later
    /// Phase 1 step; until then this is used standalone and in tests.
    /// Spawn with a fresh self-doc (no persistence) — the form tests use.
    pub async fn spawn(endpoint: Endpoint, store_dir: &Path, bootstrap: Bootstrap) -> Result<Self> {
        Self::spawn_inner(endpoint, store_dir, bootstrap, None).await
    }

    /// Spawn, opening the given `self_ns` self-doc namespace if provided (else
    /// minting a fresh one). `open_or_create` passes the persisted namespace so
    /// the same self-doc is reused across restarts.
    pub async fn spawn_inner(
        endpoint: Endpoint,
        store_dir: &Path,
        bootstrap: Bootstrap,
        self_ns: Option<NamespaceId>,
    ) -> Result<Self> {
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

        let federated = matches!(bootstrap, Bootstrap::Import(_));
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

        // This node's own self-doc: open the persisted namespace, or mint a fresh
        // one. This node holds its write key; other members only ever read it.
        let self_doc = match self_ns {
            Some(id) => docs
                .open(id)
                .await
                .context("opening self-doc")?
                .with_context(|| format!("self-doc namespace {id} not found in local store"))?,
            None => docs.create().await.context("creating self-doc")?,
        };

        #[cfg(unix)]
        let vpn_tun: crate::vpn::TunSlot = std::sync::Arc::new(tokio::sync::RwLock::new(None));
        #[cfg(unix)]
        let vpn_peer_ips: crate::vpn::VpnPeerIps =
            std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
        #[cfg(unix)]
        let vpn_local_ip: crate::vpn::VpnLocalIp = std::sync::Arc::new(tokio::sync::RwLock::new(None));
        #[cfg(unix)]
        let vpn_refresh: crate::vpn::VpnRefresh = std::sync::Arc::new(tokio::sync::Notify::new());

        let mut builder = Router::builder(endpoint.clone())
            .accept(iroh_docs::ALPN, docs.clone())
            .accept(iroh_gossip::ALPN, gossip.clone())
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&blobs, None));
        // The VPN inbound handler is always registered so peers can establish the
        // hop/vpn/1 path, but it only forwards packets once the TUN slot is set
        // (i.e. the VPN is explicitly enabled). Off by default → no-op. It
        // authenticates ingress against the shared peer-IP map (security-audit C2).
        #[cfg(unix)]
        {
            builder = builder.accept(
                crate::vpn::VPN_ALPN,
                crate::vpn::VpnInbound::new(
                    vpn_tun.clone(),
                    vpn_peer_ips.clone(),
                    vpn_local_ip.clone(),
                    vpn_refresh.clone(),
                ),
            );
        }
        let router = builder.spawn();

        Ok(Self {
            _router: router,
            fs_store,
            docs,
            doc,
            self_doc,
            member_docs: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            author,
            namespace,
            endpoint,
            federated,
            #[cfg(unix)]
            vpn_tun,
            #[cfg(unix)]
            vpn_peer_ips,
            #[cfg(unix)]
            vpn_local_ip,
            #[cfg(unix)]
            vpn_refresh,
            reach_cache: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
            validation_mode: std::sync::Mutex::new(ValidationMode::from_env()),
            entry_authors: std::sync::Mutex::new(std::collections::HashMap::new()),
            founder_author: std::sync::Mutex::new(None),
            admin_authors: std::sync::Mutex::new(std::collections::HashSet::new()),
        })
    }

    /// The network's namespace id (persist this to re-open later).
    pub fn namespace(&self) -> NamespaceId {
        self.namespace
    }

    /// This host's iroh-docs author id, hex-encoded. The founder pins this in
    /// its invites (`InviteToken::founder_author`) as the C1 trust anchor;
    /// every node conveys its own to an admin so its self-owned entries can be
    /// author-validated.
    pub fn author_hex(&self) -> String {
        hex::encode(self.author.to_bytes())
    }

    /// Record the C1 trust anchor (the founder/admin author). Call after spawn:
    /// the founder (namespace creator, not federated) is its own admin; a
    /// federated node passes the `founder_author` hex from the invite it joined
    /// with. Inert until `ValidationMode::Enforce`.
    pub fn record_founder_anchor(&self, from_invite_hex: Option<&str>) {
        let resolved = if !self.federated {
            // The host that created the namespace is the founder/admin.
            Some(self.author)
        } else {
            from_invite_hex.and_then(parse_author_hex)
        };
        if let Some(a) = resolved {
            *self.founder_author.lock().unwrap() = Some(a);
            // The founder is always an admin author; co-admins are added by
            // refresh_admin_authors once their vouched bindings replicate.
            self.admin_authors.lock().unwrap().insert(a);
            tracing::info!("netdoc C1: trusted admin author = {a}");
        } else if self.federated {
            tracing::warn!(
                "netdoc C1: no founder author available (legacy join) — enforce mode \
                 would reject admin entries; staying in observe is recommended"
            );
        }
    }

    /// The trusted admin author, if known.
    fn founder_author(&self) -> Option<AuthorId> {
        *self.founder_author.lock().unwrap()
    }

    /// True if `author` is trusted to write admin-owned keys (founder or a
    /// founder-vouched co-admin). Used by `validate_entry` under enforce.
    fn is_admin_author(&self, author: &AuthorId) -> bool {
        self.admin_authors.lock().unwrap().contains(author)
    }

    /// Rebuild the trusted-admin-author set from FOUNDER-authored `peer/` entries
    /// with the admin (creator) role whose `netdoc_author` binding is known.
    ///
    /// Only the founder grants admin authority: we read peer entries authored by
    /// the founder *only*, so a co-admin can't vouch a third author as admin and
    /// there's no validation cycle (this never calls `validate_entry`). The
    /// founder is always retained. Call after reconcile / on a refresh tick.
    pub async fn refresh_admin_authors(&self) {
        let Some(founder) = self.founder_author() else { return };
        let mut set = std::collections::HashSet::new();
        set.insert(founder);
        if let Ok(stream) = self
            .doc
            .get_many(Query::key_prefix(KEY_PEER_PREFIX.as_bytes()).build())
            .await
        {
            let mut stream = std::pin::pin!(stream);
            while let Some(Ok(entry)) = stream.next().await {
                // Only the founder confers admin authority.
                if entry.author() != founder || entry.content_len() == 0 {
                    continue;
                }
                let Ok(bytes) = self.fs_store.get_bytes(entry.content_hash()).await else { continue };
                let Ok(peer) = serde_json::from_slice::<Peer>(&bytes) else { continue };
                if peer.role == crate::config::PeerRole::Creator
                    && let Some(a) = peer.netdoc_author.as_deref().and_then(parse_author_hex)
                {
                    set.insert(a);
                }
            }
        }
        *self.admin_authors.lock().unwrap() = set;
    }

    /// Current author-validation mode.
    fn validation_mode(&self) -> ValidationMode {
        *self.validation_mode.lock().unwrap()
    }

    /// Override the validation mode (used by tests to exercise enforce on a
    /// specific instance without a process-global env var).
    #[cfg(test)]
    pub fn set_validation_mode(&self, mode: ValidationMode) {
        *self.validation_mode.lock().unwrap() = mode;
    }

    /// `node_id → vouched netdoc author` from the (admin-owned, already
    /// author-validated) `peer/` entries. The basis for self-key validation
    /// (C1 enforce): a self-owned entry for node N is legitimate only if
    /// authored by N's vouched author. Because peer entries are admin-owned, a
    /// forged peer can't inject a fake binding in enforce mode.
    pub async fn vouched_authors(&self) -> std::collections::HashMap<String, AuthorId> {
        self.list_peers()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|p| {
                p.netdoc_author
                    .as_deref()
                    .and_then(parse_author_hex)
                    .map(|a| (p.node_id, a))
            })
            .collect()
    }

    /// True if this node is the warren's C1 trust anchor (its doc author is the
    /// recorded founder/admin author). Only the trust anchor records vouched
    /// author bindings, since `peer/` entries are admin-owned.
    pub fn is_trust_anchor(&self) -> bool {
        self.founder_author()
            .map(|fa| fa == self.author)
            .unwrap_or(false)
    }

    /// Record (or refresh) the admin-owned `peer/<node_id>.netdoc_author`
    /// binding announced by a member. No-op (returns `Ok(false)`) unless this
    /// node is the trust anchor and the peer entry already exists — we vouch an
    /// author only for an already-admitted member, never mint membership. The
    /// binding is the basis for that member's self-key validation (C1 enforce).
    pub async fn record_peer_author(&self, node_id: &str, author_hex: &str) -> Result<bool> {
        if !self.is_trust_anchor() {
            return Ok(false);
        }
        // Reject a malformed author up front so we never store junk.
        if parse_author_hex(author_hex).is_none() {
            anyhow::bail!("invalid netdoc author hex");
        }
        let Some(mut peer) = self.get_peer(node_id).await? else {
            // Not an admitted member — ignore (don't create membership).
            return Ok(false);
        };
        if peer.netdoc_author.as_deref() == Some(author_hex) {
            return Ok(true); // already bound; idempotent
        }
        peer.netdoc_author = Some(author_hex.to_string());
        self.put_peer(&peer).await?;
        tracing::info!(
            "netdoc C1: vouched author {} for member {}",
            &author_hex[..8.min(author_hex.len())],
            &node_id[..8.min(node_id.len())]
        );
        // A newly-vouched co-admin must enter the trusted-admin set immediately.
        self.refresh_admin_authors().await;
        Ok(true)
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
        join: Option<DocTicket>,
    ) -> Result<(Self, bool)> {
        let existing = std::fs::read_to_string(meta_path)
            .ok()
            .and_then(|s| serde_json::from_str::<NetDocMeta>(&s).ok());

        let self_ns = existing.as_ref().and_then(|m| m.self_namespace);
        let (mut net, created) = match &existing {
            Some(meta) => match Self::spawn_inner(endpoint.clone(), store_dir, Bootstrap::Open(meta.namespace), self_ns).await {
                Ok(net) => (net, false),
                Err(e) => {
                    tracing::warn!(
                        "netdoc: saved namespace {} could not be opened ({e}); creating fresh",
                        meta.namespace
                    );
                    (Self::spawn_inner(endpoint, store_dir, Bootstrap::Create, None).await?, true)
                }
            },
            // First run: join an existing network if given a ticket, else create.
            None => match join {
                Some(ticket) => {
                    tracing::info!("netdoc: joining network via import ticket");
                    (Self::spawn_inner(endpoint, store_dir, Bootstrap::Import(Box::new(ticket)), None).await?, true)
                }
                None => (Self::spawn_inner(endpoint, store_dir, Bootstrap::Create, None).await?, true),
            },
        };

        // Restore the persisted federation status on reopen (Open loses it).
        if let Some(meta) = &existing {
            net.federated = meta.federated;
        }

        // Persist meta when first created, or when the self-doc namespace was
        // newly minted (older stores have no self_namespace → write it now).
        if created || self_ns != Some(net.self_doc.id()) {
            let meta = NetDocMeta {
                namespace: net.namespace,
                federated: net.federated,
                self_namespace: Some(net.self_doc.id()),
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
        // Removals: in the doc but no longer present locally → revoke. Skipped
        // when federated — on a shared namespace the doc contains peers owned by
        // OTHER hosts, and revoking them from our local view would wrongly evict
        // them. (Per-entry ownership scoping + Owner/Admin-capability-gated writes
        // are the deeper hardening; see docs/technical/p2p-network.md.)
        if !self.federated {
            for existing in self.list_peers().await? {
                if !desired_peers.contains(existing.node_id.as_str()) {
                    self.revoke(&existing.node_id, "removed", &now_timestamp()).await?;
                }
            }
        }

        // Roles: upsert all desired (handles create + update). Deletion of
        // not-desired roles is skipped when federated (shared role set).
        let desired_roles: HashSet<&str> = roles.iter().map(|r| r.name.as_str()).collect();
        for r in roles {
            self.put_role(r).await?;
        }
        if !self.federated {
            for er in self.list_roles().await? {
                if !desired_roles.contains(er.name.as_str()) {
                    self.del_role(&er.name).await?;
                }
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
            if !self.validate_entry(entry.key(), entry.author()) {
                continue;
            }
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

    // ── Sync resumption (robustness across restarts) ─────────────────────

    /// Re-establish live document sync with the warren's known peers.
    ///
    /// iroh-docs only starts live sync automatically on `import` (the first
    /// join, where the ticket carries peer addresses). `open` — the path taken
    /// on every restart once the namespace is persisted — does NOT. Without
    /// this, a rebooted node would open a stale local replica and never
    /// reconverge. We rebuild peer addresses from the replicated `vpn/` endpoint
    /// table (each entry is `"<endpoint_id> <relay?>"`, the netdoc-endpoint
    /// address sync runs on) and call `start_sync`, so the node actively rejoins
    /// the swarm. Best-effort and idempotent — safe to call on every start and
    /// periodically. Returns the number of peers re-synced with.
    pub async fn resume_sync(&self) -> Result<usize> {
        let self_id = self.endpoint.id();
        let query = Query::key_prefix(KEY_VPN_PREFIX.as_bytes()).build();
        let stream = self.doc.get_many(query).await.context("get_many vpn")?;
        let mut stream = std::pin::pin!(stream);
        let mut peers: Vec<EndpointAddr> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        while let Some(entry) = stream.next().await {
            let entry = entry.context("reading vpn entry")?;
            if entry.content_len() == 0 {
                continue;
            }
            let bytes = self.fs_store.get_bytes(entry.content_hash()).await?;
            let value = String::from_utf8_lossy(&bytes);
            let mut parts = value.split_whitespace();
            let Some(id_hex) = parts.next() else { continue };
            let Ok(pubkey) = id_hex.parse::<iroh::PublicKey>() else { continue };
            if pubkey == self_id || !seen.insert(pubkey) {
                continue;
            }
            let mut addr = EndpointAddr::from(pubkey);
            if let Some(relay) = parts.next().and_then(|r| r.parse().ok()) {
                addr = addr.with_relay_url(relay);
            }
            peers.push(addr);
        }
        if peers.is_empty() {
            return Ok(0);
        }
        let n = peers.len();
        // Best-effort: an unaddressable peer (no relay + no direct addr, e.g. in
        // hermetic tests) can make start_sync error; that must not fail the
        // daemon's resume. The keepalive retries, and the engine accepts incoming
        // sync regardless.
        if let Err(e) = self.doc.start_sync(peers).await {
            tracing::debug!("netdoc: start_sync during resume failed (best-effort): {e:#}");
        }
        Ok(n)
    }

    /// Spawn a background task that periodically re-affirms sync with known
    /// peers, so membership stays converged across transient disconnects and
    /// late-joining nodes — not just at startup.
    pub fn spawn_sync_keepalive(self: &std::sync::Arc<Self>, interval: std::time::Duration) {
        let me = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                match me.resume_sync().await {
                    Ok(n) if n > 0 => tracing::debug!("netdoc: re-synced with {n} peer(s)"),
                    Ok(_) => {}
                    Err(e) => tracing::debug!("netdoc: periodic re-sync failed: {e:#}"),
                }
            }
        });
    }

    /// Spawn a fast, lightweight loop that refreshes the trusted-admin-author set
    /// from replicated (founder-authored) peer entries. Decoupled from the
    /// heavier sync keepalive so a federated node converges on co-admin authority
    /// in seconds, not minutes — shrinking the window where a co-admin's entries
    /// would be rejected under enforce right after joining (the default-on
    /// mixed-version concern). Cheap: it only re-reads `peer/` entries.
    pub fn spawn_admin_author_refresh(self: &std::sync::Arc<Self>, interval: std::time::Duration) {
        let me = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                me.refresh_admin_authors().await;
            }
        });
    }

    // ── VPN endpoint registry (Phase 3) ──────────────────────────────────

    /// Publish that this host's virtual `addr` is reachable for VPN traffic at
    /// this netdoc endpoint. Value: `"<endpoint_id_hex> <relay_url?>"`.
    pub async fn register_vpn_endpoint(&self, addr: std::net::Ipv4Addr) -> Result<()> {
        let relay = crate::net::host_relay_url(&self.endpoint)
            .map(|u| u.to_string())
            .unwrap_or_default();
        let value = format!("{} {relay}", self.endpoint.id());
        let key = format!("{KEY_VPN_PREFIX}{addr}");
        self.put_self(&key, value.into_bytes()).await.context("registering vpn endpoint")?;
        Ok(())
    }

    /// Resolve a virtual `addr` to the VPN endpoint serving it.
    pub async fn lookup_vpn_endpoint(
        &self,
        addr: std::net::Ipv4Addr,
    ) -> Result<Option<(iroh::PublicKey, Option<iroh::RelayUrl>)>> {
        let key = format!("{KEY_VPN_PREFIX}{addr}");
        let query = Query::single_latest_per_key().key_exact(key.as_bytes()).build();
        let Some(entry) = self.doc.get_one(query).await.context("get_one vpn")? else {
            return Ok(None);
        };
        if entry.content_len() == 0 {
            return Ok(None);
        }
        let bytes = self.fs_store.get_bytes(entry.content_hash()).await?;
        let value = String::from_utf8_lossy(&bytes);
        let mut parts = value.split_whitespace();
        let id_hex = parts.next().unwrap_or_default();
        let Ok(pubkey) = id_hex.parse::<iroh::PublicKey>() else {
            return Ok(None);
        };
        let relay = parts.next().and_then(|s| s.parse::<iroh::RelayUrl>().ok());
        Ok(Some((pubkey, relay)))
    }

    /// Refresh the `endpoint-id-hex → vIP` map used for VPN ingress
    /// authentication (security-audit C2) from the replicated `vpn/` table.
    #[cfg(unix)]
    pub async fn refresh_vpn_peer_ips(&self) {
        use std::collections::HashMap;
        let mode = self.validation_mode();
        // C1 self-key enforce: bind each vIP/endpoint registration to its owning
        // node's vouched author, so a member can't forge `vpn/<victim>` to
        // intercept the victim's traffic. Built at refresh time (not per packet).
        let bindings = self.vouched_authors().await;

        // Validated addr → owning node, from the `ip/` allocation table. An
        // `ip/<addr> = node` entry counts only if authored by that node's vouched
        // author (enforce); unbound owners pass during migration grace.
        let mut ip_owner: HashMap<std::net::Ipv4Addr, String> = HashMap::new();
        if let Ok(s) = self.doc.get_many(Query::key_prefix(KEY_IP_PREFIX.as_bytes()).build()).await {
            let mut s = std::pin::pin!(s);
            while let Some(Ok(entry)) = s.next().await {
                if entry.content_len() == 0 { continue; }
                let key = String::from_utf8_lossy(entry.key());
                let Some(addr_str) = key.strip_prefix(KEY_IP_PREFIX) else { continue };
                let Ok(addr) = addr_str.parse::<std::net::Ipv4Addr>() else { continue };
                let Ok(bytes) = self.fs_store.get_bytes(entry.content_hash()).await else { continue };
                let node = String::from_utf8_lossy(&bytes).trim().to_string();
                if self_entry_author_ok(Some(&node), &entry.author(), &bindings, mode) {
                    ip_owner.insert(addr, node);
                } else {
                    tracing::warn!("netdoc C1: ip/{addr} author ≠ owner binding — REJECTED (forged vIP claim)");
                }
            }
        }

        // vpn/ table → endpoint-id → vIP, each validated against the owner's
        // vouched author.
        let Ok(stream) = self.doc.get_many(Query::key_prefix(KEY_VPN_PREFIX.as_bytes()).build()).await else { return };
        let mut stream = std::pin::pin!(stream);
        let mut map = HashMap::new();
        while let Some(Ok(entry)) = stream.next().await {
            if entry.content_len() == 0 {
                continue;
            }
            let key = String::from_utf8_lossy(entry.key());
            let Some(addr_str) = key.strip_prefix(KEY_VPN_PREFIX) else { continue };
            let Ok(addr) = addr_str.parse::<std::net::Ipv4Addr>() else { continue };
            let owner = ip_owner.get(&addr).map(|s| s.as_str());
            if !self_entry_author_ok(owner, &entry.author(), &bindings, mode) {
                tracing::warn!("netdoc C1: vpn/{addr} author ≠ owner binding — REJECTED (forged endpoint/interception attempt)");
                continue;
            }
            // Observe-mode author-change telemetry (no-op gate; logs hijacks).
            let _ = self.validate_entry(entry.key(), entry.author());
            let Ok(bytes) = self.fs_store.get_bytes(entry.content_hash()).await else { continue };
            let value = String::from_utf8_lossy(&bytes);
            if let Some(id) = value.split_whitespace().next() {
                map.insert(id.to_string(), addr);
            }
        }
        *self.vpn_peer_ips.write().await = map;
    }

    // ── Host tags + role-derived reach (Steps 3 & 5) ─────────────────────

    /// Publish this host's tags (drives role→tag VPN reach + MagicDNS).
    pub async fn register_host_tags(&self, host_id: &str, tags: &[String]) -> Result<()> {
        let key = format!("tag/{host_id}");
        let value = serde_json::to_vec(tags).context("serializing host tags")?;
        self.put_self(&key, value).await.context("registering host tags")?;
        self.invalidate_reach_cache().await;
        Ok(())
    }

    /// Look up a host's tags from the document (empty if unset).
    pub async fn lookup_host_tags(&self, host_id: &str) -> Result<Vec<String>> {
        let key = format!("tag/{host_id}");
        let query = Query::single_latest_per_key().key_exact(key.as_bytes()).build();
        let Some(entry) = self.doc.get_one(query).await.context("get_one tag")? else {
            return Ok(Vec::new());
        };
        if entry.content_len() == 0 {
            return Ok(Vec::new());
        }
        let bytes = self.fs_store.get_bytes(entry.content_hash()).await?;
        Ok(serde_json::from_slice(&bytes).unwrap_or_default())
    }

    /// All host-tag entries (`node_id → tags`) from the document.
    pub async fn list_host_tags(&self) -> Result<std::collections::HashMap<String, Vec<String>>> {
        let query = Query::key_prefix(b"tag/").build();
        let stream = self.doc.get_many(query).await.context("get_many tag")?;
        let mut stream = std::pin::pin!(stream);
        let mut out = std::collections::HashMap::new();
        while let Some(entry) = stream.next().await {
            let entry = entry.context("reading tag entry")?;
            if entry.content_len() == 0 {
                continue;
            }
            let key = String::from_utf8_lossy(entry.key());
            let Some(node) = key.strip_prefix("tag/") else { continue };
            let bytes = self.fs_store.get_bytes(entry.content_hash()).await?;
            let tags: Vec<String> = serde_json::from_slice(&bytes).unwrap_or_default();
            out.insert(node.to_string(), tags);
        }
        Ok(out)
    }

    /// Publish this node's device-posture attributes (Phase 6): self-attested
    /// `os`, `version`, etc., replicated so role policies can gate reach on them
    /// (`when { principal.os == "linux" }`). Self-attested for the MVP;
    /// cryptographic attestation is the trust-root follow-up.
    pub async fn register_posture(
        &self,
        node_id: &str,
        posture: &std::collections::BTreeMap<String, String>,
    ) -> Result<()> {
        let key = format!("posture/{node_id}");
        let value = serde_json::to_vec(posture).context("serializing posture")?;
        self.put_self(&key, value).await.context("registering posture")?;
        self.invalidate_reach_cache().await;
        Ok(())
    }

    /// All posture entries (`node_id → attrs`) from the document.
    pub async fn list_posture(
        &self,
    ) -> Result<std::collections::HashMap<String, std::collections::BTreeMap<String, String>>> {
        let query = Query::key_prefix(b"posture/").build();
        let stream = self.doc.get_many(query).await.context("get_many posture")?;
        let mut stream = std::pin::pin!(stream);
        let mut out = std::collections::HashMap::new();
        while let Some(entry) = stream.next().await {
            let entry = entry.context("reading posture entry")?;
            if entry.content_len() == 0 {
                continue;
            }
            let key = String::from_utf8_lossy(entry.key());
            let Some(node) = key.strip_prefix("posture/") else { continue };
            let bytes = self.fs_store.get_bytes(entry.content_hash()).await?;
            let attrs = serde_json::from_slice(&bytes).unwrap_or_default();
            out.insert(node.to_string(), attrs);
        }
        Ok(out)
    }

    /// Resolve a role by name from the document's role entries.
    pub async fn find_role(&self, name: &str) -> Result<Option<RoleDefinition>> {
        Ok(self.list_roles().await?.into_iter().find(|r| r.name == name))
    }

    /// Role-derived VPN reach (Step 5): is `src_ip` permitted to reach `dst_ip`?
    /// Resolves src IP → peer → role → tags and dst IP → host → tags through the
    /// document, then applies [`crate::vpn::acl::role_reaches`]. Default-deny on
    /// any missing link (unknown peer, no role, etc.).
    pub async fn vpn_reach_allowed(
        &self,
        src_ip: std::net::Ipv4Addr,
        dst_ip: std::net::Ipv4Addr,
        port: Option<u16>,
    ) -> bool {
        let ips = match self.list_virtual_ips().await {
            Ok(v) => v,
            Err(_) => return false,
        };
        let owner = |ip: std::net::Ipv4Addr| ips.iter().find(|(a, _)| *a == ip).map(|(_, n)| n.clone());
        let (Some(src_node), Some(dst_node)) = (owner(src_ip), owner(dst_ip)) else {
            return false;
        };
        // Cedar reach engine (cached); default-deny on any build failure.
        match self.reach_engine().await {
            Some(engine) => engine.is_reach_allowed(&src_node, &dst_node, port),
            None => false,
        }
    }

    /// Get the cached Cedar reach engine, rebuilding it from current membership
    /// if absent or older than `REACH_CACHE_TTL`. The hot forwarding path calls
    /// `is_reach_allowed` on the returned engine — a pure, in-memory decision.
    pub async fn reach_engine(&self) -> Option<std::sync::Arc<crate::vpn::cedar::AclEngine>> {
        // Fast path: fresh cached engine.
        if let Some((built, engine)) = self.reach_cache.read().await.as_ref()
            && built.elapsed() < REACH_CACHE_TTL
        {
            return Some(engine.clone());
        }
        // Rebuild from a membership snapshot.
        let peers = self.list_peers().await.unwrap_or_default();
        let roles = self.list_roles().await.unwrap_or_default();
        let host_tags = self.list_host_tags().await.unwrap_or_default();
        let posture = self.list_posture().await.unwrap_or_default();
        let authored = self.get_authored_policy().await;
        let engine = match crate::vpn::cedar::AclEngine::build(
            &peers,
            &roles,
            &host_tags,
            &posture,
            authored.as_deref(),
        ) {
            Ok(e) => std::sync::Arc::new(e),
            Err(e) => {
                tracing::warn!("netdoc: building reach engine failed (default-deny): {e:#}");
                return None;
            }
        };
        *self.reach_cache.write().await =
            Some((std::time::Instant::now(), engine.clone()));
        Some(engine)
    }

    /// Drop the cached reach engine so the next decision rebuilds from current
    /// membership. Called after local reach-affecting writes (peer/role/tag/
    /// policy) so admin actions reflect immediately; replicated changes converge
    /// via `REACH_CACHE_TTL`.
    pub async fn invalidate_reach_cache(&self) {
        *self.reach_cache.write().await = None;
    }

    /// Authored Cedar policy text appended to the generated default reach policy
    /// (Phase 3), read from `acl/cedar`. `None` until an operator sets one.
    pub async fn get_authored_policy(&self) -> Option<String> {
        let query = Query::single_latest_per_key().key_exact(b"acl/cedar").build();
        match self.doc.get_one(query).await {
            Ok(Some(e)) if e.content_len() > 0 && self.validate_entry(e.key(), e.author()) => self
                .fs_store
                .get_bytes(e.content_hash())
                .await
                .ok()
                .map(|b| String::from_utf8_lossy(&b).into_owned()),
            _ => None,
        }
    }

    /// Set the authored Cedar policy text (Phase 3). Validated by the caller.
    pub async fn set_authored_policy(&self, policy: &str) -> Result<()> {
        self.doc
            .set_bytes(self.author, b"acl/cedar".to_vec(), policy.as_bytes().to_vec())
            .await
            .context("writing authored Cedar policy")?;
        self.invalidate_reach_cache().await;
        Ok(())
    }

    /// The warren's MagicDNS domain (doc `network/domain`, default `hop`).
    /// A named warren sets `<warren-name>.hop`; unnamed falls back to `hop`.
    pub async fn network_domain(&self) -> String {
        let query = Query::single_latest_per_key().key_exact(b"network/domain").build();
        match self.doc.get_one(query).await {
            Ok(Some(e)) if e.content_len() > 0 => self
                .fs_store
                .get_bytes(e.content_hash())
                .await
                .ok()
                .map(|b| String::from_utf8_lossy(&b).trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "hop".to_string()),
            _ => "hop".to_string(),
        }
    }

    /// Set the warren's MagicDNS domain.
    pub async fn set_network_domain(&self, domain: &str) -> Result<()> {
        self.doc
            .set_bytes(self.author, b"network/domain".to_vec(), domain.as_bytes().to_vec())
            .await
            .context("writing network domain")?;
        Ok(())
    }

    /// Enable the VPN data plane (Phase 3, opt-in): claim a virtual IP, register
    /// this host's tags + endpoint, create the TUN device, and start forwarding
    /// under **role-derived reach** (Step 5; default-deny). Off unless explicitly
    /// called.
    #[cfg(unix)]
    pub async fn enable_vpn(
        self: &std::sync::Arc<Self>,
        host_node_id: &str,
        host_tags: &[String],
    ) -> Result<std::net::Ipv4Addr> {
        let addr = self.claim_virtual_ip(host_node_id).await?;
        let tun = std::sync::Arc::new(crate::vpn::create_tun(addr).await?);
        *self.vpn_tun.write().await = Some(tun.clone());
        // Ingress authentication state (security-audit C2): our own vIP (the only
        // legitimate ingress destination) + the peer-IP map (refreshed below and
        // periodically) used to reject spoofed source IPs.
        *self.vpn_local_ip.write().await = Some(addr);
        self.register_vpn_endpoint(addr).await?;
        self.refresh_vpn_peer_ips().await;
        {
            let me = std::sync::Arc::clone(self);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    me.refresh_vpn_peer_ips().await;
                }
            });
        }
        // On-demand refresh: `VpnInbound` signals when a packet arrives from a
        // peer it can't yet authenticate (e.g. just after that peer rebooted and
        // re-registered). Refresh immediately so reconvergence doesn't wait for
        // the 5s tick, rate-limited to once per second so a spoofed-source flood
        // can't amplify into a doc-read storm.
        {
            let me = std::sync::Arc::clone(self);
            let notify = self.vpn_refresh.clone();
            tokio::spawn(async move {
                loop {
                    notify.notified().await;
                    me.refresh_vpn_peer_ips().await;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            });
        }
        // Publish this host's tags so other members' roles can resolve reach.
        if let Err(e) = self.register_host_tags(host_node_id, host_tags).await {
            tracing::warn!("vpn: host-tag registration failed: {e:#}");
        }
        // Self-attest device posture (Phase 6): OS + hop version, for posture-
        // gated reach policies.
        let posture = std::collections::BTreeMap::from([
            ("os".to_string(), std::env::consts::OS.to_string()),
            ("version".to_string(), env!("CARGO_PKG_VERSION").to_string()),
        ]);
        if let Err(e) = self.register_posture(host_node_id, &posture).await {
            tracing::warn!("vpn: posture registration failed: {e:#}");
        }
        // M4a: a host that OWNS this warren (created the namespace, not federated)
        // self-registers as an `admin` member so it can originate and return VPN
        // traffic. Joiners get their membership/role from the inviter, never
        // self-assigned. Only the owner of a namespace can self-claim admin.
        if !self.federated && self.get_peer(host_node_id).await.ok().flatten().is_none() {
            let me = Peer {
                node_id: host_node_id.to_string(),
                name: "self".to_string(),
                authorized_at: now_timestamp(),
                last_seen: None,
                username: None,
                role: crate::config::PeerRole::Creator,
                role_name: Some("admin".to_string()),
                // The founder vouches its own doc author, so its self-owned
                // entries validate under enforce.
                netdoc_author: Some(self.author_hex()),
                // Record the founder's own self-doc read ticket so other nodes
                // import its self-state from the isolated self-doc.
                self_doc: self.self_doc_read_ticket().await.ok(),
                sandbox: crate::sandbox::SandboxPolicy::default(),
            };
            if let Err(e) = self.put_peer(&me).await {
                tracing::warn!("vpn: self-member registration failed: {e:#}");
            }
        }
        let me = std::sync::Arc::clone(self);
        tokio::spawn(async move { me.vpn_outbound_loop(tun).await });

        // MagicDNS: register this host's name → virtual IP and serve `*.hop`
        // lookups on the virtual interface (split-DNS points `.hop` here).
        if let Ok(h) = hostname::get() {
            let name = h.to_string_lossy().to_lowercase();
            if let Err(e) = self.register_name(&name, addr).await {
                tracing::warn!("vpn: name registration failed: {e:#}");
            }
        }
        let dns = std::sync::Arc::clone(self);
        tokio::spawn(async move { dns.vpn_dns_loop(addr).await });

        Ok(addr)
    }

    /// Register `name` → virtual `addr` for MagicDNS (replicates to all nodes).
    pub async fn register_name(&self, name: &str, addr: std::net::Ipv4Addr) -> Result<()> {
        let key = format!("name/{}", name.to_lowercase());
        self.put_self(&key, addr.to_string().into_bytes()).await.context("registering name")?;
        Ok(())
    }

    /// Resolve a host `name` to its virtual IP via the document.
    ///
    /// C1 `name/` self-key enforce: a `name/<name> = <vIP>` entry is honored only
    /// if its author is the vouched author of the node that owns that vIP (the
    /// `ip/` table), so a member can't forge a MagicDNS name to point at its own
    /// endpoint (DNS spoofing). An unbound owner passes under migration grace.
    /// Off/Observe resolve straight from the doc (current behaviour).
    pub async fn lookup_name(&self, name: &str) -> Result<Option<std::net::Ipv4Addr>> {
        let key = format!("name/{}", name.to_lowercase());
        let query = Query::single_latest_per_key().key_exact(key.as_bytes()).build();
        let Some(entry) = self.doc.get_one(query).await.context("get_one name")? else {
            return Ok(None);
        };
        if entry.content_len() == 0 {
            return Ok(None);
        }
        let bytes = self.fs_store.get_bytes(entry.content_hash()).await?;
        let Some(addr) = String::from_utf8_lossy(&bytes).trim().parse::<std::net::Ipv4Addr>().ok()
        else {
            return Ok(None);
        };
        if self.validation_mode() == ValidationMode::Enforce
            && !self.name_author_ok(addr, &entry.author()).await
        {
            tracing::warn!(
                "netdoc C1: name/{} author ≠ owner binding — REJECTED (MagicDNS spoof attempt)",
                name.to_lowercase()
            );
            return Ok(None);
        }
        Ok(Some(addr))
    }

    /// Whether `name_author` is allowed to bind a name to `addr`: it must be the
    /// vouched author of the node that owns `addr` (from the author-validated
    /// `ip/` table). An unbound owner (or no valid `ip/` claim) → grace (allow).
    async fn name_author_ok(&self, addr: std::net::Ipv4Addr, name_author: &AuthorId) -> bool {
        let bindings = self.vouched_authors().await;
        // Resolve addr → owning node from the ip/ table, honoring only a
        // self-author-valid ip/ entry (a forged vIP claim confers no ownership).
        let ip_key = format!("{KEY_IP_PREFIX}{addr}");
        let owner = match self
            .doc
            .get_one(Query::single_latest_per_key().key_exact(ip_key.as_bytes()).build())
            .await
        {
            Ok(Some(e)) if e.content_len() > 0 => match self.fs_store.get_bytes(e.content_hash()).await {
                Ok(b) => {
                    let node = String::from_utf8_lossy(&b).trim().to_string();
                    if self_entry_author_ok(Some(&node), &e.author(), &bindings, ValidationMode::Enforce) {
                        Some(node)
                    } else {
                        None
                    }
                }
                Err(_) => None,
            },
            _ => None,
        };
        self_entry_author_ok(owner.as_deref(), name_author, &bindings, ValidationMode::Enforce)
    }

    /// MagicDNS server: answer `A` queries for `*.hop` on the virtual interface.
    #[cfg(unix)]
    async fn vpn_dns_loop(&self, addr: std::net::Ipv4Addr) {
        let sock = match tokio::net::UdpSocket::bind((addr, 53)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("vpn: DNS bind on {addr}:53 failed ({e}); MagicDNS disabled");
                return;
            }
        };
        let domain = self.network_domain().await;
        let suffix = format!(".{domain}");
        tracing::info!("vpn: MagicDNS serving *.{domain} on {addr}:53");
        let mut buf = [0u8; 512];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some(query) = crate::vpn::dns::parse_query(&buf[..n]) else { continue };
            let resolved = match query.name.strip_suffix(&suffix) {
                Some(host) => self.lookup_name(host).await.ok().flatten(),
                None => None,
            };
            let resp = crate::vpn::dns::build_response(&query, resolved);
            let _ = sock.send_to(&resp, peer).await;
        }
    }

    /// Read packets off the TUN device and forward each to the owning peer over
    /// a `hop/vpn/1` QUIC-datagram connection (re-using/reconnecting as needed).
    #[cfg(unix)]
    async fn vpn_outbound_loop(&self, tun: std::sync::Arc<tun::AsyncDevice>) {
        use std::collections::HashMap;
        let mut conns: HashMap<iroh::PublicKey, iroh::endpoint::Connection> = HashMap::new();
        let mut buf = vec![0u8; 65535];
        loop {
            let n = match tun.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!("vpn: TUN read error, stopping forwarder: {e}");
                    break;
                }
            };
            let pkt = &buf[..n];
            let Some(dst) = crate::vpn::parse_dest_ipv4(pkt) else { continue };
            if !crate::vpn::is_virtual_addr(dst) {
                continue;
            }
            // Role-derived reach (Step 5; default-deny). Drop packets the source
            // peer's role doesn't permit to the destination host's tags.
            match crate::vpn::parse_src_ipv4(pkt) {
                Some(src) if self.vpn_reach_allowed(src, dst, crate::vpn::parse_dest_port(pkt)).await => {}
                _ => continue,
            }
            let (pubkey, relay) = match self.lookup_vpn_endpoint(dst).await {
                Ok(Some(v)) => v,
                _ => continue, // unknown destination — drop
            };
            // Reuse an open connection, else dial one.
            let conn = match conns.get(&pubkey) {
                Some(c) if c.close_reason().is_none() => c.clone(),
                _ => {
                    match crate::net::connect_to_host_with_alpn(
                        &self.endpoint,
                        pubkey,
                        relay.as_ref(),
                        crate::vpn::VPN_ALPN,
                    )
                    .await
                    {
                        Ok((c, _)) => {
                            conns.insert(pubkey, c.clone());
                            c
                        }
                        Err(e) => {
                            tracing::debug!("vpn: dial {pubkey} failed: {e}");
                            continue;
                        }
                    }
                }
            };
            if let Err(e) = conn.send_datagram(bytes::Bytes::copy_from_slice(pkt)) {
                tracing::debug!("vpn: send_datagram failed: {e}");
                conns.remove(&pubkey);
            }
        }
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

    /// Produce a WRITE-capability ticket so another host can join this network
    /// (federation, Phase 3): import it to replicate and contribute entries.
    pub async fn write_ticket(&self) -> Result<DocTicket> {
        self.doc
            .share(ShareMode::Write, AddrInfoOptions::RelayAndAddresses)
            .await
            .context("sharing write ticket")
    }

    // ── Per-member self-doc (C1 write-isolation) ─────────────────────────────

    /// A **read** ticket for this node's own self-doc, announced to an admin so
    /// other nodes can import this node's self-state read-only. The write key is
    /// never shared — only this node can write its self-doc.
    pub async fn self_doc_read_ticket(&self) -> Result<String> {
        let ticket = self
            .self_doc
            .share(ShareMode::Read, AddrInfoOptions::RelayAndAddresses)
            .await
            .context("sharing self-doc read ticket")?;
        Ok(ticket.to_string())
    }

    /// Record an admitted member's self-doc read ticket in the admin doc
    /// (`peer/N.self_doc`). Trust-anchor-only and member-must-exist, like
    /// `record_peer_author`. Returns `Ok(false)` when not applicable.
    pub async fn record_peer_self_doc(&self, node_id: &str, ticket: &str) -> Result<bool> {
        if !self.is_trust_anchor() {
            return Ok(false);
        }
        if ticket.parse::<DocTicket>().is_err() {
            anyhow::bail!("invalid self-doc ticket");
        }
        let Some(mut peer) = self.get_peer(node_id).await? else {
            return Ok(false);
        };
        if peer.self_doc.as_deref() == Some(ticket) {
            return Ok(true);
        }
        peer.self_doc = Some(ticket.to_string());
        self.put_peer(&peer).await?;
        tracing::info!("netdoc: recorded self-doc for member {}", &node_id[..8.min(node_id.len())]);
        Ok(true)
    }

    /// Resolve (and lazily import + cache) a member's read-only self-doc from the
    /// admin doc's `peer/N.self_doc` binding. `None` when the member has no
    /// self-doc (legacy → shared-doc fallback) or the ticket is unusable.
    /// On-demand sync: the self-doc is imported the first time a member is
    /// reached, then cached for the process lifetime.
    pub async fn member_self_doc(&self, node_id: &str) -> Option<Doc> {
        if let Some(doc) = self.member_docs.read().await.get(node_id).cloned() {
            return Some(doc);
        }
        let peer = self.get_peer(node_id).await.ok().flatten()?;
        let ticket: DocTicket = peer.self_doc.as_deref()?.parse().ok()?;
        // Already syncing this namespace (e.g. our own)? open instead of re-import.
        let ns = ticket.capability.id();
        let doc = match self.docs.open(ns).await {
            Ok(Some(d)) => d,
            _ => match self.docs.import(ticket).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::debug!("netdoc: import self-doc for {} failed: {e:#}", &node_id[..8.min(node_id.len())]);
                    return None;
                }
            },
        };
        self.member_docs.write().await.insert(node_id.to_string(), doc.clone());
        Some(doc)
    }

    /// Drop a member's cached self-doc (on revoke).
    pub async fn evict_member_self_doc(&self, node_id: &str) {
        self.member_docs.write().await.remove(node_id);
    }

    /// Write a self-owned entry (`ip/ vpn/ name/ tag/ posture/`) to this node's
    /// **self-doc** (the isolated, member-only-writable source) AND the shared
    /// admin doc (migration dual-write). The shared-doc copy keeps not-yet-
    /// upgraded readers — which only read the shared doc — working; the self-doc
    /// is what upgraded readers prefer. Once self-docs are universal the
    /// shared-doc write is dropped, leaving self-state physically isolated.
    async fn put_self(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.self_doc
            .set_bytes(self.author, key.as_bytes().to_vec(), value.clone())
            .await
            .context("writing self-doc entry")?;
        self.doc
            .set_bytes(self.author, key.as_bytes().to_vec(), value)
            .await
            .context("writing shared self entry")?;
        Ok(())
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
        self.invalidate_reach_cache().await;
        Ok(())
    }

    /// Fetch a single peer by node id, if present (and not tombstoned).
    pub async fn get_peer(&self, node_id: &str) -> Result<Option<Peer>> {
        let key = format!("{KEY_PEER_PREFIX}{node_id}");
        let query = Query::single_latest_per_key().key_exact(key.as_bytes()).build();
        let Some(entry) = self.doc.get_one(query).await.context("get_one peer")? else {
            return Ok(None);
        };
        // Membership grants are admin-owned: a peer entry forged by a non-admin
        // is ignored in enforce mode (C1).
        if !self.validate_entry(entry.key(), entry.author()) {
            return Ok(None);
        }
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
        self.invalidate_reach_cache().await;
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
        self.invalidate_reach_cache().await;
        Ok(())
    }

    /// Whether a peer has been revoked.
    pub async fn is_revoked(&self, node_id: &str) -> Result<bool> {
        let key = format!("{KEY_REVOCATION_PREFIX}{node_id}");
        let query = Query::single_latest_per_key().key_exact(key.as_bytes()).build();
        // A revocation only counts if it passes author validation — in enforce
        // mode a revocation forged by a non-admin must not lock anyone out (C1).
        match self.doc.get_one(query).await.context("get_one revocation")? {
            Some(entry) => Ok(self.validate_entry(entry.key(), entry.author())),
            None => Ok(false),
        }
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
            if !self.validate_entry(entry.key(), entry.author()) {
                continue;
            }
            if let Some(value) = self.decode_entry::<T>(&entry).await? {
                out.push(value);
            }
        }
        Ok(out)
    }

    /// Validate a replicated entry's author (security-audit C1). Returns whether
    /// the entry should be **honored**:
    /// - `Off` → always honor.
    /// - **Admin-owned keys** (`peer/ role/ revocation/ acl/ network/`): honored
    ///   only when authored by the founder anchor. In `Observe`, a mismatch is
    ///   logged but still honored; in `Enforce` it's rejected (skipped). If the
    ///   anchor is unknown, the entry is honored (can't validate) — which is why
    ///   `Enforce` should only be enabled once `record_founder_anchor` has set it.
    /// - **Self-owned keys** (`vpn/ ip/ name/ tag/ posture/`): tracked for
    ///   author *stability*; an author change is logged as a likely
    ///   forgery/hijack. These stay honored even in `Enforce` (first-seen TOFU
    ///   would risk false rejects) until the per-member binding lands.
    #[must_use]
    fn validate_entry(&self, key: &[u8], author: AuthorId) -> bool {
        if self.validation_mode() == ValidationMode::Off {
            return true;
        }
        if is_admin_owned_key(key) {
            // Admin keys are honored from the founder OR any founder-vouched
            // co-admin author (multi-admin / federated warrens). When no founder
            // anchor is known (legacy join) the set is empty → honor (no
            // partition); enforcement only kicks in once an anchor exists.
            if self.founder_author().is_some() && !self.is_admin_author(&author) {
                tracing::warn!(
                    "netdoc C1: admin key {:?} authored by {} ∉ vouched admins — {}",
                    String::from_utf8_lossy(key),
                    author,
                    if self.validation_mode() == ValidationMode::Enforce { "REJECTED" } else { "honored (observe)" },
                );
                return self.validation_mode() != ValidationMode::Enforce;
            }
            return true;
        }
        if is_self_owned_key(key) {
            let mut map = self.entry_authors.lock().unwrap();
            match map.get(key) {
                Some(prev) if *prev != author => {
                    tracing::warn!(
                        "netdoc C1: author changed for key {:?} ({} → {}) — possible forgery/hijack",
                        String::from_utf8_lossy(key),
                        prev,
                        author,
                    );
                    map.insert(key.to_vec(), author);
                }
                None => {
                    map.insert(key.to_vec(), author);
                }
                _ => {}
            }
        }
        true
    }
}

/// Keys that a single node owns and should keep one stable author. The C1
/// forgery vectors (traffic interception, vIP theft, MagicDNS spoofing) all
/// hijack one of these.
fn is_self_owned_key(key: &[u8]) -> bool {
    const SELF_PREFIXES: &[&[u8]] = &[b"vpn/", b"ip/", b"name/", b"tag/", b"posture/"];
    SELF_PREFIXES.iter().any(|p| key.starts_with(p))
}

/// Admin-owned keys — membership, roles, revocations, network policy. In enforce
/// mode these are honored only when authored by the founder/admin anchor.
fn is_admin_owned_key(key: &[u8]) -> bool {
    const ADMIN_PREFIXES: &[&[u8]] = &[b"peer/", b"role/", b"revocation/", b"acl/", b"network/"];
    ADMIN_PREFIXES.iter().any(|p| key.starts_with(p))
}

/// Decide whether a self-owned entry whose claimed owner is `owner` and whose
/// writer is `author` should be honored, given the vouched `node → author`
/// bindings and the validation `mode` (C1 self-key enforce). In `Off`/`Observe`
/// → always honor (the caller logs anomalies in observe). In `Enforce` → honor
/// only when the owner has no binding yet (migration grace) or the author equals
/// the owner's vouched author. A forged entry (author ≠ the owner's binding) is
/// rejected.
fn self_entry_author_ok(
    owner: Option<&str>,
    author: &AuthorId,
    bindings: &std::collections::HashMap<String, AuthorId>,
    mode: ValidationMode,
) -> bool {
    if mode != ValidationMode::Enforce {
        return true;
    }
    match owner.and_then(|n| bindings.get(n)) {
        Some(expected) => author == expected,
        None => true, // owner unbound (migration grace) — honor
    }
}

/// Parse a 64-char hex iroh-docs author id.
fn parse_author_hex(hex_str: &str) -> Option<AuthorId> {
    let bytes = hex::decode(hex_str.trim()).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(AuthorId::from(&arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PeerRole;
    use crate::sandbox::SandboxPolicy;

    #[test]
    fn self_owned_key_classification() {
        // The C1 forgery vectors — each must be tracked for author stability.
        for k in [
            &b"vpn/100.64.0.1"[..],
            b"ip/100.64.0.1",
            b"name/myhost",
            b"tag/abcdef",
            b"posture/abcdef",
        ] {
            assert!(is_self_owned_key(k), "{:?} should be self-owned", String::from_utf8_lossy(k));
        }
        // Admin-owned tables are legitimately rewritten by the admin → not tracked.
        for k in [&b"peer/abc"[..], b"role/admin", b"revocation/abc", b"acl/cedar", b"network/domain"] {
            assert!(!is_self_owned_key(k), "{:?} should not be self-owned", String::from_utf8_lossy(k));
        }
    }

    #[test]
    fn validation_mode_from_env_defaults_observe() {
        // Default (unset / unknown) is the safe Observe.
        assert_eq!(ValidationMode::default(), ValidationMode::Observe);
    }

    #[test]
    fn admin_owned_key_classification() {
        for k in [&b"peer/abc"[..], b"role/admin", b"revocation/abc", b"acl/cedar", b"network/domain"] {
            assert!(is_admin_owned_key(k), "{:?} should be admin-owned", String::from_utf8_lossy(k));
        }
        for k in [&b"vpn/100.64.0.1"[..], b"ip/x", b"name/h", b"tag/x", b"posture/x"] {
            assert!(!is_admin_owned_key(k));
        }
        // A key is never both classes.
        for k in [&b"peer/x"[..], b"vpn/x", b"role/x", b"name/x"] {
            assert!(!(is_admin_owned_key(k) && is_self_owned_key(k)));
        }
    }

    #[test]
    fn self_entry_author_validation() {
        use std::collections::HashMap;
        let owner_author = AuthorId::from(&[1u8; 32]);
        let attacker_author = AuthorId::from(&[2u8; 32]);
        let mut bindings = HashMap::new();
        bindings.insert("nodeN".to_string(), owner_author);

        // Off / Observe: always honor (no enforcement).
        for mode in [ValidationMode::Off, ValidationMode::Observe] {
            assert!(self_entry_author_ok(Some("nodeN"), &attacker_author, &bindings, mode));
        }
        // Enforce: the owner's own author is honored…
        assert!(self_entry_author_ok(Some("nodeN"), &owner_author, &bindings, ValidationMode::Enforce));
        // …a forged author for a bound node is rejected (the C1 attack).
        assert!(!self_entry_author_ok(Some("nodeN"), &attacker_author, &bindings, ValidationMode::Enforce));
        // An unbound owner (migration grace) is honored even in enforce.
        assert!(self_entry_author_ok(Some("unknown"), &attacker_author, &bindings, ValidationMode::Enforce));
        assert!(self_entry_author_ok(None, &attacker_author, &bindings, ValidationMode::Enforce));
    }

    #[test]
    fn author_hex_roundtrips() {
        let arr = [7u8; 32];
        let a = AuthorId::from(&arr);
        let hex = hex::encode(a.to_bytes());
        assert_eq!(parse_author_hex(&hex), Some(a));
        assert_eq!(parse_author_hex("not-hex"), None);
        assert_eq!(parse_author_hex("00"), None); // wrong length
    }

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
            role_name: None,
            netdoc_author: None,
            self_doc: None,
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

    #[tokio::test]
    async fn role_derived_reach_via_doc() {
        use crate::proto::{RoleDefinition, UserMode};
        let dir = tempfile::tempdir().unwrap();
        let net = NetDoc::spawn(test_endpoint().await, dir.path(), Bootstrap::Create)
            .await
            .expect("spawn");

        // A developer role reaches `staging`-tagged hosts.
        net.put_role(&RoleDefinition {
            name: "developer".into(),
            host_tags: vec!["staging".into()],
            user_mode: UserMode::Individual,
            sudo: false,
            admin: false,
            network_only: false,
            groups: vec![],
            shell: None,
            sandbox: SandboxPolicy::default(),
            capabilities: Default::default(),
        })
        .await
        .unwrap();

        // src peer = a developer; dst host tagged staging.
        let src_ip = net.claim_virtual_ip("devpeer").await.unwrap();
        let dst_ip = net.claim_virtual_ip("staginghost").await.unwrap();
        let mut dev = sample_peer("devpeer", "dev");
        dev.role_name = Some("developer".into());
        net.put_peer(&dev).await.unwrap();
        net.register_host_tags("staginghost", &["staging".into()]).await.unwrap();

        // Developer reaches the staging host.
        assert!(net.vpn_reach_allowed(src_ip, dst_ip, None).await);

        // Re-tag the host production-only → developer is denied.
        net.register_host_tags("staginghost", &["production".into()]).await.unwrap();
        assert!(!net.vpn_reach_allowed(src_ip, dst_ip, None).await);

        // A member (no role_name) reaches nothing.
        let m_ip = net.claim_virtual_ip("memberpeer").await.unwrap();
        net.put_peer(&sample_peer("memberpeer", "m")).await.unwrap();
        net.register_host_tags("staginghost", &["staging".into()]).await.unwrap();
        assert!(!net.vpn_reach_allowed(m_ip, dst_ip, None).await);
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

    /// Federation safety (Step 4): a federated host must NOT revoke peers it
    /// doesn't own when reconciling against its own (empty) peers.json.
    #[tokio::test]
    async fn federated_reconcile_is_additive() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        a.put_peer(&sample_peer("ownedbyA", "alice")).await.unwrap();
        let ticket = a.write_ticket().await.unwrap();

        let dir_b = tempfile::tempdir().unwrap();
        let b = NetDoc::spawn(
            test_endpoint().await,
            dir_b.path(),
            Bootstrap::Import(Box::new(ticket)),
        )
        .await
        .expect("spawn B");
        assert!(b.federated, "imported namespace must be marked federated");

        // Wait for A's peer to replicate to B.
        let mut replicated = false;
        for _ in 0..150 {
            if b.get_peer("ownedbyA").await.unwrap().is_some() {
                replicated = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        assert!(replicated, "peer did not replicate A -> B");

        // B reconciles against its own (empty) peers.json — must NOT revoke A's peer.
        b.reconcile(&[], &[]).await.unwrap();
        assert!(b.get_peer("ownedbyA").await.unwrap().is_some(), "federated reconcile wrongly revoked another host's peer");
        assert!(!b.is_revoked("ownedbyA").await.unwrap());
    }

    /// Reboot resilience (unit): `resume_sync` must rediscover the warren's
    /// peers from the persisted `vpn/` endpoint table and exclude self — this is
    /// the logic a reopened node (`Bootstrap::Open`, which iroh-docs does NOT
    /// auto-sync) relies on. Deterministic: no replication/reopen (those are
    /// exercised end-to-end, over a real relay, by `vpn-e2e.sh`'s reboot phase).
    #[tokio::test]
    async fn resume_sync_finds_persisted_peers_and_excludes_self() {
        let dir = tempfile::tempdir().unwrap();
        let net = NetDoc::spawn(test_endpoint().await, dir.path(), Bootstrap::Create)
            .await
            .expect("spawn");

        // This node's own VPN endpoint (must be excluded from re-sync).
        net.register_vpn_endpoint("100.64.0.1".parse().unwrap()).await.unwrap();
        // A peer's endpoint, as it would arrive via replication.
        let peer_pk = iroh::SecretKey::from_bytes(&[9u8; 32]).public();
        net.doc
            .set_bytes(
                net.author,
                b"vpn/100.64.0.2".to_vec(),
                format!("{peer_pk} ").into_bytes(),
            )
            .await
            .unwrap();

        // resume_sync finds exactly the one non-self peer (start_sync is
        // best-effort and tolerated when the peer has no relay).
        let n = net.resume_sync().await.expect("resume_sync");
        assert_eq!(n, 1, "resume_sync should find the peer endpoint and exclude self");
    }

    /// Federation: a VPN endpoint registration written on host A must replicate
    /// to host B after it imports A's write ticket. Validates the multi-node
    /// doc-sync path (gossip + reconciliation) the VPN routing depends on.
    ///
    /// C1 self-key enforce, end to end: a member with a write ticket forges
    /// `vpn/<founder_addr>` to point the founder's vIP at the member's own
    /// endpoint (traffic interception). In Observe the forgery replicates and is
    /// honored; flipping the founder to Enforce drops it while keeping the
    /// founder's legitimate registration.
    #[cfg(unix)]
    #[tokio::test]
    async fn enforce_rejects_forged_vpn_entry() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        a.record_founder_anchor(None); // founder = A's own author

        // A claims a vIP, vouches its own author binding (peer/node_a), and
        // registers its endpoint — all authored by A.
        let node_a = "nodeAAAAAAAA";
        let addr = a.claim_virtual_ip(node_a).await.unwrap();
        let mut peer = sample_peer(node_a, "A");
        peer.netdoc_author = Some(a.author_hex());
        a.put_peer(&peer).await.unwrap();
        a.register_vpn_endpoint(addr).await.unwrap();

        // Member B (write ticket) forges A's vpn entry → A's addr → B's endpoint.
        let ticket = a.write_ticket().await.unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let b = NetDoc::spawn(test_endpoint().await, dir_b.path(), Bootstrap::Import(Box::new(ticket)))
            .await
            .expect("spawn B");
        b.register_vpn_endpoint(addr).await.unwrap();

        let a_id = a.endpoint.id().to_string();
        let b_id = b.endpoint.id().to_string();

        // Phase 1 (Observe, the default): poll until B's forgery replicates and is
        // honored — proving the attack would work without enforcement.
        let mut replicated = false;
        for _ in 0..150 {
            a.refresh_vpn_peer_ips().await;
            if a.vpn_peer_ips.read().await.contains_key(&b_id) {
                replicated = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        assert!(replicated, "forged vpn entry did not replicate A<-B within 10s (test setup)");

        // Phase 2 (Enforce): the forgery must be dropped; A's own entry kept.
        a.set_validation_mode(ValidationMode::Enforce);
        a.refresh_vpn_peer_ips().await;
        let map = a.vpn_peer_ips.read().await.clone();
        assert_eq!(map.get(&a_id), Some(&addr), "founder's own endpoint must remain mapped");
        assert!(
            !map.contains_key(&b_id),
            "enforce must reject the forged vpn entry (member's endpoint on the founder's vIP)"
        );
    }

    /// C1 self-key enforce, the binding's teeth: once the founder vouches member
    /// B's author via `record_peer_author` (the `AnnounceNetdocAuthor`
    /// mechanism), a forged `vpn/<B's vIP>` from a *different* author is rejected
    /// under Enforce while B's own registration is honored. Before the vouch the
    /// owner is unbound (migration grace) and the forgery would be honored —
    /// proving the binding, not mere membership, is what authorizes the entry.
    #[cfg(unix)]
    #[tokio::test]
    async fn enforce_rejects_forgery_against_vouched_member() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        a.record_founder_anchor(None); // founder = A

        let ticket = a.write_ticket().await.unwrap();
        // Member B (legitimate) and attacker C both import the warren.
        let dir_b = tempfile::tempdir().unwrap();
        let b = NetDoc::spawn(test_endpoint().await, dir_b.path(), Bootstrap::Import(Box::new(ticket.clone())))
            .await
            .expect("spawn B");
        let dir_c = tempfile::tempdir().unwrap();
        let c = NetDoc::spawn(test_endpoint().await, dir_c.path(), Bootstrap::Import(Box::new(ticket)))
            .await
            .expect("spawn C");
        let b_id = b.endpoint.id().to_string();
        let c_id = c.endpoint.id().to_string();

        // A admits B (admin-owned peer entry). B claims its own stable vIP and
        // registers its endpoint (both self-owned, authored by B). Attacker C
        // forges the same vIP -> C's endpoint (authored by C).
        a.put_peer(&sample_peer(&b_id, "B")).await.unwrap();
        let addr_b = b.claim_virtual_ip(&b_id).await.unwrap();
        b.register_vpn_endpoint(addr_b).await.unwrap();
        c.register_vpn_endpoint(addr_b).await.unwrap();

        // Wait until both B's legit registration and C's forgery replicate to A
        // (Observe default — both honored, proving the attack works unguarded).
        let mut replicated = false;
        for _ in 0..150 {
            a.refresh_vpn_peer_ips().await;
            let m = a.vpn_peer_ips.read().await;
            if m.contains_key(&c_id) && m.contains_key(&b_id) {
                replicated = true;
                break;
            }
            drop(m);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        assert!(replicated, "B+C vpn entries did not replicate to A within 10s (test setup)");

        // Founder vouches B's author (the announce mechanism). Idempotent + only
        // for an already-admitted member.
        assert!(
            a.record_peer_author(&b_id, &b.author_hex()).await.unwrap(),
            "trust anchor must record the binding for an admitted member"
        );
        assert!(
            a.record_peer_author(&b_id, &b.author_hex()).await.unwrap(),
            "record_peer_author must be idempotent"
        );
        assert_eq!(
            a.vouched_authors().await.get(&b_id).copied(),
            parse_author_hex(&b.author_hex()),
            "vouched binding must be visible to the validator"
        );

        // Enforce: B's own endpoint stays mapped; C's forgery is dropped.
        a.set_validation_mode(ValidationMode::Enforce);
        a.refresh_vpn_peer_ips().await;
        let map = a.vpn_peer_ips.read().await.clone();
        assert_eq!(map.get(&b_id), Some(&addr_b), "vouched member's own entry must be honored");
        assert!(
            !map.contains_key(&c_id),
            "enforce must reject a forgery against a vouched member's vIP"
        );
    }

    /// Vouched-admin-authors: a co-admin's federated `peer/` entry is rejected
    /// under Enforce until the founder vouches that co-admin's author (a
    /// founder-authored peer entry with the Creator role + a netdoc_author
    /// binding); afterwards it's honored. This is what makes enforce safe for
    /// multi-admin / federated warrens (and unblocks default-on).
    #[tokio::test]
    async fn enforce_honors_vouched_co_admin_peer_entry() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        a.record_founder_anchor(None); // founder = A

        // Co-admin B imports the warren and invites C — i.e. B authors peer/C.
        let ticket = a.write_ticket().await.unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let b = NetDoc::spawn(test_endpoint().await, dir_b.path(), Bootstrap::Import(Box::new(ticket)))
            .await
            .expect("spawn B");
        let b_id = b.endpoint.id().to_string();
        b.put_peer(&sample_peer("nodeCCCCCCCC", "C")).await.unwrap();

        // Wait until B's peer/C replicates to A (Observe default — honored).
        let mut replicated = false;
        for _ in 0..150 {
            if a.get_peer("nodeCCCCCCCC").await.unwrap().is_some() {
                replicated = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        assert!(replicated, "B's peer/C did not replicate A<-B within 10s (test setup)");

        // Enforce, B NOT yet a vouched admin → A rejects B-authored peer/C.
        a.set_validation_mode(ValidationMode::Enforce);
        a.refresh_admin_authors().await;
        assert!(
            a.get_peer("nodeCCCCCCCC").await.unwrap().is_none(),
            "enforce must reject a non-admin author's peer entry"
        );

        // Founder admits B as a co-admin (Creator role) and vouches its author —
        // a founder-authored peer/B entry, the only way to confer admin authority.
        let mut admin_b = sample_peer(&b_id, "B");
        admin_b.role = PeerRole::Creator;
        admin_b.netdoc_author = Some(b.author_hex());
        a.put_peer(&admin_b).await.unwrap();
        a.refresh_admin_authors().await;

        // Now B is a vouched admin → its peer/C entry is honored under enforce.
        assert!(
            a.get_peer("nodeCCCCCCCC").await.unwrap().is_some(),
            "enforce must honor a vouched co-admin's peer entry"
        );
    }

    /// C1 `name/` self-key enforce: a MagicDNS name bound by a non-owner author
    /// (spoof) is dropped under Enforce, while the legitimate owner's binding
    /// resolves. Mirrors the vpn/ forgery test but via `lookup_name`.
    #[tokio::test]
    async fn enforce_rejects_spoofed_name() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        a.record_founder_anchor(None); // founder = A, vouched for its own author

        // A (the founder) owns vIP addr and binds name "web" → addr. A vouches its
        // own author, so under enforce A's own ip/name entries validate.
        let node_a = a.endpoint.id().to_string();
        let mut peer = sample_peer(&node_a, "A");
        peer.netdoc_author = Some(a.author_hex());
        a.put_peer(&peer).await.unwrap();
        let addr = a.claim_virtual_ip(&node_a).await.unwrap();
        a.register_name("web", addr).await.unwrap();

        // Observe (default): the legit name resolves.
        assert_eq!(a.lookup_name("web").await.unwrap(), Some(addr));

        // Enforce: the founder-owned, founder-authored name still resolves.
        a.set_validation_mode(ValidationMode::Enforce);
        assert_eq!(
            a.lookup_name("web").await.unwrap(),
            Some(addr),
            "enforce must keep a legitimately-owned MagicDNS name"
        );

        // A member B forges name "evil" → A's addr from B's own author (a spoof:
        // B doesn't own addr). Under enforce it must not resolve.
        let ticket = a.write_ticket().await.unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let b = NetDoc::spawn(test_endpoint().await, dir_b.path(), Bootstrap::Import(Box::new(ticket)))
            .await
            .expect("spawn B");
        b.register_name("evil", addr).await.unwrap();
        // Wait for B's spoof to replicate to A.
        let mut replicated = false;
        for _ in 0..150 {
            // Read in Observe to confirm arrival (author check off).
            a.set_validation_mode(ValidationMode::Observe);
            if a.lookup_name("evil").await.unwrap() == Some(addr) {
                replicated = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        assert!(replicated, "B's spoofed name did not replicate within 10s (test setup)");
        a.set_validation_mode(ValidationMode::Enforce);
        assert_eq!(
            a.lookup_name("evil").await.unwrap(),
            None,
            "enforce must drop a MagicDNS name bound by a non-owner (spoof)"
        );
    }

    /// Per-member self-doc round-trip: a member's self-state, written to its own
    /// (member-only-writable) self-doc, is importable + readable by the founder
    /// via the admin-recorded `peer/N.self_doc` read ticket — the core C1
    /// write-isolation mechanism.
    #[tokio::test]
    async fn member_self_doc_roundtrips() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        a.record_founder_anchor(None);

        let ticket = a.write_ticket().await.unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let b = NetDoc::spawn(test_endpoint().await, dir_b.path(), Bootstrap::Import(Box::new(ticket)))
            .await
            .expect("spawn B");
        let b_id = b.endpoint.id().to_string();

        // A admits B; B publishes a vpn endpoint to its OWN self-doc (dual-write).
        a.put_peer(&sample_peer(&b_id, "B")).await.unwrap();
        let addr: std::net::Ipv4Addr = "100.64.5.5".parse().unwrap();
        b.register_vpn_endpoint(addr).await.unwrap();

        // B announces its self-doc read ticket → A records peer/B.self_doc.
        let b_self_ticket = b.self_doc_read_ticket().await.unwrap();
        assert!(
            a.record_peer_self_doc(&b_id, &b_self_ticket).await.unwrap(),
            "trust anchor must record an admitted member's self-doc ticket"
        );
        assert!(
            a.record_peer_self_doc(&b_id, &b_self_ticket).await.unwrap(),
            "record_peer_self_doc must be idempotent"
        );

        // A imports B's self-doc on demand and reads B's vpn/ entry FROM IT.
        let bdoc = a.member_self_doc(&b_id).await.expect("import B's self-doc");
        let key = format!("{KEY_VPN_PREFIX}{addr}");
        let mut found = false;
        for _ in 0..150 {
            if let Ok(Some(entry)) = bdoc
                .get_one(Query::single_latest_per_key().key_exact(key.as_bytes()).build())
                .await
                && entry.content_len() > 0
            {
                found = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        assert!(found, "B's vpn/ entry was not readable via its self-doc on A");

        // A malformed self-doc ticket is rejected.
        assert!(a.record_peer_self_doc(&b_id, "not-a-ticket").await.is_err());
    }

    /// Only the trust anchor records bindings, and only for admitted members.
    #[cfg(unix)]
    #[tokio::test]
    async fn record_peer_author_guards() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        // No founder anchor yet → not the trust anchor → no-op.
        assert!(!a.record_peer_author("nodeZZZZ", &a.author_hex()).await.unwrap());
        a.record_founder_anchor(None);
        // Trust anchor, but the node was never admitted → still no-op (never mints membership).
        assert!(!a.record_peer_author("nodeZZZZ", &a.author_hex()).await.unwrap());
        // Malformed author is rejected outright.
        a.put_peer(&sample_peer("nodeZZZZ", "Z")).await.unwrap();
        assert!(a.record_peer_author("nodeZZZZ", "not-hex").await.is_err());
    }

    #[tokio::test]
    async fn federation_replicates_vpn_registration() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        let addr: std::net::Ipv4Addr = "100.64.1.2".parse().unwrap();
        a.register_vpn_endpoint(addr).await.unwrap();
        let ticket = a.write_ticket().await.unwrap();

        let dir_b = tempfile::tempdir().unwrap();
        let b = NetDoc::spawn(
            test_endpoint().await,
            dir_b.path(),
            Bootstrap::Import(Box::new(ticket)),
        )
        .await
        .expect("spawn B");

        // Poll for replication (gossip + set reconciliation over loopback).
        for _ in 0..150 {
            if let Ok(Some((pubkey, _))) = b.lookup_vpn_endpoint(addr).await {
                assert_eq!(pubkey, a.endpoint.id());
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        panic!("vpn registration did not replicate A -> B within 10s");
    }
}
