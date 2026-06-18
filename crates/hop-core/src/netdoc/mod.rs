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
/// Subnet/exit routes advertised by gateway nodes (Tier 1 LAN bridging):
/// `route/<node_id_hex>/<cidr>` (slash in the CIDR encoded as `-`).
const KEY_ROUTE_PREFIX: &str = "route/";

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

fn default_true() -> bool {
    true
}

/// Kind of advertised route (Tier 1 LAN bridging).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteKind {
    /// A specific LAN CIDR (or `/32` device) the gateway bridges onto its
    /// physical network.
    Subnet,
    /// The default route (`0.0.0.0/0`) — the gateway acts as an internet exit
    /// node.
    Exit,
}

/// A subnet/exit route advertised by a gateway node. Stored in the gateway's
/// self-doc under `route/<node_id>/<cidr>`; the rest of the warren reads it to
/// decide what to tunnel through that gateway. Inert until a peer *accepts* the
/// route and the gateway is set up to forward — advertising alone changes
/// nothing on the data plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteAdvert {
    /// Advertised CIDR in canonical form, e.g. `192.168.1.0/24` or `0.0.0.0/0`.
    pub cidr: String,
    /// Tags gating reach to this route (Cedar resource tags). Empty = inherit
    /// the gateway node's own host tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether the gateway SNATs (masquerades) forwarded traffic to its LAN IP.
    /// Default true: replies return to the gateway with zero changes on the
    /// target LAN. `false` preserves the client's source IP but requires return
    /// routes on the target side (power-user / site-to-site).
    #[serde(default = "default_true")]
    pub snat: bool,
    /// Subnet vs. exit-node.
    pub kind: RouteKind,
    /// Epoch-seconds when advertised (audit/debug).
    #[serde(default)]
    pub advertised_at: String,
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

/// Read the persisted warren namespace from a host config dir's `netdoc.json`,
/// returning its canonical string form, or `None` if this host isn't on a
/// warren (or the file is unreadable).
///
/// The namespace is stored as a `NamespaceId`, which serde encodes as a JSON
/// byte array — not a string. Callers must deserialize the typed struct;
/// pulling `["namespace"].as_str()` off the raw JSON always yields `None`.
pub fn read_namespace(config_dir: &Path) -> Option<String> {
    std::fs::read_to_string(config_dir.join("netdoc.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<NetDocMeta>(&s).ok())
        .map(|meta| meta.namespace.to_string())
}

/// Extract the namespace id a warren ticket points at, *without* joining or
/// importing it. Lets the consume path detect a multi-warren conflict in the
/// unprivileged user context before any daemon restart.
pub fn namespace_of_ticket(ticket: &str) -> Result<String> {
    let t: DocTicket = ticket.trim().parse().context("invalid warren ticket")?;
    Ok(t.capability.id().to_string())
}

/// How consuming a warren ticket relates to the host's current warren.
#[derive(Debug, PartialEq, Eq)]
pub enum WarrenConflict {
    /// Not on any warren yet — joining is a clean first-run.
    None,
    /// The incoming warren is the one we're already on — idempotent, no prompt.
    Same,
    /// Already on a *different* warren — the caller must resolve the conflict
    /// (replace / merge / multi-home / abort).
    Conflict { existing: String },
}

/// Classify whether consuming the warren identified by `incoming_ns` conflicts
/// with the host's currently-joined warren (read from `netdoc.json`).
pub fn classify_warren_conflict(config_dir: &Path, incoming_ns: &str) -> WarrenConflict {
    match read_namespace(config_dir) {
        None => WarrenConflict::None,
        Some(existing) if existing == incoming_ns => WarrenConflict::Same,
        Some(existing) => WarrenConflict::Conflict { existing },
    }
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
    /// isolated from other members. Created **lazily** on first self-state write
    /// or read-ticket request, so a pure client / non-VPN node never mints one
    /// (and tests that don't use self-state pay no gossip overhead).
    self_doc: tokio::sync::RwLock<Option<Doc>>,
    /// The self-doc namespace id, persisted across restarts (`None` until the
    /// self-doc is first created).
    self_ns: std::sync::Mutex<Option<NamespaceId>>,
    /// Path to the persisted `NetDocMeta`, so lazy self-doc creation can record
    /// its namespace. `None` for test/`spawn` instances (no persistence).
    meta_path: Option<std::path::PathBuf>,
    /// Lazily-imported, read-only member self-docs keyed by node_id (lazy/on-
    /// demand sync). Populated by `member_self_doc` on first reach; the cached
    /// value is `(doc, owner endpoint addrs)` so a keepalive can actively
    /// re-sync each (an opened-but-not-syncing self-doc otherwise goes stale).
    member_docs: tokio::sync::RwLock<std::collections::HashMap<String, (Doc, Vec<EndpointAddr>)>>,
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
    /// Live inbound hop/vpn/1 connections (newest per peer), shared with the
    /// outbound forwarder so replies ride a fresh connection after a peer
    /// reboot instead of a silently-dead cached dial.
    #[cfg(unix)]
    vpn_conns: crate::vpn::VpnConns,
    /// Per-peer last-inbound-datagram timestamps, shared with `VpnInbound` and
    /// every pump. The outbound forwarder uses it to detect a silently-dead
    /// pooled connection (still `Ok` on send, but no replies) and re-dial.
    #[cfg(unix)]
    vpn_last_rx: crate::vpn::VpnLastRx,
    /// Gateway-advertised CIDRs (Tier 1 LAN bridging), shared with the VPN
    /// inbound pump so a datagram for an advertised subnet is forwarded (the
    /// kernel NATs it onto the LAN) instead of dropped as "not for our vIP".
    /// Filled by `set_gateway_cidrs` after the daemon reads `routes.json`; empty
    /// for a non-gateway node.
    #[cfg(unix)]
    vpn_gateway_cidrs: crate::vpn::GatewayCidrs,
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

        #[cfg(unix)]
        let vpn_tun: crate::vpn::TunSlot = std::sync::Arc::new(tokio::sync::RwLock::new(None));
        #[cfg(unix)]
        let vpn_peer_ips: crate::vpn::VpnPeerIps =
            std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
        #[cfg(unix)]
        let vpn_local_ip: crate::vpn::VpnLocalIp = std::sync::Arc::new(tokio::sync::RwLock::new(None));
        #[cfg(unix)]
        let vpn_refresh: crate::vpn::VpnRefresh = std::sync::Arc::new(tokio::sync::Notify::new());
        #[cfg(unix)]
        let vpn_conns: crate::vpn::VpnConns =
            std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
        #[cfg(unix)]
        let vpn_last_rx: crate::vpn::VpnLastRx =
            std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));

        let mut builder = Router::builder(endpoint.clone())
            .accept(iroh_docs::ALPN, docs.clone())
            .accept(iroh_gossip::ALPN, gossip.clone())
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&blobs, None));
        // The VPN inbound handler is always registered so peers can establish the
        // hop/vpn/1 path, but it only forwards packets once the TUN slot is set
        // (i.e. the VPN is explicitly enabled). Off by default → no-op. It
        // authenticates ingress against the shared peer-IP map (security-audit C2).
        #[cfg(unix)]
        let vpn_gateway_cidrs: crate::vpn::GatewayCidrs =
            std::sync::Arc::new(std::sync::RwLock::new(Vec::new()));
        #[cfg(unix)]
        {
            builder = builder.accept(
                crate::vpn::VPN_ALPN,
                crate::vpn::VpnInbound::new(
                    vpn_tun.clone(),
                    vpn_peer_ips.clone(),
                    vpn_local_ip.clone(),
                    vpn_refresh.clone(),
                    vpn_conns.clone(),
                    vpn_last_rx.clone(),
                    vpn_gateway_cidrs.clone(),
                ),
            );
        }
        let router = builder.spawn();

        Ok(Self {
            _router: router,
            fs_store,
            docs,
            doc,
            self_doc: tokio::sync::RwLock::new(None),
            self_ns: std::sync::Mutex::new(self_ns),
            meta_path: None,
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
            #[cfg(unix)]
            vpn_conns,
            #[cfg(unix)]
            vpn_last_rx,
            #[cfg(unix)]
            vpn_gateway_cidrs,
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
                    // Opening the persisted namespace failed. NEVER fall back to
                    // Bootstrap::Create here: that silently replaces the warren
                    // with a brand-new EMPTY namespace, orphaning this node (lost
                    // peer roster → vIP→owner resolves to nothing → VPN drops),
                    // which is the "VPN broke after an upgrade/restart" footgun.
                    // Instead re-import the SAME warren's join ticket to re-sync
                    // it; if we have no ticket, FAIL loudly so the node keeps its
                    // place in the warren and a later restart / re-join recovers
                    // it — rather than masquerading as joined while alone.
                    match join {
                        Some(ticket) => {
                            tracing::warn!(
                                "netdoc: saved namespace {} could not be opened ({e}); re-importing its join ticket to re-sync the SAME warren",
                                meta.namespace
                            );
                            (
                                Self::spawn_inner(endpoint, store_dir, Bootstrap::Import(Box::new(ticket)), None).await?,
                                true,
                            )
                        }
                        None => anyhow::bail!(
                            "netdoc: saved namespace {} could not be opened ({e}) and no join ticket is available to re-sync it — refusing to create a fresh namespace (that would orphan this node from its warren). Re-join with the warren invite to recover.",
                            meta.namespace
                        ),
                    }
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
        // Remember where to persist meta so lazy self-doc creation can record its
        // namespace later.
        net.meta_path = Some(meta_path.to_path_buf());

        if created {
            net.persist_meta()?;
        }
        Ok((net, created))
    }

    /// Persist `NetDocMeta` (namespace + federation + self-doc namespace) to the
    /// meta path, if one is set (production). No-op for test instances.
    fn persist_meta(&self) -> Result<()> {
        let Some(meta_path) = &self.meta_path else { return Ok(()) };
        let meta = NetDocMeta {
            namespace: self.namespace,
            federated: self.federated,
            self_namespace: *self.self_ns.lock().unwrap(),
        };
        let json = serde_json::to_string_pretty(&meta).context("serializing netdoc meta")?;
        std::fs::write(meta_path, json)
            .with_context(|| format!("writing netdoc meta to {}", meta_path.display()))?;
        Ok(())
    }

    /// This node's own self-doc, created (or reopened) **lazily** on first use.
    /// Creating a fresh one persists its namespace to meta. The write key never
    /// leaves this node.
    async fn self_doc(&self) -> Result<Doc> {
        if let Some(d) = self.self_doc.read().await.clone() {
            return Ok(d);
        }
        let mut guard = self.self_doc.write().await;
        if let Some(d) = guard.clone() {
            return Ok(d); // raced
        }
        let existing_ns = *self.self_ns.lock().unwrap();
        let doc = match existing_ns {
            Some(id) => self
                .docs
                .open(id)
                .await
                .context("opening self-doc")?
                .with_context(|| format!("self-doc namespace {id} not found"))?,
            None => {
                let d = self.docs.create().await.context("creating self-doc")?;
                *self.self_ns.lock().unwrap() = Some(d.id());
                if let Err(e) = self.persist_meta() {
                    tracing::warn!("netdoc: persisting self-doc namespace failed: {e:#}");
                }
                d
            }
        };
        *guard = Some(doc.clone());
        Ok(doc)
    }

    /// Admit a member into the warren directory: the trust anchor allocates its
    /// vIP once and records it on the peer entry (`peer/N.vip` — the admin-owned
    /// addr→owner authority readers trust, #3b), then writes the entry. The
    /// claim probes + resolves collisions in the shared `ip/` table; members
    /// never allocate. Best-effort — a failed claim never blocks admission
    /// (readers fall back to the author-validated `ip/` table). Used by BOTH
    /// admission paths: invite redemption (auth) and reconcile.
    pub async fn admit_peer(&self, peer: &Peer) -> Result<()> {
        let mut p = peer.clone();
        if p.vip.is_none() && self.is_trust_anchor() {
            match self.claim_virtual_ip(&p.node_id).await {
                Ok(addr) => p.vip = Some(addr.to_string()),
                Err(e) => tracing::warn!(
                    "netdoc #3b: vIP claim for {} failed: {e:#}",
                    &p.node_id[..8.min(p.node_id.len())]
                ),
            }
        }
        self.put_peer(&p).await
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
                self.admit_peer(p).await?;
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
        let mut peers: Vec<EndpointAddr> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Primary source (#3b): each member's self-doc ticket (recorded in the
        // admin doc, persisted locally) embeds that member's netdoc endpoint
        // address. The shared `vpn/` table no longer carries endpoints (they
        // live in per-member self-docs), so membership is the peer source.
        for peer in self.list_peers().await.unwrap_or_default() {
            let Some(ticket) = peer.self_doc.as_deref().and_then(|s| s.parse::<DocTicket>().ok()) else {
                continue;
            };
            for addr in ticket.nodes {
                if addr.id != self_id && seen.insert(addr.id) {
                    peers.push(addr);
                }
            }
        }

        // Legacy source: the shared `vpn/` table (pre-self-doc members).
        let query = Query::key_prefix(KEY_VPN_PREFIX.as_bytes()).build();
        let stream = self.doc.get_many(query).await.context("get_many vpn")?;
        let mut stream = std::pin::pin!(stream);
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
                // Keep imported member self-docs syncing too (#3b).
                me.resync_member_self_docs().await;
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
                // Fast re-sync of imported member self-docs so the data plane
                // converges in seconds (discovery resolves a stale ticket addr).
                me.resync_member_self_docs().await;
            }
        });
    }

    // ── VPN endpoint registry (Phase 3) ──────────────────────────────────

    /// Publish that this host's virtual `addr` is reachable for VPN traffic at
    /// this netdoc endpoint. Value: `"<endpoint_id_hex> <relay_url?>"`.
    /// This node's own VPN endpoint, as the static `"<endpoint_id> <relay>"`
    /// string written to `vpn/<addr>` and recorded in `peer/N.vpn_endpoint`. Both
    /// halves are stable (the netdoc endpoint id is derived from the persisted
    /// host key; the relay is configured), so the value never changes once the
    /// relay is up — which is what lets an admin record it once with no online
    /// coupling.
    pub fn own_vpn_endpoint_value(&self) -> String {
        let relay = crate::net::host_relay_url(&self.endpoint)
            .map(|u| u.to_string())
            .unwrap_or_default();
        format!("{} {relay}", self.endpoint.id())
    }

    pub async fn register_vpn_endpoint(&self, addr: std::net::Ipv4Addr) -> Result<()> {
        let value = self.own_vpn_endpoint_value();
        let key = format!("{KEY_VPN_PREFIX}{addr}");
        // #3b isolation: the endpoint lives ONLY in this node's self-doc — no
        // shared-doc copy for any other member to forge. Readers resolve it from
        // the owner's self-doc keyed by the admin-allocated peer/N.vip; imported
        // member self-docs are actively kept in sync (member_self_doc start_sync
        // + the resync keepalives).
        self.self_doc()
            .await?
            .set_bytes(self.author, key.into_bytes(), value.into_bytes())
            .await
            .context("registering vpn endpoint")?;
        Ok(())
    }

    /// The node that owns `addr`: primarily the admin-allocated `peer/N.vip`
    /// authority (admin-owned + validated under enforce, so a member can't forge
    /// ownership of another's addr); falling back to the shared `ip/` allocation
    /// table for legacy members with no `vip` — honored only when the claim is
    /// authored by that node's vouched author (same rule as
    /// `refresh_vpn_peer_ips`, so the fallback can't be forged either).
    async fn vip_owner(&self, addr: std::net::Ipv4Addr) -> Option<String> {
        let target = addr.to_string();
        if let Some(p) = self
            .list_peers()
            .await
            .ok()?
            .into_iter()
            .find(|p| p.vip.as_deref() == Some(target.as_str()))
        {
            return Some(p.node_id);
        }
        // Legacy fallback: the self-claimed `ip/` table, author-validated.
        let key = format!("{KEY_IP_PREFIX}{target}");
        let query = Query::single_latest_per_key().key_exact(key.as_bytes()).build();
        let entry = self.doc.get_one(query).await.ok().flatten()?;
        if entry.content_len() == 0 {
            return None;
        }
        let bytes = self.fs_store.get_bytes(entry.content_hash()).await.ok()?;
        let node = String::from_utf8_lossy(&bytes).trim().to_string();
        let bindings = self.vouched_authors().await;
        // Self-claim or vouched-admin allocation, same rule as refresh.
        if self_entry_author_ok(Some(&node), &entry.author(), &bindings, self.validation_mode())
            || self.is_admin_author(&entry.author())
        {
            Some(node)
        } else {
            tracing::debug!("netdoc: ip/{target} fallback claim rejected (author ≠ owner binding)");
            None
        }
    }

    /// Resolve a virtual `addr` to the VPN endpoint serving it. #3b: prefer the
    /// owning member's isolated self-doc (keyed by the admin-allocated
    /// `peer/N.vip`); fall back to the shared `vpn/` table for legacy members.
    pub async fn lookup_vpn_endpoint(
        &self,
        addr: std::net::Ipv4Addr,
    ) -> Result<Option<(iroh::PublicKey, Option<iroh::RelayUrl>)>> {
        let key = format!("{KEY_VPN_PREFIX}{addr}");
        let mk_query = || Query::single_latest_per_key().key_exact(key.as_bytes()).build();

        // Who owns this vIP? Validated (admin-allocated peer.vip / vouched ip/).
        // Computed once, reused by the self-doc lookup and the node-id fallback.
        let owner = self.vip_owner(addr).await;

        // Preferred: the owner's endpoint recorded in the admin doc roster
        // (`peer/N.vpn_endpoint`). Admin-vouched (the peer entry is admin-authored,
        // rejected otherwise under enforce) and replicated on the one document
        // every node reliably syncs — so the data plane no longer depends on the
        // owner's per-member self-doc namespace having converged. The value is
        // static, so this is always current once recorded.
        if let Some(ref owner) = owner
            && let Ok(Some(peer)) = self.get_peer(owner).await
            && let Some(val) = peer.vpn_endpoint.as_deref()
            && let Some(v) = parse_vpn_endpoint_value(val.as_bytes())
        {
            tracing::debug!("netdoc egress: {addr} resolved via roster vpn_endpoint");
            return Ok(Some(v));
        }

        // Fallback: the addr owner's self-doc (the isolated endpoint source) — for
        // members that announced a self-doc but not yet a roster `vpn_endpoint`.
        if let Some(ref owner) = owner
            && let Some(sd) = self.member_self_doc(owner).await
            && let Ok(Some(entry)) = sd.get_one(mk_query()).await
            && entry.content_len() > 0
            && let Ok(bytes) = self.fs_store.get_bytes(entry.content_hash()).await
            && let Some(v) = parse_vpn_endpoint_value(&bytes)
        {
            tracing::debug!("netdoc egress: {addr} resolved via owner self-doc");
            return Ok(Some(v));
        }

        // Fallback 1: the shared `vpn/` table (legacy / self-doc not yet imported).
        // Best-effort: a doc read error or a not-yet-synced blob must fall THROUGH
        // to the node-id fallback below, never abort the whole lookup (which would
        // black-hole egress that the node-id fallback could have resolved).
        if let Ok(Some(entry)) = self.doc.get_one(mk_query()).await
            && entry.content_len() > 0
            && let Ok(bytes) = self.fs_store.get_bytes(entry.content_hash()).await
            && let Some(v) = parse_vpn_endpoint_value(&bytes)
        {
            tracing::debug!("netdoc egress: {addr} resolved via shared fallback");
            return Ok(Some(v));
        }

        // Fallback 2: the vIP OWNER's node-id alone. We already know who owns this
        // vIP, and that node-id + the warren relay is everything connect_to_host
        // needs to dial the VPN ALPN — exactly what a self-doc / vpn entry yields
        // (both resolve to just `(pubkey, relay)`). A member on an older build
        // that publishes neither a self-doc nor a shared `vpn/` entry is still
        // reachable by node-id, so don't black-hole its traffic over a doc-sync
        // gap. The owner is author-validated, so this dials the legitimate owner.
        if let Some(owner) = owner
            && let Ok(pubkey) = owner.parse::<iroh::PublicKey>()
        {
            let relay = crate::net::HOP_RELAY_URL.parse().ok();
            tracing::debug!("netdoc egress: {addr} resolved via owner node-id fallback");
            return Ok(Some((pubkey, relay)));
        }

        tracing::debug!("netdoc egress: {addr} UNRESOLVED (no self-doc, no shared entry, no owner)");
        Ok(None)
    }

    /// Resolve a **gateway node's** VPN endpoint by node-id, for routing to a
    /// gateway (which, unlike a member vIP, isn't itself the packet's
    /// destination). Mirrors `lookup_vpn_endpoint`'s roster-then-node-id path.
    async fn lookup_endpoint_for_node(
        &self,
        node_id: &str,
    ) -> Option<(iroh::PublicKey, Option<iroh::RelayUrl>)> {
        if let Ok(Some(peer)) = self.get_peer(node_id).await
            && let Some(val) = peer.vpn_endpoint.as_deref()
            && let Some(v) = parse_vpn_endpoint_value(val.as_bytes())
        {
            return Some(v);
        }
        // Node-id + warren relay is enough to dial the VPN ALPN.
        if let Ok(pubkey) = node_id.parse::<iroh::PublicKey>() {
            return Some((pubkey, crate::net::HOP_RELAY_URL.parse().ok()));
        }
        None
    }

    /// Set the gateway-advertised CIDRs this node forwards (Tier 1 LAN bridging),
    /// shared with the VPN inbound pump. Called by the daemon after reading
    /// `routes.json`.
    #[cfg(unix)]
    pub fn set_gateway_routes(&self, routes: Vec<(String, Vec<String>)>) {
        if let Ok(mut g) = self.vpn_gateway_cidrs.write() {
            *g = routes
                .into_iter()
                .map(|(cidr, tags)| crate::vpn::GatewayRouteEntry {
                    cidr,
                    tags,
                    allowed_vips: Default::default(),
                })
                .collect();
        }
    }

    /// Bring up this node as a gateway for `routes` (Tier 1 LAN bridging): publish
    /// each route to the warren, register the CIDRs with the inbound pump, and
    /// program the kernel (ip_forward + nftables NAT) using the live TUN. Called
    /// by the daemon after `enable_vpn` when `routes.json` is non-empty. Inert
    /// (returns immediately) for an empty route set. Best-effort: a failed
    /// advertise/setup logs and continues — it never blocks serving.
    #[cfg(unix)]
    pub async fn setup_gateway_routes(&self, node_id: &str, routes: &[crate::fleet::RouteConfig]) {
        if routes.is_empty() {
            return;
        }
        let mut cidrs = Vec::new();
        let mut gw_routes = Vec::new();
        for rc in routes {
            let cidr = crate::fleet::RoutesStore::effective_cidr(rc);
            let advert = RouteAdvert {
                cidr: cidr.clone(),
                tags: rc.tags.clone(),
                snat: rc.snat,
                kind: if rc.exit { RouteKind::Exit } else { RouteKind::Subnet },
                advertised_at: now_timestamp(),
            };
            if let Err(e) = self.advertise_route(node_id, &advert).await {
                tracing::warn!("vpn gateway: advertising {cidr} failed (continuing): {e:#}");
                continue;
            }
            cidrs.push((cidr.clone(), rc.tags.clone()));
            gw_routes.push(crate::vpn::gateway::GatewayRoute { cidr, snat: rc.snat });
        }
        self.set_gateway_routes(cidrs.clone());
        let tun_name = {
            use tun::AbstractDevice;
            self.vpn_tun.read().await.as_ref().and_then(|d| d.tun_name().ok())
        };
        match tun_name {
            Some(_tun) => match crate::privsep::setup_gateway(&gw_routes) {
                Ok(()) => tracing::info!(
                    "vpn gateway: forwarding {} route(s) live: {:?}",
                    cidrs.len(),
                    cidrs
                ),
                Err(e) => tracing::warn!(
                    "vpn gateway: advertised {:?} but kernel forwarding setup failed \
                     (continuing): {e:#}",
                    cidrs
                ),
            },
            None => tracing::warn!(
                "vpn gateway: TUN not up — advertised {:?} but skipped kernel forwarding",
                cidrs
            ),
        }
    }

    /// Build the client-side **accepted-route** table — every warren-advertised
    /// subnet/exit route (except our own) resolved to its gateway's endpoint, as
    /// `(cidr, gateway_pubkey, relay)`. The forwarder caches this and matches a
    /// non-vIP destination against it (longest-prefix) to route via the gateway.
    ///
    /// Route acceptance is **opt-in** (`HOP_ACCEPT_ROUTES`) because installing a
    /// route mutates the host's routing table — off by default, like Tailscale's
    /// `--accept-routes`.
    ///
    /// WIP (plan P1 slice 4): not yet reach-gated per role — any accepted route
    /// is reachable by this node. Per-role gating via Cedar route resources, plus
    /// the gateway-side authorization check, is the security follow-up.
    #[cfg(unix)]
    async fn accepted_route_endpoints(
        &self,
    ) -> Vec<(String, iroh::PublicKey, Option<iroh::RelayUrl>)> {
        let accept_subnets = std::env::var_os("HOP_ACCEPT_ROUTES").is_some();
        // Exit-node use is a SEPARATE explicit opt-in (it routes ALL traffic, not a
        // specific subnet): `HOP_EXIT_NODE` = a gateway node-id prefix, or `auto`
        // for the first advertised exit. Subnet acceptance never implies it.
        let exit_pref = std::env::var("HOP_EXIT_NODE").ok().filter(|s| !s.is_empty());
        if !accept_subnets && exit_pref.is_none() {
            return Vec::new();
        }
        let me = self.endpoint.id().to_string();
        let mut out = Vec::new();
        let mut took_exit = false;
        for (gw, advert) in self.list_routes().await.unwrap_or_default() {
            if gw == me {
                continue; // don't route our own LAN/exit back through ourselves
            }
            let is_exit = advert.cidr == "0.0.0.0/0";
            let accept = if is_exit {
                // One exit at a time; it must match the configured gateway.
                !took_exit
                    && match &exit_pref {
                        Some(p) => p == "auto" || gw.starts_with(p.as_str()),
                        None => false,
                    }
            } else {
                accept_subnets
            };
            if !accept {
                continue;
            }
            if let Some((pk, relay)) = self.lookup_endpoint_for_node(&gw).await {
                if is_exit {
                    took_exit = true;
                }
                out.push((advert.cidr, pk, relay));
            }
        }
        out
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
                // Valid if claimed by the owner itself OR allocated by a vouched
                // admin (the trust anchor claims on behalf at admission — #3b).
                if self_entry_author_ok(Some(&node), &entry.author(), &bindings, mode)
                    || self.is_admin_author(&entry.author())
                {
                    ip_owner.insert(addr, node);
                } else {
                    tracing::warn!("netdoc C1: ip/{addr} author ≠ owner binding — REJECTED (forged vIP claim)");
                }
            }
        }

        // #3b: the admin-allocated `peer/N.vip` is the AUTHORITATIVE addr→owner
        // map — it's admin-owned (validated under enforce, so a member can't
        // forge another's), so it overrides the shared `ip/` table (which remains
        // the fallback for legacy members that have no `vip` yet).
        // Also collect each member's admin-vouched roster endpoint
        // (`peer/N.vpn_endpoint`) keyed by the addr it owns — the reliable ingress
        // source that doesn't depend on the member's self-doc namespace syncing.
        let mut roster_endpoints: Vec<(String, std::net::Ipv4Addr)> = Vec::new();
        // A roster READ failure (doc-level, not a missing blob — those are skipped
        // per-entry in `list_prefix`) must keep the last-known-good ingress map, not
        // rebuild from an empty roster and overwrite working routes. Bail; the next
        // tick retries.
        let peers = match self.list_peers().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    "netdoc refresh: list_peers failed ({e:#}); keeping last-known-good vpn_peer_ips"
                );
                return;
            }
        };
        for peer in peers {
            if let Some(vip) = peer.vip.as_deref().and_then(|s| s.parse::<std::net::Ipv4Addr>().ok()) {
                ip_owner.insert(vip, peer.node_id.clone());
                if let Some(val) = peer.vpn_endpoint.as_deref()
                    && let Some(id) = val.split_whitespace().next()
                {
                    roster_endpoints.push((id.to_string(), vip));
                }
            }
        }

        // vpn/ table → endpoint-id → vIP, each validated against the owner's
        // vouched author. Seed the map with the roster endpoints first (the base
        // the shared `vpn/` scan and self-doc override may refine).
        let Ok(stream) = self.doc.get_many(Query::key_prefix(KEY_VPN_PREFIX.as_bytes()).build()).await else { return };
        let mut stream = std::pin::pin!(stream);
        let mut map: HashMap<String, std::net::Ipv4Addr> =
            roster_endpoints.into_iter().collect();
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

        // Per-member self-doc override (C1 write-isolation): take each owner's
        // endpoint from its OWN isolated self-doc, keyed by the addr it holds per
        // the validated `ip/` table above. A member can only set its own
        // endpoint for the addr it owns — it can't forge another's, since the
        // addr→owner binding is the validated `ip/` table, not the self-doc.
        // This is what carries the data plane once the shared-doc endpoint write
        // is dropped (it is, in `register_vpn_endpoint`); the shared scan above
        // still serves not-yet-upgraded members.
        let local_ip = *self.vpn_local_ip.read().await;
        for (addr, owner) in ip_owner.iter() {
            let own = Some(*addr) == local_ip;
            let sd = if own {
                self.self_doc().await.ok() // our own addr → our own self-doc
            } else {
                self.member_self_doc(owner).await
            };
            let Some(sd) = sd else {
                tracing::debug!("netdoc refresh: vpn/{addr} owner {} — NO self-doc available", &owner[..8.min(owner.len())]);
                continue;
            };
            let key = format!("{KEY_VPN_PREFIX}{addr}");
            let q = Query::single_latest_per_key().key_exact(key.as_bytes()).build();
            let entry = match sd.get_one(q).await {
                Ok(Some(e)) if e.content_len() > 0 => e,
                Ok(_) => {
                    tracing::debug!("netdoc refresh: vpn/{addr} owner {} — self-doc open but NO entry yet (sync pending?)", &owner[..8.min(owner.len())]);
                    continue;
                }
                Err(e) => {
                    tracing::debug!("netdoc refresh: vpn/{addr} owner {} — self-doc read error: {e:#}", &owner[..8.min(owner.len())]);
                    continue;
                }
            };
            let Ok(bytes) = self.fs_store.get_bytes(entry.content_hash()).await else {
                tracing::debug!("netdoc refresh: vpn/{addr} owner {} — entry present but BLOB content missing", &owner[..8.min(owner.len())]);
                continue;
            };
            if let Some(id) = String::from_utf8_lossy(&bytes).split_whitespace().next() {
                // Replace any stale shared-doc endpoint for this addr, then bind ours.
                map.retain(|_, a| a != addr);
                map.insert(id.to_string(), *addr);
            }
        }

        tracing::debug!(
            "netdoc refresh: vpn_peer_ips = {:?} (ip_owner had {} addr(s))",
            map.iter().map(|(id, a)| format!("{}→{a}", &id[..10.min(id.len())])).collect::<Vec<_>>(),
            ip_owner.len()
        );
        // Never discard a working ingress map because this refresh came up empty —
        // that's almost always a transient sync gap (blob content not yet
        // re-fetched), not a genuine "zero peers". Keep last-known-good; Layer 2's
        // content re-fetch + the next refresh rebuild it. (A node that legitimately
        // drops to zero peers keeps a few stale endpoint→vIP entries, which is
        // harmless: a departed endpoint-id can no longer connect.)
        if map.is_empty() {
            let prev_len = self.vpn_peer_ips.read().await.len();
            if prev_len > 0 {
                tracing::warn!(
                    "netdoc refresh: computed empty vpn_peer_ips but {prev_len} route(s) known — \
                     keeping last-known-good (transient sync gap)"
                );
                return;
            }
        }
        *self.vpn_peer_ips.write().await = map;

        // Tier 1 LAN bridging: recompute per-route reach gates on the same tick.
        self.refresh_gateway_acl().await;
    }

    /// Recompute, for each locally-advertised **tagged** gateway route, the set of
    /// member vIPs whose role reaches it (the gateway-side authorization for Tier 1
    /// LAN bridging). Untagged routes stay open to any member. Cheap and off the
    /// per-packet path — the pump just does a set lookup. No tagged routes → no-op.
    async fn refresh_gateway_acl(&self) {
        // Snapshot (cidr, tags) without holding the std lock across `.await`.
        let snapshot: Vec<(String, Vec<String>)> = match self.vpn_gateway_cidrs.read() {
            Ok(rs) => rs.iter().map(|r| (r.cidr.clone(), r.tags.clone())).collect(),
            Err(_) => return,
        };
        if !snapshot.iter().any(|(_, t)| !t.is_empty()) {
            return;
        }
        let engine = self.reach_engine().await;
        let vips = self.list_virtual_ips().await.unwrap_or_default();
        let mut allow: std::collections::HashMap<String, std::collections::HashSet<std::net::Ipv4Addr>> =
            std::collections::HashMap::new();
        if let Some(eng) = engine {
            for (cidr, tags) in &snapshot {
                if tags.is_empty() {
                    continue;
                }
                let mut set = std::collections::HashSet::new();
                for (vip, node) in &vips {
                    if eng.reaches_tags(node, tags) {
                        set.insert(*vip);
                    }
                }
                allow.insert(cidr.clone(), set);
            }
        }
        if let Ok(mut routes) = self.vpn_gateway_cidrs.write() {
            for r in routes.iter_mut() {
                if let Some(set) = allow.remove(&r.cidr) {
                    r.allowed_vips = set;
                }
            }
        }
    }

    /// Layer 2 — active self-heal of missing blob content. iroh-docs downloads an
    /// entry's content only while reconciling a *changed* entry; if a download was
    /// interrupted (e.g. a connection churned mid-sync) the entry key is present
    /// but `get_bytes` returns `NotFound`, and plain re-sync never re-fetches it
    /// (no entry diff). This sweep finds such gaps in the roster prefixes and pulls
    /// the content from a current sync peer (who holds it).
    ///
    /// STRICTLY best-effort: every failure is logged and swallowed. It can only
    /// *add* missing content — never remove, deny, or block — so it can't regress
    /// the data plane beyond Layer 1's last-known-good behavior. A no-op (cheap)
    /// once everything is present.
    #[cfg(unix)]
    pub async fn ensure_content_synced(&self) {
        // Providers: the peers we're actively syncing the doc with — they hold the
        // content and the endpoint already knows how to reach them. None → nothing
        // to fetch from yet.
        let providers: Vec<iroh::PublicKey> = match self.doc.get_sync_peers().await {
            Ok(Some(peers)) => peers
                .iter()
                .filter_map(|b| iroh::PublicKey::from_bytes(b).ok())
                .collect(),
            _ => return,
        };
        if providers.is_empty() {
            return;
        }

        // Find roster entries whose content hasn't landed locally yet.
        let mut missing: std::collections::HashSet<iroh_blobs::Hash> = std::collections::HashSet::new();
        for prefix in [KEY_PEER_PREFIX, KEY_IP_PREFIX, KEY_VPN_PREFIX] {
            let Ok(stream) = self.doc.get_many(Query::key_prefix(prefix.as_bytes()).build()).await
            else {
                continue;
            };
            let mut stream = std::pin::pin!(stream);
            while let Some(Ok(entry)) = stream.next().await {
                if entry.content_len() == 0 {
                    continue; // tombstone — no content expected
                }
                let hash = entry.content_hash();
                if self.fs_store.get_bytes(hash).await.is_err() {
                    missing.insert(hash);
                }
            }
        }
        if missing.is_empty() {
            return;
        }

        tracing::warn!(
            "netdoc: {} roster blob(s) missing content locally — re-fetching from {} sync peer(s)",
            missing.len(),
            providers.len()
        );
        let downloader = iroh_blobs::api::downloader::Downloader::new(&self.fs_store, &self.endpoint);
        for hash in missing {
            let dl = downloader.download(
                hash,
                iroh_blobs::api::downloader::Shuffled::new(providers.clone()),
            );
            match tokio::time::timeout(std::time::Duration::from_secs(20), dl).await {
                Ok(Ok(())) => tracing::debug!("netdoc: re-fetched missing content {hash}"),
                Ok(Err(e)) => tracing::debug!("netdoc: content re-fetch for {hash} failed: {e:#}"),
                Err(_) => tracing::debug!("netdoc: content re-fetch for {hash} timed out"),
            }
        }
        // Freshly-fetched content is now readable — nudge a refresh to pick it up.
        self.vpn_refresh.notify_one();
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

    // ── Subnet routes (Tier 1 LAN bridging) ─────────────────────────────

    /// Advertise that `node_id` can route `advert.cidr` onto its physical LAN
    /// (or the default route, for an exit node). Written to this node's self-doc
    /// under `route/<node_id>/<cidr>`. Advertising is inert by itself — a peer
    /// must *accept* the route and the gateway must be set up to forward.
    pub async fn advertise_route(&self, node_id: &str, advert: &RouteAdvert) -> Result<()> {
        let key = format!("{KEY_ROUTE_PREFIX}{node_id}/{}", advert.cidr.replace('/', "-"));
        let value = serde_json::to_vec(advert).context("serializing route advert")?;
        self.put_self(&key, value).await.context("advertising route")?;
        self.invalidate_reach_cache().await;
        Ok(())
    }

    /// Withdraw a previously-advertised route (empty-value tombstone).
    pub async fn withdraw_route(&self, node_id: &str, cidr: &str) -> Result<()> {
        let key = format!("{KEY_ROUTE_PREFIX}{node_id}/{}", cidr.replace('/', "-"));
        self.put_self(&key, Vec::new()).await.context("withdrawing route")?;
        self.invalidate_reach_cache().await;
        Ok(())
    }

    /// All advertised routes across the warren as `(gateway_node_id, RouteAdvert)`.
    /// Reads the shared doc plus each imported member self-doc (a read-ticket
    /// member's routes live only in its self-doc), deduped by `(node, cidr)`.
    pub async fn list_routes(&self) -> Result<Vec<(String, RouteAdvert)>> {
        let member_docs: Vec<Doc> =
            self.member_docs.read().await.values().map(|(d, _)| d.clone()).collect();
        let mut out: Vec<(String, RouteAdvert)> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for doc in std::iter::once(&self.doc).chain(member_docs.iter()) {
            let query = Query::key_prefix(KEY_ROUTE_PREFIX.as_bytes()).build();
            let stream = doc.get_many(query).await.context("get_many route")?;
            let mut stream = std::pin::pin!(stream);
            while let Some(entry) = stream.next().await {
                let entry = entry.context("reading route entry")?;
                if entry.content_len() == 0 {
                    continue;
                }
                let key = String::from_utf8_lossy(entry.key()).into_owned();
                let Some(rest) = key.strip_prefix(KEY_ROUTE_PREFIX) else { continue };
                let Some((node_id, _cidr_key)) = rest.split_once('/') else { continue };
                let bytes = self.fs_store.get_bytes(entry.content_hash()).await?;
                let Ok(advert) = serde_json::from_slice::<RouteAdvert>(&bytes) else { continue };
                if seen.insert((node_id.to_string(), advert.cidr.clone())) {
                    out.push((node_id.to_string(), advert));
                }
            }
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
        // Each deny path logs WHY (debug) — the reach decision was previously a
        // silent drop, which made "I'm a member but can't reach anything"
        // impossible to diagnose without a code change.
        let ips = match self.list_virtual_ips().await {
            Ok(v) => v,
            Err(e) => {
                // Fail OPEN on a roster READ error (a doc-level failure — missing
                // blobs are skipped per-entry, not errors). Hard-denying all egress
                // over a transient read is the "dead until restart" footgun. Safe:
                // delivery is still gated by lookup_vpn_endpoint (an unknown vIP has
                // no endpoint → dropped there), so fail-open can't reach a
                // non-member. Kick a refresh and allow.
                tracing::warn!(
                    "reach ALLOW(read-error) {src_ip}->{dst_ip}: list_virtual_ips failed ({e:#}) — \
                     refreshing rather than blackholing"
                );
                self.vpn_refresh.notify_one();
                return true;
            }
        };
        let owner = |ip: std::net::Ipv4Addr| ips.iter().find(|(a, _)| *a == ip).map(|(_, n)| n.clone());
        let (Some(src_node), Some(dst_node)) = (owner(src_ip), owner(dst_ip)) else {
            // The ip/ ownership table lags peer/role sync (5s refresh tick). Hard-
            // denying here drops a legitimate member's packets during the
            // convergence window — the "member but can't reach" footgun, just
            // relocated to the resolution layer. Fail OPEN and kick a refresh
            // instead of blackholing: the endpoint-resolution step
            // (lookup_vpn_endpoint) still gates actual delivery, so an unknown
            // vIP has no endpoint and is dropped there — fail-open here can't
            // forward to a non-member, it only avoids dropping during sync lag.
            tracing::debug!(
                "reach ALLOW(sync) {src_ip}->{dst_ip}: vIP owner not resolved yet (src_known={}, \
                 dst_known={}) — refreshing rather than blackholing",
                owner(src_ip).is_some(),
                owner(dst_ip).is_some()
            );
            self.vpn_refresh.notify_one();
            return true;
        };
        // Cedar reach engine (cached); default-deny on any build failure.
        match self.reach_engine().await {
            Some(engine) => {
                // Egress trust: this check only runs on the SENDER (the sole caller
                // is the egress loop). If the local node isn't a known principal in
                // its own engine, it's a leaf member that doesn't hold the peer
                // roster — it CANNOT evaluate its own role, so a default-deny here
                // would silently strand every leaf (the deny-by-default footgun).
                // A node trusts its own egress onto the warren; reach restriction
                // stays enforceable on nodes that DO hold the roster (hosts/founders
                // evaluate their full membership normally). Mirrors the 0.6.74
                // "members reach the warren by default" posture.
                if !engine.knows_peer(&src_node) {
                    tracing::debug!(
                        "vpn egress: src {src_node} not a known principal locally (leaf member \
                         without roster) — allowing egress to {dst_node}"
                    );
                    return true;
                }
                let ok = engine.is_reach_allowed(&src_node, &dst_node, port);
                if !ok {
                    tracing::debug!(
                        "reach DENY {src_node} -> {dst_node}: role policy (the src role has no \
                         reach to the dst's tags — is the role defined + synced with reach?)"
                    );
                }
                ok
            }
            None => {
                tracing::debug!("reach DENY {src_node}->{dst_node}: reach engine unavailable (build failed)");
                false
            }
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
        // vIP acquisition (#3b): a federated member's vIP is allocated by the
        // admin at admission (`peer/N.vip`, with a matching `ip/` claim) — wait
        // briefly for it to replicate instead of self-claiming, since a
        // read-ticket member CANNOT write the shared `ip/` table. Falls back to
        // self-claiming (legacy write members). The founder claims directly.
        let addr = if self.federated {
            let mut found = None;
            for _ in 0..15 {
                if let Some(v) = self
                    .get_peer(host_node_id)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|p| p.vip.as_deref().and_then(|s| s.parse::<std::net::Ipv4Addr>().ok()))
                {
                    found = Some(v);
                    break;
                }
                if let Ok(Some(ip)) = self.get_virtual_ip(host_node_id).await {
                    found = Some(ip);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            match found {
                Some(a) => a,
                None => self.claim_virtual_ip(host_node_id).await?,
            }
        } else {
            self.claim_virtual_ip(host_node_id).await?
        };
        // In privsep-worker mode this requests the TUN fd from the root monitor;
        // otherwise it creates the device directly (non-privsep path).
        let tun = std::sync::Arc::new(crate::privsep::acquire_tun(addr).await?);
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
        // Layer 2: a slow content-heal sweep that re-fetches any roster blob whose
        // content didn't land (interrupted sync) so a member never stays
        // unreachable waiting for the next entry change or a restart. Best-effort
        // and a cheap no-op once everything is present.
        {
            let me = std::sync::Arc::clone(self);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    me.ensure_content_synced().await;
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
                    // An unauthenticated-ingress signal often means a peer's content
                    // hasn't synced — kick a content-heal so it converges now, not on
                    // the slow tick. Best-effort; no-op if nothing is missing.
                    me.ensure_content_synced().await;
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
                // The founder's display name is its bare hostname (same label
                // MagicDNS registers), not the literal "self" — otherwise every
                // *other* node's `hop fleet list` shows the founder as "self".
                // "Is this me?" is a node-id comparison the renderer does locally.
                name: crate::invite::system_hostname().unwrap_or_else(|| "self".to_string()),
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
                // The founder's admin-allocated vIP (its own claim, #3b).
                vip: Some(addr.to_string()),
                // The founder's own VPN endpoint in the roster, so peers resolve
                // it from the admin doc without importing the founder's self-doc.
                vpn_endpoint: Some(self.own_vpn_endpoint_value()),
                sandbox: crate::sandbox::SandboxPolicy::default(),
            };
            if let Err(e) = self.put_peer(&me).await {
                tracing::warn!("vpn: self-member registration failed: {e:#}");
            }
        }
        // Self-heal the founder's own roster entries on EVERY bringup. The block
        // above sets them only when the founder's peer entry is first created, so a
        // founder whose entry predates these fields (or whose self-doc ticket went
        // stale after a relay/address change) keeps an empty/old value forever —
        // and since the founder never announces (it's the trust anchor), nothing
        // else would ever record it, leaving its VPN endpoint unresolvable to every
        // peer. Heals BOTH `self_doc` (legacy resolution path) and the new
        // `vpn_endpoint` (the roster routing path). Idempotent: only writes on an
        // actual change.
        if !self.federated
            && let Ok(Some(mut me)) = self.get_peer(host_node_id).await
        {
            let mut changed = false;
            if let Ok(ticket) = self.self_doc_read_ticket().await
                && me.self_doc.as_deref() != Some(ticket.as_str())
            {
                me.self_doc = Some(ticket);
                changed = true;
            }
            let ep = self.own_vpn_endpoint_value();
            if me.vpn_endpoint.as_deref() != Some(ep.as_str()) {
                me.vpn_endpoint = Some(ep);
                changed = true;
            }
            if changed {
                if let Err(e) = self.put_peer(&me).await {
                    tracing::warn!("vpn: founder roster self-heal failed: {e:#}");
                } else {
                    tracing::info!("vpn: refreshed founder's own roster entry (self_doc + vpn_endpoint)");
                }
            }
        }
        let me = std::sync::Arc::clone(self);
        tokio::spawn(async move { me.vpn_outbound_loop(tun).await });

        // MagicDNS: register this host's name → virtual IP and serve `*.hop`
        // lookups on the virtual interface (split-DNS points `.hop` here).
        if let Ok(h) = hostname::get() {
            // Register the bare host label, stripping any DNS suffix the OS/DHCP
            // appended (e.g. macOS returns the FQDN `RexMundi.lan` on a home
            // network). MagicDNS strips the warren domain off a query and looks
            // up the remainder, so the registered key must be `rexmundi`, not
            // `rexmundi.lan`, for `RexMundi.hop` to resolve.
            let full = h.to_string_lossy().to_lowercase();
            let name = full.split('.').next().unwrap_or(&full);
            if !name.is_empty()
                && let Err(e) = self.register_name(name, addr).await
            {
                tracing::warn!("vpn: name registration failed: {e:#}");
            }
        }
        // MagicDNS binds on the vIP on Linux, but loopback on macOS (a p2p utun
        // can't deliver a query to its own vIP locally). The resolver is pointed
        // at the same address, so they always agree.
        let dns_bind = crate::vpn::magicdns_bind_addr(addr);
        let dns = std::sync::Arc::clone(self);
        tokio::spawn(async move { dns.vpn_dns_loop(dns_bind).await });

        // Automatic split-DNS: point the OS resolver for the warren domain at
        // this node's MagicDNS server so `<host>.<domain>` resolves with zero
        // manual setup. Privileged, so under privsep this routes through the
        // monitor; best-effort — failure only costs name resolution.
        if !crate::vpn::resolver::auto_resolver_disabled() {
            let domain = self.network_domain().await;
            if let Err(e) = crate::privsep::configure_resolver(&domain, dns_bind) {
                tracing::warn!(
                    "vpn: automatic DNS config failed ({e:#}); names won't resolve until you \
                     point `.{domain}` at {dns_bind}:53 manually"
                );
            }
        }

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
    ///
    /// Searches the main doc first (founder names + admin-mirrored member names),
    /// then each imported member self-doc — a **read-ticket member** can't write
    /// the main-doc mirror (`put_self`), so its `name/<host>` lives only in its
    /// self-doc. Self-doc coverage grows as the node syncs/routes to peers; a
    /// not-yet-imported member's name won't resolve until its self-doc lands.
    pub async fn lookup_name(&self, name: &str) -> Result<Option<std::net::Ipv4Addr>> {
        let q = name.to_lowercase();

        // Roster-first (reliable): the admin doc carries each peer's name AND its
        // admin-allocated vip — both admin-authored (validated under enforce, so a
        // member can't forge another's) and replicated on the one document every
        // node syncs. Resolve name→vip straight from the roster so MagicDNS doesn't
        // wait on the owner's per-member `name/` self-doc entry converging (the
        // same fragility the endpoint roster move fixed). Match the bare host label
        // the way `register_name` does (lowercased, DNS suffix stripped).
        for peer in self.list_peers().await.unwrap_or_default() {
            let label = peer.name.split('.').next().unwrap_or(&peer.name).to_lowercase();
            if label == q
                && let Some(vip) = peer.vip.as_deref().and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
            {
                tracing::debug!("netdoc: name {q} resolved via roster peer.name → {vip}");
                return Ok(Some(vip));
            }
        }

        let key = format!("name/{}", q);
        let mk_query = || Query::single_latest_per_key().key_exact(key.as_bytes()).build();

        // [main doc] then [each imported member self-doc].
        let member_docs: Vec<Doc> =
            self.member_docs.read().await.values().map(|(d, _)| d.clone()).collect();
        for doc in std::iter::once(&self.doc).chain(member_docs.iter()) {
            let Some(entry) = doc.get_one(mk_query()).await.context("get_one name")? else {
                continue;
            };
            if entry.content_len() == 0 {
                continue;
            }
            let bytes = self.fs_store.get_bytes(entry.content_hash()).await?;
            let Some(addr) =
                String::from_utf8_lossy(&bytes).trim().parse::<std::net::Ipv4Addr>().ok()
            else {
                continue;
            };
            if self.validation_mode() == ValidationMode::Enforce
                && !self.name_author_ok(addr, &entry.author()).await
            {
                tracing::warn!(
                    "netdoc C1: name/{} author ≠ owner binding — REJECTED (MagicDNS spoof attempt)",
                    name.to_lowercase()
                );
                continue;
            }
            return Ok(Some(addr));
        }
        Ok(None)
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
        // Under privsep-drop the worker is unprivileged and cannot bind :53, so
        // route through the monitor (root) which binds and passes back the socket
        // fd; non-privsep binds directly. See privsep::acquire_priv_port.
        let sock = match crate::privsep::acquire_priv_port(addr, 53).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("vpn: DNS bind on {addr}:53 failed ({e:#}); MagicDNS disabled");
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
        // Cached dials: connection + when we dialed it (for the post-dial grace).
        let mut conns: HashMap<iroh::PublicKey, (iroh::endpoint::Connection, std::time::Instant)> =
            HashMap::new();
        // Recovery thresholds. QUIC datagram sends return Ok even on a dead path,
        // so close_reason() never trips — a pooled connection is treated as usable
        // only if we've received a datagram from the peer within STALE_AFTER
        // (proves the path is live), or, for one we just dialed, within DIAL_GRACE
        // while the first reply is still in flight. Otherwise we re-dial. Both ends
        // run this, so a silently-dead path recovers on whichever side is sending.
        const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(20);
        // Cold-reconnect window: a freshly-dialed connection — especially a
        // relay-only path re-established with no founder online (the no-admin
        // case) — needs time to validate a path before the first keepalive/reply
        // arrives. Keep using it until then instead of redialing; redialing
        // mid-establishment was the reconnect storm that prevented any connection
        // from ever stabilizing.
        const DIAL_GRACE: std::time::Duration = std::time::Duration::from_secs(30);
        // App-level keepalive: every KEEPALIVE_INTERVAL send a heartbeat datagram
        // to each peer connection. Keeps the QUIC path validated/warm and the
        // remote's `last_rx` fresh, so a live-but-idle connection is never
        // mistaken for silently-dead and redialed (the original rationale for
        // multipath — a failover lands on an already-warm path). Both ends run
        // this, so the liveness signal stays bidirectional.
        const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
        let mut buf = vec![0u8; 65535];
        let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Tier 1 LAN bridging: accepted subnet/exit routes (cidr → gateway
        // endpoint), local to the forwarder like `conns` (no shared state). Empty
        // unless HOP_ACCEPT_ROUTES is set. Refreshed every ROUTE_REFRESH; each
        // accepted CIDR also gets a kernel route → TUN (collision-guarded).
        const ROUTE_REFRESH: std::time::Duration = std::time::Duration::from_secs(15);
        let tun_name = {
            use tun::AbstractDevice;
            tun.tun_name().unwrap_or_default()
        };
        let mut accepted_routes: Vec<(String, iroh::PublicKey, Option<iroh::RelayUrl>)> =
            self.accepted_route_endpoints().await;
        // Exit routes (0.0.0.0/0) install a split-default + relay handling; subnet
        // routes install the CIDR directly (collision-guarded).
        let install_route = |cidr: &str| {
            if cidr == "0.0.0.0/0" {
                let _ = crate::privsep::install_exit_route(&tun_name);
            } else {
                let _ = crate::privsep::install_client_route(cidr, &tun_name);
            }
        };
        let uninstall_route = |cidr: &str| {
            if cidr == "0.0.0.0/0" {
                crate::privsep::uninstall_exit_route(&tun_name);
            } else {
                crate::privsep::uninstall_client_route(cidr, &tun_name);
            }
        };
        for (cidr, _, _) in &accepted_routes {
            install_route(cidr);
        }
        let mut route_refresh = tokio::time::interval(ROUTE_REFRESH);
        route_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let n = tokio::select! {
                _ = keepalive.tick() => {
                    let hb = bytes::Bytes::from_static(crate::vpn::VPN_KEEPALIVE);
                    // Warm every live connection; reap closed ones in the same
                    // pass so dead entries don't linger in the caches until the
                    // next send error.
                    conns.retain(|_, (conn, _)| {
                        if conn.close_reason().is_none() {
                            let _ = conn.send_datagram(hb.clone());
                            true
                        } else {
                            false
                        }
                    });
                    self.vpn_conns.write().await.retain(|_, conn| {
                        if conn.close_reason().is_none() {
                            let _ = conn.send_datagram(hb.clone());
                            true
                        } else {
                            false
                        }
                    });
                    continue;
                }
                _ = route_refresh.tick() => {
                    let fresh = self.accepted_route_endpoints().await;
                    // Install newly-accepted CIDRs, withdraw routes no longer
                    // advertised. Both idempotent + collision-guarded.
                    for (cidr, _, _) in &fresh {
                        if !accepted_routes.iter().any(|(c, _, _)| c == cidr) {
                            install_route(cidr);
                        }
                    }
                    for (cidr, _, _) in &accepted_routes {
                        if !fresh.iter().any(|(c, _, _)| c == cidr) {
                            uninstall_route(cidr);
                        }
                    }
                    accepted_routes = fresh;
                    continue;
                }
                r = tun.recv(&mut buf) => match r {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!("vpn: TUN read error, stopping forwarder: {e}");
                        break;
                    }
                },
            };
            let pkt = &buf[..n];
            let Some(dst) = crate::vpn::parse_dest_ipv4(pkt) else { continue };
            let (pubkey, relay) = if crate::vpn::is_virtual_addr(dst) {
                // dst is a warren member. Enforce the member-to-member reach ACL
                // (Step 5; default-deny) only when the SOURCE is also a member
                // vIP. A non-virtual source is return traffic from a LAN subnet we
                // gateway for — the destination member already had reach to that
                // route, and conntrack on the gateway gates it to established
                // flows — so it bypasses the member ACL (which keys on vIP→role
                // and would otherwise drop the reply for an unknown source).
                match crate::vpn::parse_src_ipv4(pkt) {
                    None => continue, // malformed — drop
                    Some(src) if crate::vpn::is_virtual_addr(src) => {
                        if !self
                            .vpn_reach_allowed(src, dst, crate::vpn::parse_dest_port(pkt))
                            .await
                        {
                            // Observability: the reach ACL silently dropping
                            // packets is the hard-to-debug case (a missing/empty
                            // role → reach nothing). Say so (debug; per-packet).
                            tracing::debug!(
                                "vpn egress: reach DENIED {src} -> {dst} (role policy) — dropped"
                            );
                            continue;
                        }
                    }
                    Some(_) => {} // LAN-sourced reply for a gatewayed route
                }
                match self.lookup_vpn_endpoint(dst).await {
                    Ok(Some(v)) => v,
                    _ => {
                        tracing::debug!(
                            "vpn egress: {dst} UNRESOLVED (no endpoint) — packet dropped"
                        );
                        continue;
                    }
                }
            } else {
                // Tier 1 LAN bridging + HA: gather every accepted gateway whose
                // route covers `dst` at the LONGEST prefix (a /32 device beats a
                // /24 beats the 0.0.0.0/0 exit). When several advertise the SAME
                // longest-prefix route (HA subnet routers), prefer a gateway we've
                // heard from recently and fail over to a backup when the primary
                // goes silent. Acceptance already gated reach; the gateway
                // re-authorizes on ingress. No covering route → drop.
                let mut best_len: Option<u8> = None;
                let mut candidates: Vec<(iroh::PublicKey, Option<iroh::RelayUrl>)> = Vec::new();
                for (cidr, pk, relay) in &accepted_routes {
                    if let Some((_, len)) = crate::vpn::parse_cidr_v4(cidr)
                        && crate::vpn::cidr_contains_v4(cidr, dst)
                    {
                        match best_len {
                            Some(bl) if len < bl => {}
                            Some(bl) if len == bl => candidates.push((*pk, relay.clone())),
                            _ => {
                                best_len = Some(len);
                                candidates = vec![(*pk, relay.clone())];
                            }
                        }
                    }
                }
                if candidates.is_empty() {
                    continue;
                }
                // Failover: pick a live gateway (fresh inbound datagram) if any;
                // else the first (cold start — the send path below dials it).
                let chosen = {
                    let last_rx = self.vpn_last_rx.read().await;
                    let idx = crate::vpn::select_live(&candidates, |(pk, _)| {
                        last_rx
                            .get(&pk.to_string())
                            .map(|t| t.elapsed() < STALE_AFTER)
                            .unwrap_or(false)
                    });
                    candidates[idx].clone()
                };
                if candidates.len() > 1 {
                    tracing::debug!(
                        "vpn egress: {dst} routed via gateway {} ({} HA candidates)",
                        chosen.0.fmt_short(),
                        candidates.len()
                    );
                }
                chosen
            };
            // Have we received a datagram from this peer recently? That's the only
            // trustworthy liveness signal on the datagram data plane.
            let rx_fresh = self
                .vpn_last_rx
                .read()
                .await
                .get(&pubkey.to_string())
                .map(|t| t.elapsed() < STALE_AFTER)
                .unwrap_or(false);

            // Prefer the peer's live INBOUND connection when we've heard from it
            // recently (a rebooted peer redials and that fresh conn replaces the
            // old one). Else reuse our dial cache if it's fresh / within grace.
            // Else dial. The rx_fresh gate is what lets a silently-dead connection
            // be abandoned instead of black-holing every packet onto it forever.
            let inbound = self.vpn_conns.read().await.get(&pubkey.to_string()).cloned();
            let conn = match inbound {
                Some(c) if c.close_reason().is_none() && rx_fresh => {
                    // One connection per peer: the peer's inbound connection is
                    // live, so converge on it and drop our now-redundant outbound
                    // dial — otherwise two competing connections (26 paths) to one
                    // peer keep flip-flopping. Only the LOWER-node-id side closes,
                    // so exactly one of the pair drops its dial (no simultaneous-
                    // close race that would leave the peer with none).
                    if self.endpoint.id().as_bytes() < pubkey.as_bytes()
                        && let Some((old, _)) = conns.remove(&pubkey)
                    {
                        old.close(0u32.into(), b"superseded by peer inbound connection");
                    }
                    c
                }
                _ => match conns.get(&pubkey) {
                    Some((c, dialed))
                        if c.close_reason().is_none()
                            && (rx_fresh || dialed.elapsed() < DIAL_GRACE) =>
                    {
                        c.clone()
                    }
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
                                // Pump return datagrams on this dialed conn too:
                                // the remote replies over the SAME connection we
                                // dialed (QUIC datagrams are bidirectional), and
                                // without a reader those replies are discarded.
                                {
                                    let (conn2, tun2, ips2, lip2, rfr2, rx2, gw2) = (
                                        c.clone(),
                                        self.vpn_tun.clone(),
                                        self.vpn_peer_ips.clone(),
                                        self.vpn_local_ip.clone(),
                                        self.vpn_refresh.clone(),
                                        self.vpn_last_rx.clone(),
                                        self.vpn_gateway_cidrs.clone(),
                                    );
                                    tokio::spawn(async move {
                                        crate::vpn::pump_vpn_datagrams(&conn2, &tun2, &ips2, &lip2, &rfr2, &rx2, &gw2).await;
                                    });
                                }
                                conns.insert(pubkey, (c.clone(), std::time::Instant::now()));
                                c
                            }
                            Err(e) => {
                                tracing::debug!("vpn: dial {pubkey} failed: {e}");
                                continue;
                            }
                        }
                    }
                },
            };
            if let Err(e) = conn.send_datagram(bytes::Bytes::copy_from_slice(pkt)) {
                // Only abandon the connection if it's genuinely CLOSED. A
                // transient send failure — no validated path yet on a
                // freshly-dialed multipath connection, or an over-MTU packet —
                // must NOT tear it down: doing so dropped the connection on the
                // first packet and the next packet redialed, a tight storm that
                // never let any connection finish establishing (the no-admin
                // reconnect failure). A live connection recovers on its own; a
                // truly-dead one is caught by the rx-staleness gate + keepalive.
                if conn.close_reason().is_some() {
                    tracing::debug!("vpn: connection to {pubkey} closed ({e}); dropping from cache");
                    conns.remove(&pubkey);
                    let mut shared = self.vpn_conns.write().await;
                    if shared.get(&pubkey.to_string()).map(|c| c.stable_id()) == Some(conn.stable_id()) {
                        shared.remove(&pubkey.to_string());
                    }
                } else {
                    tracing::trace!("vpn: transient send failure to {pubkey} ({e}); keeping connection");
                }
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
            .self_doc()
            .await?
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

    /// Record an admitted member's VPN endpoint (`peer/N.vpn_endpoint`) from the
    /// member's authenticated announce. Trust-anchor-only and member-must-exist,
    /// exactly like [`record_peer_self_doc`]. The value is the static
    /// `"<endpoint_id> <relay>"` string (validated by parsing). This is what lets
    /// routing resolve a member's endpoint from the reliably-replicated admin doc
    /// instead of importing the member's self-doc namespace. Idempotent; returns
    /// `Ok(false)` when not applicable.
    pub async fn record_peer_vpn_endpoint(&self, node_id: &str, value: &str) -> Result<bool> {
        if !self.is_trust_anchor() {
            return Ok(false);
        }
        if parse_vpn_endpoint_value(value.as_bytes()).is_none() {
            anyhow::bail!("invalid vpn endpoint value");
        }
        let Some(mut peer) = self.get_peer(node_id).await? else {
            return Ok(false);
        };
        if peer.vpn_endpoint.as_deref() == Some(value) {
            return Ok(true);
        }
        peer.vpn_endpoint = Some(value.to_string());
        self.put_peer(&peer).await?;
        tracing::info!("netdoc: recorded vpn endpoint for member {}", &node_id[..8.min(node_id.len())]);
        Ok(true)
    }

    /// Resolve (and lazily import + cache) a member's read-only self-doc from the
    /// admin doc's `peer/N.self_doc` binding. `None` when the member has no
    /// self-doc (legacy → shared-doc fallback) or the ticket is unusable.
    /// On-demand sync: the self-doc is imported the first time a member is
    /// reached, then cached for the process lifetime.
    pub async fn member_self_doc(&self, node_id: &str) -> Option<Doc> {
        let short = &node_id[..8.min(node_id.len())];
        if let Some((doc, _)) = self.member_docs.read().await.get(node_id).cloned() {
            return Some(doc);
        }
        let peer = self.get_peer(node_id).await.ok().flatten()?;
        let Some(ticket_str) = peer.self_doc.as_deref() else {
            tracing::debug!("netdoc: member {short} has no self_doc ticket recorded yet");
            return None;
        };
        let ticket: DocTicket = match ticket_str.parse() {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!("netdoc: member {short} self_doc ticket unparseable: {e:#}");
                return None;
            }
        };
        let addrs = ticket.nodes.clone();
        // Open if already in the local store, else import. NOTE: `open` does NOT
        // start sync, so always start_sync afterwards with the owner's address —
        // otherwise the content goes stale and the data plane never converges.
        let ns = ticket.capability.id();
        let (doc, how) = match self.docs.open(ns).await {
            Ok(Some(d)) => (d, "opened"),
            _ => match self.docs.import(ticket).await {
                Ok(d) => (d, "imported"),
                Err(e) => {
                    tracing::debug!("netdoc: import self-doc for {short} failed: {e:#}");
                    return None;
                }
            },
        };
        let sync_res = if addrs.is_empty() {
            "no-addrs"
        } else {
            match doc.start_sync(addrs.clone()).await {
                Ok(()) => "start_sync ok",
                Err(e) => {
                    tracing::debug!("netdoc: start_sync self-doc for {short} failed (best-effort): {e:#}");
                    "start_sync FAILED"
                }
            }
        };
        tracing::debug!(
            "netdoc: member {short} self-doc {how} (ns {}), {} addr(s), {sync_res}",
            ns.fmt_short(),
            addrs.len()
        );
        self.member_docs.write().await.insert(node_id.to_string(), (doc.clone(), addrs));
        Some(doc)
    }

    /// Re-affirm sync with every imported member self-doc (keepalive). An
    /// imported self-doc that was `open`ed (not freshly imported) or whose owner
    /// reconnected won't keep syncing on its own, so periodically re-`start_sync`
    /// each with the owner's address — the analogue of `resume_sync` for the
    /// admin doc. Best-effort.
    pub async fn resync_member_self_docs(&self) {
        let docs: Vec<(Doc, Vec<EndpointAddr>)> = self
            .member_docs
            .read()
            .await
            .values()
            .filter(|(_, a)| !a.is_empty())
            .cloned()
            .collect();
        for (doc, addrs) in docs {
            let _ = doc.start_sync(addrs).await;
        }
    }

    /// Drop a member's cached self-doc (on revoke).
    pub async fn evict_member_self_doc(&self, node_id: &str) {
        self.member_docs.write().await.remove(node_id);
    }

    /// Write a self-owned entry (`vpn/ name/ tag/ posture/`) to this node's
    /// **self-doc** AND the shared admin doc (dual-write). Readers PREFER the
    /// owner's self-doc keyed by the admin-allocated `peer/N.vip` (so a forged
    /// shared entry is never consulted — interception-resistant); the shared
    /// copy is the convergence/legacy fallback. Dropping the shared write is the
    /// final isolation step, gated on hardening imported-self-doc sync (a live
    /// 2-node test showed routing didn't converge without it). See §10.
    async fn put_self(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.self_doc()
            .await?
            .set_bytes(self.author, key.as_bytes().to_vec(), value.clone())
            .await
            .context("writing self-doc entry")?;
        // The shared mirror is best-effort: a read-ticket member (#3b Phase 4)
        // has no write capability on the admin doc — its state lives in the
        // self-doc alone, which readers prefer anyway.
        if let Err(e) = self
            .doc
            .set_bytes(self.author, key.as_bytes().to_vec(), value)
            .await
        {
            tracing::debug!("netdoc: shared mirror write for {key:?} failed (read-only member?): {e:#}");
        }
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
            // Per-entry resilience (Layer 1): a single entry whose blob content
            // hasn't synced yet (`entity not found`) — or a malformed value — must
            // NOT fail the whole prefix read. Failing here empties the roster and
            // black-holes the VPN over one lagging entry; instead skip it (Layer 2
            // re-fetches missing content) and return everything else.
            match self.decode_entry::<T>(&entry).await {
                Ok(Some(value)) => out.push(value),
                Ok(None) => {} // tombstone
                Err(e) => {
                    tracing::warn!(
                        "netdoc: skipping entry {} under prefix {prefix}: {e:#}",
                        String::from_utf8_lossy(entry.key())
                    );
                }
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

/// Parse a `vpn/` entry value (`"<endpoint_id_hex> <relay_url?>"`) into the
/// endpoint pubkey + optional relay.
fn parse_vpn_endpoint_value(bytes: &[u8]) -> Option<(iroh::PublicKey, Option<iroh::RelayUrl>)> {
    let value = String::from_utf8_lossy(bytes);
    let mut parts = value.split_whitespace();
    let pubkey = parts.next()?.parse::<iroh::PublicKey>().ok()?;
    let relay = parts.next().and_then(|s| s.parse::<iroh::RelayUrl>().ok());
    Some((pubkey, relay))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PeerRole;
    use crate::sandbox::SandboxPolicy;

    /// Conflict classification drives the multi-warren resolution prompt:
    /// no warren → clean join; same namespace → idempotent; different → conflict.
    #[test]
    fn warren_conflict_classification() {
        let dir = tempfile::tempdir().unwrap();
        // No netdoc.json yet → first warren, no conflict.
        assert_eq!(classify_warren_conflict(dir.path(), "abc123"), WarrenConflict::None);

        // Persist a netdoc.json with a namespace by writing the typed struct's
        // JSON shape directly (namespace is a 32-byte id; use a known hex).
        let ns_hex = "38b534260368fb961765edbdd9ca90b712e107952a8ab7e3948662c2b1dfc230";
        let meta = serde_json::json!({
            "namespace": hex::decode(ns_hex).unwrap(),
            "federated": false,
            "self_namespace": null,
        });
        std::fs::write(dir.path().join("netdoc.json"), meta.to_string()).unwrap();
        let existing = read_namespace(dir.path()).expect("namespace reads back");

        assert_eq!(classify_warren_conflict(dir.path(), &existing), WarrenConflict::Same);
        assert_eq!(
            classify_warren_conflict(dir.path(), "deadbeef"),
            WarrenConflict::Conflict { existing }
        );
    }

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
            vip: None,
            vpn_endpoint: None,
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

    /// Root-cause regression for the e2e routing break: a member admitted with
    /// NO `peer.vip` (e.g. by an older admin) must still be egress-resolvable —
    /// `vip_owner` falls back to its author-validated shared `ip/` claim, so
    /// `lookup_vpn_endpoint` finds its self-doc-only endpoint. And `admit_peer`
    /// (the redemption path) allocates the vip so new admissions never need it.
    #[tokio::test]
    async fn egress_resolves_vipless_member_via_ip_fallback() {
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
        let bep = b.endpoint.id();

        // A admits B WITHOUT a vip (the old redemption gap), but records B's
        // self-doc ticket; B claims its own vIP in the shared ip/ table and
        // registers its endpoint (self-doc only, post-drop).
        let mut peer_b = sample_peer(&b_id, "B");
        peer_b.self_doc = Some(b.self_doc_read_ticket().await.unwrap());
        a.put_peer(&peer_b).await.unwrap();
        let addr = b.claim_virtual_ip(&b_id).await.unwrap();
        b.register_vpn_endpoint(addr).await.unwrap();

        // A resolves B's endpoint via the ip/ fallback → B's self-doc.
        let mut found = false;
        for _ in 0..150 {
            if let Ok(Some((pk, _))) = a.lookup_vpn_endpoint(addr).await
                && pk == bep
            {
                found = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        assert!(found, "egress must resolve a vip-less member via the validated ip/ fallback");

        // admit_peer (the redemption path) allocates a vip for a new member.
        a.admit_peer(&sample_peer("nodeNEWMEMBER", "N")).await.unwrap();
        let admitted = a.get_peer("nodeNEWMEMBER").await.unwrap().unwrap();
        assert!(admitted.vip.is_some(), "admit_peer on the trust anchor must allocate peer.vip");
    }

    /// #3b Phase 1: the trust anchor allocates + records each admitted member's
    /// vIP (`peer/N.vip`); a non-anchor does not.
    #[tokio::test]
    async fn reconcile_allocates_member_vip() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        a.record_founder_anchor(None); // A is the trust anchor

        // Admit member B via reconcile (B present in A's local peers.json).
        let peers = vec![sample_peer("nodeBBBBBBBB", "B")];
        a.reconcile(&peers, &[]).await.unwrap();
        let p = a.get_peer("nodeBBBBBBBB").await.unwrap().unwrap();
        let vip: std::net::Ipv4Addr = p.vip.as_deref().expect("anchor allocates vIP").parse().unwrap();
        assert!(crate::vpn::is_virtual_addr(vip), "vIP must be in the CGNAT range");
        // Idempotent: re-reconcile leaves it unchanged (peer already in doc).
        a.reconcile(&peers, &[]).await.unwrap();
        assert_eq!(a.get_peer("nodeBBBBBBBB").await.unwrap().unwrap().vip, Some(vip.to_string()));

        // A non-anchor node does NOT allocate vIPs.
        let dir_b = tempfile::tempdir().unwrap();
        let b = NetDoc::spawn(test_endpoint().await, dir_b.path(), Bootstrap::Create)
            .await
            .expect("spawn B");
        // no record_founder_anchor → not the trust anchor
        b.reconcile(&[sample_peer("nodeCCCCCCCC", "C")], &[]).await.unwrap();
        assert!(b.get_peer("nodeCCCCCCCC").await.unwrap().unwrap().vip.is_none());
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

        // A peer with NO role_name reaches nothing.
        let m_ip = net.claim_virtual_ip("memberpeer").await.unwrap();
        net.put_peer(&sample_peer("memberpeer", "m")).await.unwrap();
        net.register_host_tags("staginghost", &["staging".into()]).await.unwrap();
        assert!(!net.vpn_reach_allowed(m_ip, dst_ip, None).await);

        // But a peer WITH a role name that isn't defined/synced still reaches the
        // warren by default — an admitted member must not be silently isolated by
        // role-sync lag (the bug behind the macOS warren saga).
        let u_ip = net.claim_virtual_ip("unsyncedpeer").await.unwrap();
        let mut u = sample_peer("unsyncedpeer", "u");
        u.role_name = Some("member".into()); // no "member" role defined in this doc
        net.put_peer(&u).await.unwrap();
        assert!(net.vpn_reach_allowed(u_ip, dst_ip, None).await);

        // A leaf member owns a vIP but holds NO peer roster — its own node is not
        // among list_peers (the real-world leaf case: members don't replicate the
        // full roster). Egress reach can't evaluate its own role, so it must be
        // ALLOWED rather than silently stranded. (Reach is enforced only on the
        // sender; nodes that DO hold the roster still evaluate normally — asserted
        // above.) This is THE bug behind the two-Mac warren's 100% packet loss.
        let leaf_ip = net.claim_virtual_ip("leafnode").await.unwrap();
        // deliberately no put_peer("leafnode") → not a known principal locally
        assert!(net.vpn_reach_allowed(leaf_ip, dst_ip, None).await);
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
    /// #3b interception resistance (the security property of the self-doc model):
    /// a member's endpoint lives ONLY in its own self-doc, and a reader resolves
    /// `vpn/<addr>` from the self-doc of the node that **owns** `addr` per the
    /// admin-allocated `peer/N.vip`. So an attacker M cannot hijack victim V's
    /// vIP: M can't write V's self-doc (no key), and M writing `vpn/<V.vip>` in
    /// M's OWN self-doc is never consulted (the reader reads V.vip from V's
    /// self-doc, since V owns it). M also can't forge `peer/V.vip` (admin-owned).
    #[cfg(unix)]
    #[tokio::test]
    async fn self_doc_blocks_endpoint_interception() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        a.record_founder_anchor(None); // admin / trust anchor
        let ticket = a.write_ticket().await.unwrap();

        // Victim V and attacker M are both members.
        let dir_v = tempfile::tempdir().unwrap();
        let v = NetDoc::spawn(test_endpoint().await, dir_v.path(), Bootstrap::Import(Box::new(ticket.clone())))
            .await
            .expect("spawn V");
        let dir_m = tempfile::tempdir().unwrap();
        let m = NetDoc::spawn(test_endpoint().await, dir_m.path(), Bootstrap::Import(Box::new(ticket)))
            .await
            .expect("spawn M");
        let (v_id, m_id) = (v.endpoint.id().to_string(), m.endpoint.id().to_string());
        let (v_ep, m_ep) = (v.endpoint.id().to_string(), m.endpoint.id().to_string());
        let v_vip: std::net::Ipv4Addr = "100.64.9.9".parse().unwrap();
        let m_vip: std::net::Ipv4Addr = "100.64.9.10".parse().unwrap();

        // Admin admits both with allocated vIPs + records their self-doc tickets.
        let mut pv = sample_peer(&v_id, "V");
        pv.vip = Some(v_vip.to_string());
        pv.self_doc = Some(v.self_doc_read_ticket().await.unwrap());
        a.put_peer(&pv).await.unwrap();
        let mut pm = sample_peer(&m_id, "M");
        pm.vip = Some(m_vip.to_string());
        pm.self_doc = Some(m.self_doc_read_ticket().await.unwrap());
        a.put_peer(&pm).await.unwrap();

        // V writes its legit endpoint. M writes its legit endpoint AND forges
        // `vpn/<V.vip>` -> M's endpoint in M's own self-doc (the interception try).
        let vdoc = v.self_doc().await.unwrap();
        vdoc.set_bytes(v.author, format!("{KEY_VPN_PREFIX}{v_vip}").into_bytes(), format!("{v_ep} ").into_bytes()).await.unwrap();
        let mdoc = m.self_doc().await.unwrap();
        mdoc.set_bytes(m.author, format!("{KEY_VPN_PREFIX}{m_vip}").into_bytes(), format!("{m_ep} ").into_bytes()).await.unwrap();
        mdoc.set_bytes(m.author, format!("{KEY_VPN_PREFIX}{v_vip}").into_bytes(), format!("{m_ep} ").into_bytes()).await.unwrap(); // ATTACK

        a.set_validation_mode(ValidationMode::Enforce);
        // Wait for both members' self-docs to replicate + refresh.
        let mut ready = false;
        for _ in 0..150 {
            a.refresh_vpn_peer_ips().await;
            let map = a.vpn_peer_ips.read().await;
            if map.contains_key(&v_ep) && map.contains_key(&m_ep) {
                ready = true;
                break;
            }
            drop(map);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        assert!(ready, "V+M self-doc endpoints did not replicate to A within 30s (setup)");

        let map = a.vpn_peer_ips.read().await.clone();
        // V's vIP is served by V's endpoint; M's endpoint serves only its OWN vIP.
        assert_eq!(map.get(&v_ep), Some(&v_vip), "V's endpoint serves V's vIP");
        assert_eq!(map.get(&m_ep), Some(&m_vip), "M's endpoint serves only its own vIP, not V's");
        // No endpoint other than V's may be associated with V's vIP.
        for (ep, addr) in map.iter() {
            if *addr == v_vip {
                assert_eq!(ep, &v_ep, "only V may serve V's vIP — interception blocked");
            }
        }
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

    /// #3b Phase 2: egress resolution (`lookup_vpn_endpoint`) resolves a
    /// member's endpoint from its self-doc, keyed by the admin-allocated
    /// `peer/N.vip`, with NO shared-doc `vpn/` entry present.
    #[tokio::test]
    async fn lookup_vpn_endpoint_prefers_self_doc() {
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
        let bep = b.endpoint.id();

        // A admits B with an admin-allocated vIP.
        let addr: std::net::Ipv4Addr = "100.64.7.7".parse().unwrap();
        let mut peer_b = sample_peer(&b_id, "B");
        peer_b.vip = Some(addr.to_string());
        a.put_peer(&peer_b).await.unwrap();

        // B writes its endpoint ONLY to its self-doc (no shared vpn/ entry).
        b.self_doc()
            .await
            .unwrap()
            .set_bytes(
                b.author,
                format!("{KEY_VPN_PREFIX}{addr}").into_bytes(),
                format!("{bep} ").into_bytes(),
            )
            .await
            .unwrap();
        // A records B's self-doc ticket so it can import it.
        a.record_peer_self_doc(&b_id, &b.self_doc_read_ticket().await.unwrap()).await.unwrap();

        // Egress: A resolves addr → B's endpoint via peer.vip + B's self-doc.
        let mut found = false;
        for _ in 0..150 {
            if let Ok(Some((pk, _))) = a.lookup_vpn_endpoint(addr).await
                && pk == bep
            {
                found = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        assert!(found, "lookup_vpn_endpoint did not resolve B's self-doc endpoint via peer.vip");
    }

    /// A member with an admin-allocated vIP but NO published endpoint (neither a
    /// self-doc nor a shared `vpn/` entry — a doc-sync gap, as seen on a live
    /// 0.6.80 warren) must still resolve via the owner node-id fallback: the
    /// validated owner + the warren relay is all `connect_to_host` needs, so its
    /// VPN traffic isn't black-holed over a sync gap.
    #[tokio::test]
    async fn lookup_vpn_endpoint_falls_back_to_owner_nodeid() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        a.record_founder_anchor(None);

        // A real peer id with an admin-allocated vIP, but no endpoint doc at all.
        let peer_ep = test_endpoint().await;
        let peer_id = peer_ep.id();
        let addr: std::net::Ipv4Addr = "100.64.9.9".parse().unwrap();
        let mut peer = sample_peer(&peer_id.to_string(), "P");
        peer.vip = Some(addr.to_string());
        a.put_peer(&peer).await.unwrap();

        let resolved = a.lookup_vpn_endpoint(addr).await.expect("lookup ok");
        assert_eq!(
            resolved.map(|(pk, _)| pk),
            Some(peer_id),
            "egress must resolve a member with no endpoint doc via the owner node-id fallback"
        );
    }

    /// The roster routing path (the structural fix): a member's endpoint recorded
    /// in the admin-vouched `peer/N.vpn_endpoint` resolves egress with **no
    /// self-doc and no shared `vpn/` entry** — so the data plane no longer depends
    /// on the owner's per-member self-doc namespace having synced. Uses an endpoint
    /// id DISTINCT from the owner's node-id, so a pass can only come from the
    /// roster entry, not the owner-node-id fallback.
    #[tokio::test]
    async fn lookup_vpn_endpoint_resolves_via_roster_endpoint() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        a.record_founder_anchor(None);

        let peer_ep = test_endpoint().await;
        let peer_id = peer_ep.id();
        let vpn_ep = test_endpoint().await;
        let vpn_id = vpn_ep.id();
        assert_ne!(peer_id, vpn_id, "endpoint id must differ from node-id to prove the path");
        let addr: std::net::Ipv4Addr = "100.64.7.7".parse().unwrap();
        let mut peer = sample_peer(&peer_id.to_string(), "P");
        peer.vip = Some(addr.to_string());
        a.put_peer(&peer).await.unwrap();
        // Admin records the member's static endpoint (trust-anchor-gated, validated).
        let value = format!("{vpn_id} ");
        assert!(
            a.record_peer_vpn_endpoint(&peer_id.to_string(), &value).await.unwrap(),
            "trust anchor records peer/N.vpn_endpoint"
        );

        let resolved = a.lookup_vpn_endpoint(addr).await.expect("lookup ok");
        assert_eq!(
            resolved.map(|(pk, _)| pk),
            Some(vpn_id),
            "egress must resolve via the admin-vouched roster vpn_endpoint (no self-doc needed)"
        );
    }

    /// Layer 1: egress resolution falls through to the vIP owner's node-id when the
    /// member published neither a roster `vpn_endpoint`, a self-doc, nor a shared
    /// `vpn/` entry — so a doc/blob sync gap can't black-hole reachable traffic that
    /// the node-id fallback could dial.
    #[tokio::test]
    async fn lookup_vpn_endpoint_falls_back_to_owner_node_id() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        a.record_founder_anchor(None);

        let peer_ep = test_endpoint().await;
        let peer_id = peer_ep.id();
        let addr: std::net::Ipv4Addr = "100.64.9.9".parse().unwrap();
        let mut peer = sample_peer(&peer_id.to_string(), "P");
        peer.vip = Some(addr.to_string());
        a.put_peer(&peer).await.unwrap();
        // Deliberately publish NO vpn_endpoint, NO self-doc, NO shared vpn/ entry.

        let resolved = a.lookup_vpn_endpoint(addr).await.expect("lookup ok");
        assert_eq!(
            resolved.map(|(pk, _)| pk),
            Some(peer_id),
            "egress must fall back to the vIP owner's node-id when no endpoint is published"
        );
    }

    /// Layer 1: a refresh that computes an empty roster (a transient sync gap — e.g.
    /// blob content not yet re-fetched) must NOT wipe the working ingress map. The
    /// VPN keeps routing on last-known-good rather than black-holing until restart.
    #[cfg(unix)]
    #[tokio::test]
    async fn refresh_keeps_last_known_good_when_roster_empties() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        a.record_founder_anchor(None);

        // Seed a known-good ingress route, as a prior successful refresh would have.
        let addr: std::net::Ipv4Addr = "100.64.3.3".parse().unwrap();
        a.vpn_peer_ips.write().await.insert("deadbeef".to_string(), addr);

        // The doc has no peer/ip/vpn entries → this refresh computes an empty map.
        a.refresh_vpn_peer_ips().await;

        assert_eq!(
            a.vpn_peer_ips.read().await.get("deadbeef"),
            Some(&addr),
            "an empty refresh must keep the last-known-good route, not wipe it"
        );
    }

    /// MagicDNS resolves from the roster (`peer.name` → `peer.vip`) with NO
    /// `name/` doc entry and no self-doc — so name resolution doesn't wait on the
    /// owner's per-member self-doc converging. Case-insensitive, bare-label match.
    #[tokio::test]
    async fn lookup_name_resolves_via_roster() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        a.record_founder_anchor(None);

        let addr: std::net::Ipv4Addr = "100.64.5.5".parse().unwrap();
        let mut peer = sample_peer(
            "1111111111111111111111111111111111111111111111111111111111111111",
            "Laptop",
        );
        peer.vip = Some(addr.to_string());
        a.put_peer(&peer).await.unwrap();

        assert_eq!(a.lookup_name("laptop").await.unwrap(), Some(addr), "lowercase query");
        assert_eq!(a.lookup_name("Laptop").await.unwrap(), Some(addr), "mixed-case query");
        assert_eq!(a.lookup_name("nope").await.unwrap(), None, "unknown name");
    }

    /// MagicDNS for a read-ticket member: B registers its name ONLY in its
    /// self-doc (it can't write A's main doc), and A still resolves it via the
    /// `lookup_name` member-self-doc fallback.
    #[tokio::test]
    async fn lookup_name_resolves_member_self_doc_name() {
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

        let addr: std::net::Ipv4Addr = "100.64.8.8".parse().unwrap();
        let mut peer_b = sample_peer(&b_id, "B");
        peer_b.vip = Some(addr.to_string());
        a.put_peer(&peer_b).await.unwrap();

        // B writes `name/laptop -> addr` ONLY to its self-doc (no main-doc mirror,
        // as a read-ticket member). A records B's self-doc ticket to import it.
        b.self_doc()
            .await
            .unwrap()
            .set_bytes(b.author, b"name/laptop".to_vec(), addr.to_string().into_bytes())
            .await
            .unwrap();
        a.record_peer_self_doc(&b_id, &b.self_doc_read_ticket().await.unwrap()).await.unwrap();

        // A resolves `laptop` via B's imported self-doc (the new fallback). The
        // main doc never had the entry, so this exercises the self-doc path.
        let mut found = None;
        for _ in 0..150 {
            let _ = a.member_self_doc(&b_id).await; // trigger/keep the import
            if let Ok(Some(ip)) = a.lookup_name("laptop").await {
                found = Some(ip);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        assert_eq!(found, Some(addr), "lookup_name did not resolve B's self-doc name");
    }

    /// The data-plane self-doc override: `refresh_vpn_peer_ips` resolves a
    /// member's endpoint from its OWN self-doc (keyed by the addr it owns per the
    /// validated `ip/` table), even when there is NO shared-doc `vpn/` entry for
    /// it — proving self-docs can carry the data plane (the isolation target).
    #[cfg(unix)]
    #[tokio::test]
    async fn refresh_prefers_self_doc_endpoint() {
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

        // A admits B and owns the addr→B binding via the shared ip/ table.
        a.put_peer(&sample_peer(&b_id, "B")).await.unwrap();
        let addr = a.claim_virtual_ip(&b_id).await.unwrap();

        // B's endpoint is written ONLY to B's self-doc (no shared vpn/ entry).
        let bep = b.endpoint.id();
        b.self_doc()
            .await
            .unwrap()
            .set_bytes(
                b.author,
                format!("{KEY_VPN_PREFIX}{addr}").into_bytes(),
                format!("{bep} ").into_bytes(),
            )
            .await
            .unwrap();

        // A records B's self-doc read ticket so the override can import it.
        let b_self = b.self_doc_read_ticket().await.unwrap();
        a.record_peer_self_doc(&b_id, &b_self).await.unwrap();

        // Refresh: the override must surface B's endpoint from its self-doc.
        let mut found = false;
        for _ in 0..150 {
            a.refresh_vpn_peer_ips().await;
            if a.vpn_peer_ips.read().await.get(&bep.to_string()) == Some(&addr) {
                found = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        assert!(found, "refresh did not resolve B's self-doc-only endpoint via the override");
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

    /// #3b: a node's VPN endpoint (now self-doc-only) resolves on another node
    /// via the admin-recorded `peer/N.vip` + `peer/N.self_doc`, with no shared
    /// `vpn/` entry — the data plane is carried entirely by the isolated self-doc.
    #[tokio::test]
    async fn vpn_endpoint_replicates_via_self_doc() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = NetDoc::spawn(test_endpoint().await, dir_a.path(), Bootstrap::Create)
            .await
            .expect("spawn A");
        a.record_founder_anchor(None);
        let a_id = a.endpoint.id().to_string();
        let addr: std::net::Ipv4Addr = "100.64.1.2".parse().unwrap();
        a.register_vpn_endpoint(addr).await.unwrap(); // self-doc only

        // A records its own admin-doc entry: vip + self-doc read ticket.
        let mut peer_a = sample_peer(&a_id, "A");
        peer_a.vip = Some(addr.to_string());
        peer_a.self_doc = Some(a.self_doc_read_ticket().await.unwrap());
        a.put_peer(&peer_a).await.unwrap();

        let ticket = a.write_ticket().await.unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let b = NetDoc::spawn(test_endpoint().await, dir_b.path(), Bootstrap::Import(Box::new(ticket)))
            .await
            .expect("spawn B");

        // B resolves A's endpoint via peer.vip → A's self-doc (no shared vpn/).
        for _ in 0..150 {
            if let Ok(Some((pubkey, _))) = b.lookup_vpn_endpoint(addr).await {
                assert_eq!(pubkey, a.endpoint.id());
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        panic!("vpn endpoint did not resolve A -> B via self-doc within 30s");
    }
}
