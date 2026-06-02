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
    /// Keeps the docs/gossip/blobs (+ vpn) accept loop alive. Dropping aborts it.
    _router: Router,
    /// Owns the persistent blobs backing store; also used to read entry values.
    fs_store: FsStore,
    doc: Doc,
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

        let mut builder = Router::builder(endpoint.clone())
            .accept(iroh_docs::ALPN, docs.clone())
            .accept(iroh_gossip::ALPN, gossip.clone())
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&blobs, None));
        // The VPN inbound handler is always registered so peers can establish the
        // hop/vpn/1 path, but it only forwards packets once the TUN slot is set
        // (i.e. the VPN is explicitly enabled). Off by default → no-op.
        #[cfg(unix)]
        {
            builder = builder.accept(crate::vpn::VPN_ALPN, crate::vpn::VpnInbound::new(vpn_tun.clone()));
        }
        let router = builder.spawn();

        Ok(Self {
            _router: router,
            fs_store,
            doc,
            author,
            namespace,
            endpoint,
            federated,
            #[cfg(unix)]
            vpn_tun,
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
        join: Option<DocTicket>,
    ) -> Result<(Self, bool)> {
        let existing = std::fs::read_to_string(meta_path)
            .ok()
            .and_then(|s| serde_json::from_str::<NetDocMeta>(&s).ok());

        let (mut net, created) = match &existing {
            Some(meta) => match Self::spawn(endpoint.clone(), store_dir, Bootstrap::Open(meta.namespace)).await {
                Ok(net) => (net, false),
                Err(e) => {
                    tracing::warn!(
                        "netdoc: saved namespace {} could not be opened ({e}); creating fresh",
                        meta.namespace
                    );
                    (Self::spawn(endpoint, store_dir, Bootstrap::Create).await?, true)
                }
            },
            // First run: join an existing network if given a ticket, else create.
            None => match join {
                Some(ticket) => {
                    tracing::info!("netdoc: joining network via import ticket");
                    (Self::spawn(endpoint, store_dir, Bootstrap::Import(Box::new(ticket))).await?, true)
                }
                None => (Self::spawn(endpoint, store_dir, Bootstrap::Create).await?, true),
            },
        };

        // Restore the persisted federation status on reopen (Open loses it).
        if let Some(meta) = &existing {
            net.federated = meta.federated;
        }

        if created {
            let meta = NetDocMeta {
                namespace: net.namespace,
                federated: net.federated,
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

    // ── VPN endpoint registry (Phase 3) ──────────────────────────────────

    /// Publish that this host's virtual `addr` is reachable for VPN traffic at
    /// this netdoc endpoint. Value: `"<endpoint_id_hex> <relay_url?>"`.
    pub async fn register_vpn_endpoint(&self, addr: std::net::Ipv4Addr) -> Result<()> {
        let relay = crate::net::host_relay_url(&self.endpoint)
            .map(|u| u.to_string())
            .unwrap_or_default();
        let value = format!("{} {relay}", self.endpoint.id());
        let key = format!("{KEY_VPN_PREFIX}{addr}");
        self.doc
            .set_bytes(self.author, key.into_bytes(), value.into_bytes())
            .await
            .context("registering vpn endpoint")?;
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

    // ── Host tags + role-derived reach (Steps 3 & 5) ─────────────────────

    /// Publish this host's tags (drives role→tag VPN reach + MagicDNS).
    pub async fn register_host_tags(&self, host_id: &str, tags: &[String]) -> Result<()> {
        let key = format!("tag/{host_id}");
        let value = serde_json::to_vec(tags).context("serializing host tags")?;
        self.doc
            .set_bytes(self.author, key.into_bytes(), value)
            .await
            .context("registering host tags")?;
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
    ) -> bool {
        let ips = match self.list_virtual_ips().await {
            Ok(v) => v,
            Err(_) => return false,
        };
        let owner = |ip: std::net::Ipv4Addr| ips.iter().find(|(a, _)| *a == ip).map(|(_, n)| n.clone());
        let (Some(src_node), Some(dst_node)) = (owner(src_ip), owner(dst_ip)) else {
            return false;
        };
        // Source peer's role.
        let Ok(Some(peer)) = self.get_peer(&src_node).await else { return false };
        let Some(role_name) = peer.role_name else { return false };
        let Ok(Some(role)) = self.find_role(&role_name).await else { return false };
        // Destination host's tags.
        let dst_tags = self.lookup_host_tags(&dst_node).await.unwrap_or_default();
        crate::vpn::acl::role_reaches(&role.host_tags, &dst_tags)
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

    /// Read the network's ACL policy from the document (default-deny if unset).
    pub async fn get_acl_policy(&self) -> Result<crate::vpn::acl::AclPolicy> {
        let query = Query::single_latest_per_key().key_exact(b"acl/policy").build();
        match self.doc.get_one(query).await.context("get_one acl")? {
            Some(e) if e.content_len() > 0 => {
                let bytes = self.fs_store.get_bytes(e.content_hash()).await?;
                Ok(serde_json::from_slice(&bytes).unwrap_or_default())
            }
            _ => Ok(crate::vpn::acl::AclPolicy::default_deny()),
        }
    }

    /// Write the network's ACL policy to the document (replicates to all nodes).
    pub async fn set_acl_policy(&self, policy: &crate::vpn::acl::AclPolicy) -> Result<()> {
        let value = serde_json::to_vec(policy).context("serializing acl policy")?;
        self.doc
            .set_bytes(self.author, b"acl/policy".to_vec(), value)
            .await
            .context("writing acl policy")?;
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
        self.register_vpn_endpoint(addr).await?;
        // Publish this host's tags so other members' roles can resolve reach.
        if let Err(e) = self.register_host_tags(host_node_id, host_tags).await {
            tracing::warn!("vpn: host-tag registration failed: {e:#}");
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
        self.doc
            .set_bytes(self.author, key.into_bytes(), addr.to_string().into_bytes())
            .await
            .context("registering name")?;
        Ok(())
    }

    /// Resolve a host `name` to its virtual IP via the document.
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
        Ok(String::from_utf8_lossy(&bytes).parse().ok())
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
                Some(src) if self.vpn_reach_allowed(src, dst).await => {}
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
            role_name: None,
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
            groups: vec![],
            shell: None,
            sandbox: SandboxPolicy::default(),
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
        assert!(net.vpn_reach_allowed(src_ip, dst_ip).await);

        // Re-tag the host production-only → developer is denied.
        net.register_host_tags("staginghost", &["production".into()]).await.unwrap();
        assert!(!net.vpn_reach_allowed(src_ip, dst_ip).await);

        // A member (no role_name) reaches nothing.
        let m_ip = net.claim_virtual_ip("memberpeer").await.unwrap();
        net.put_peer(&sample_peer("memberpeer", "m")).await.unwrap();
        net.register_host_tags("staginghost", &["staging".into()]).await.unwrap();
        assert!(!net.vpn_reach_allowed(m_ip, dst_ip).await);
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
        for _ in 0..50 {
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

    /// Federation: a VPN endpoint registration written on host A must replicate
    /// to host B after it imports A's write ticket. Validates the multi-node
    /// doc-sync path (gossip + reconciliation) the VPN routing depends on.
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
        for _ in 0..50 {
            if let Ok(Some((pubkey, _))) = b.lookup_vpn_endpoint(addr).await {
                assert_eq!(pubkey, a.endpoint.id());
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        panic!("vpn registration did not replicate A -> B within 10s");
    }
}
