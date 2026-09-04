//! Fleet registration, role management, and aggregate invite handling.
//!
//! Any `hop host` can act as an orchestrator — fleet features are integrated.
//! Fleet data is stored alongside normal host config.

use anyhow::{Context, Result};
use iroh::PublicKey;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::config::{write_shared_file, PeerRole};
use crate::invite;
use crate::proto::{
    AdminResponse, FleetMemberInfo, RoleDefinition, RoleUpdates, UserMode,
};
use crate::sandbox::SandboxPolicy;

// --- Warren membership snapshot (warren-first fleet) ---

/// A read-only mirror of this node's netdoc replica view, exported by the daemon
/// to `warren-members.json`. The full warren membership lives only in the
/// daemon's (exclusively-leased) netdoc store; this file lets any local
/// operator's `hop fleet list/status` read the replicated view without holding
/// the store open and without admin rights (membership is replicated to every
/// node). Same shape every node sees — there is no orchestrator master copy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WarrenSnapshot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub members: Vec<WarrenMemberInfo>,
    #[serde(default)]
    pub roles: Vec<RoleDefinition>,
    /// Unix seconds when the daemon last refreshed this snapshot.
    #[serde(default)]
    pub updated_at: u64,
}

/// A warren member as seen in the replicated netdoc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarrenMemberInfo {
    pub node_id: String,
    pub name: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vip: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
}

/// Default liveness window: a member seen within this many seconds counts as
/// "online" in `hop fleet list` and is targeted by fan-out (`grep`/`exec`) without
/// `--include-offline`. Chosen to comfortably exceed the member→admin contact
/// cadence (announce/redial/keepalive) so a live-but-idle node isn't mislabeled.
pub const DEFAULT_LIVENESS_WINDOW_SECS: u64 = 15 * 60;

impl WarrenMemberInfo {
    /// Seconds since this member was last seen, if `last_seen` parses as an
    /// epoch-seconds timestamp (the format the daemon writes). `None` when there's
    /// no timestamp or it's unparseable (unknown liveness).
    pub fn last_seen_age_secs(&self, now: u64) -> Option<u64> {
        let ls = self.last_seen.as_deref()?.trim().parse::<u64>().ok()?;
        Some(now.saturating_sub(ls))
    }

    /// Whether the member counts as **online**: seen within `window_secs`. A member
    /// with no/unparseable `last_seen` is treated as **offline** (unknown liveness).
    /// NOTE: the founder's own self-entry has no `last_seen`; a renderer that knows
    /// "this node" should force it online rather than rely on this.
    pub fn is_online(&self, now: u64, window_secs: u64) -> bool {
        self.last_seen_age_secs(now).map(|age| age <= window_secs).unwrap_or(false)
    }
}

impl WarrenSnapshot {
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("warren-members.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            Ok(serde_json::from_str(&data)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, config_dir: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        write_shared_file(&config_dir.join("warren-members.json"), &data)?;
        Ok(())
    }
}

/// Member count of the warren the daemon last snapshotted to `warren-members.json`,
/// but **only** when that snapshot is for `namespace` — a stale snapshot from a
/// previously-joined warren must not be trusted. `None` means "unknown" (no
/// snapshot, or it's for a different warren); callers should treat unknown
/// conservatively (e.g. prompt rather than auto-switch). The count includes this
/// node itself, so a solo warren reports `Some(1)`.
pub fn warren_member_count(config_dir: &Path, namespace: &str) -> Option<usize> {
    let snap = WarrenSnapshot::load(config_dir).ok()?;
    match snap.namespace.as_deref() {
        Some(ns) if ns == namespace => Some(snap.members.len()),
        _ => None,
    }
}

/// Pure join of netdoc reads into a snapshot — `peer/` entries enriched with the
/// admin-allocated vIP (falling back to the shared `ip/` table) and per-node
/// tags. Separated from the async reads so it can be unit-tested.
fn join_warren_snapshot(
    peers: Vec<crate::config::Peer>,
    roles: Vec<RoleDefinition>,
    vips: Vec<(std::net::Ipv4Addr, String)>,
    tags: std::collections::HashMap<String, Vec<String>>,
    namespace: Option<String>,
) -> WarrenSnapshot {
    let vip_by_node: std::collections::HashMap<String, String> =
        vips.into_iter().map(|(addr, node)| (node, addr.to_string())).collect();
    let members = peers
        .into_iter()
        .map(|p| {
            let role = p
                .role_name
                .clone()
                .unwrap_or_else(|| format!("{:?}", p.role).to_lowercase());
            let vip = p.vip.clone().or_else(|| vip_by_node.get(&p.node_id).cloned());
            let node_tags = tags.get(&p.node_id).cloned().unwrap_or_default();
            WarrenMemberInfo { node_id: p.node_id, name: p.name, role, vip, tags: node_tags, last_seen: p.last_seen }
        })
        .collect();
    WarrenSnapshot { namespace, members, roles, updated_at: 0 }
}

/// Build a membership snapshot from the live netdoc (daemon side).
pub async fn build_warren_snapshot(netdoc: &crate::netdoc::NetDoc) -> Result<WarrenSnapshot> {
    let mut peers = netdoc.list_peers().await.context("list_peers")?;
    let roles = netdoc.list_roles().await.unwrap_or_default();
    let vips = netdoc.list_virtual_ips().await.unwrap_or_default();
    let tags = netdoc.list_host_tags().await.unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Merge VPN data-plane liveness into `last_seen`: control-plane `last_seen`
    // misses a VPN-active-but-idle member (it only refreshes on a hop/3 connect),
    // but the founder receives that member's keepalive every ~5s. Take the later of
    // the two so liveness in `hop fleet list` / fan-out reflects real reachability.
    for p in &mut peers {
        if let Some(ep) = p.vpn_endpoint.as_deref()
            && let Some(vpn_seen) = netdoc.vpn_last_rx_epoch(ep, now).await
        {
            let cp = p.last_seen.as_deref().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
            if vpn_seen > cp {
                p.last_seen = Some(vpn_seen.to_string());
            }
        }
    }
    let mut snap = join_warren_snapshot(peers, roles, vips, tags, Some(netdoc.namespace().to_string()));
    snap.updated_at = now;
    Ok(snap)
}

/// Build + persist the snapshot (daemon side). Best-effort; logs on failure.
pub async fn export_warren_snapshot(netdoc: &crate::netdoc::NetDoc, config_dir: &Path) {
    match build_warren_snapshot(netdoc).await {
        Ok(snap) => {
            if let Err(e) = snap.save(config_dir) {
                tracing::warn!("warren snapshot save failed: {e:#}");
            }
        }
        Err(e) => tracing::warn!("warren snapshot build failed: {e:#}"),
    }
}

// --- Fleet store ---

/// A registered fleet member (orchestrator side).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetMember {
    pub node_id: String,
    pub hostname: String,
    pub tags: Vec<String>,
    pub registered_at: String,
    pub last_heartbeat: Option<String>,
    pub relay_url: Option<String>,
    pub online: bool,
}

/// Orchestrator-side fleet store, persisted as `fleet.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FleetStore {
    pub members: Vec<FleetMember>,
}

impl FleetStore {
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("fleet.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            Ok(serde_json::from_str(&data)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, config_dir: &Path) -> Result<()> {
        let path = config_dir.join("fleet.json");
        let data = serde_json::to_string_pretty(self)?;
        write_shared_file(&path, &data)?;
        Ok(())
    }

    /// Add a member, replacing any existing entry with the same node_id.
    pub fn add_member(&mut self, member: FleetMember) {
        self.members.retain(|m| m.node_id != member.node_id);
        self.members.push(member);
    }
}

// --- Roles store ---

fn route_default_true() -> bool {
    true
}

/// A subnet/exit route this host advertises as a **gateway** (Tier 1 LAN
/// bridging). Persisted in `routes.json` (git-committable infra-as-code) and
/// materialized into the netdoc + gateway forwarding when the daemon starts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// CIDR to bridge, e.g. `192.168.1.0/24`, or a `/32` device. Ignored for an
    /// exit route (which always advertises `0.0.0.0/0`).
    pub cidr: String,
    /// Tags gating reach to this route (Cedar resource tags). Empty = inherit
    /// the gateway node's own host tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// SNAT (masquerade) forwarded traffic to the gateway's LAN IP. Default on.
    #[serde(default = "route_default_true")]
    pub snat: bool,
    /// Advertise as an internet exit node (`0.0.0.0/0`) rather than a subnet.
    #[serde(default)]
    pub exit: bool,
    /// App connector (P4): a domain name to resolve and advertise as `/32`
    /// route(s) for its current IP(s), so warren traffic to that domain egresses
    /// from this connector's stable address. When set, `cidr`/`exit` are ignored.
    #[serde(default)]
    pub domain: Option<String>,
}

impl RouteConfig {
    /// The `/32` CIDRs this entry advertises right now. For an app-connector
    /// (`domain` set) this resolves the domain to its current IPv4(s); otherwise
    /// it's the single effective CIDR.
    pub fn resolved_cidrs(&self) -> Vec<String> {
        if let Some(domain) = &self.domain {
            use std::net::ToSocketAddrs;
            return (domain.as_str(), 0u16)
                .to_socket_addrs()
                .map(|addrs| {
                    let mut v: Vec<String> = addrs
                        .filter_map(|a| match a.ip() {
                            std::net::IpAddr::V4(ip) => Some(format!("{ip}/32")),
                            std::net::IpAddr::V6(_) => None,
                        })
                        .collect();
                    v.sort();
                    v.dedup();
                    v
                })
                .unwrap_or_default();
        }
        vec![RoutesStore::effective_cidr(self)]
    }
}

/// A split-DNS rule (P4): send queries for `domain` to `nameserver` (a LAN DNS
/// server, typically reachable via an accepted subnet route) instead of MagicDNS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitDns {
    pub domain: String,
    pub nameserver: String,
}

/// Gateway routes + DNS config this host applies, persisted as `routes.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RoutesStore {
    pub routes: Vec<RouteConfig>,
    /// Split-DNS rules this node applies to its own resolver (P4).
    #[serde(default)]
    pub split_dns: Vec<SplitDns>,
}

impl RoutesStore {
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("routes.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            Ok(serde_json::from_str(&data)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, config_dir: &Path) -> Result<()> {
        let path = config_dir.join("routes.json");
        let data = serde_json::to_string_pretty(self)?;
        write_shared_file(&path, &data)?;
        Ok(())
    }

    /// The canonical CIDR a route resolves to (`0.0.0.0/0` for an exit node).
    pub fn effective_cidr(rc: &RouteConfig) -> String {
        if rc.exit {
            "0.0.0.0/0".to_string()
        } else {
            rc.cidr.clone()
        }
    }
}

/// Orchestrator-side role definitions, persisted as `roles.json`.
/// This file is designed to be git-committable for infrastructure-as-code.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RolesStore {
    pub roles: Vec<RoleDefinition>,
}

impl RolesStore {
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("roles.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            Ok(serde_json::from_str(&data)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, config_dir: &Path) -> Result<()> {
        let path = config_dir.join("roles.json");
        let data = serde_json::to_string_pretty(self)?;
        write_shared_file(&path, &data)?;
        Ok(())
    }

    pub fn find_role(&self, name: &str) -> Option<&RoleDefinition> {
        self.roles.iter().find(|r| r.name == name)
    }

    /// Ensure the canonical `member` role exists (warren-mesh reach, no host
    /// sessions). Self-heals a warren whose `roles.json` was seeded **before**
    /// `member` was a default role: an admitted peer with `role_name = "member"`
    /// but no such definition hits the reach engine's role-not-found path and
    /// reaches NOTHING. Returns `true` if it added the role (caller should
    /// `save` + reconcile so it propagates to members). No-op if already present.
    pub fn ensure_member(&mut self) -> bool {
        if self.roles.iter().any(|r| r.name == "member") {
            return false;
        }
        self.roles.push(RoleDefinition {
            name: "member".into(),
            host_tags: vec!["*".into()],
            sudo: false,
            admin: false,
            network_only: false,
            user_mode: UserMode::Individual,
            groups: vec![],
            shell: None,
            sandbox: SandboxPolicy::default(),
            capabilities: Default::default(),
            exec_tags: vec![],
            search_tags: vec![],
        });
        true
    }

    /// Seed opinionated default roles on first orchestrator startup.
    /// Only call this when roles.json does not yet exist.
    pub fn seed_defaults(config_dir: &Path) -> Result<Self> {
        let store = Self {
            roles: vec![
                // Default role for every node invite. Reaches the warren mesh by
                // default (`*`) so a fresh/personal warren "just works" — members
                // can ping/route to each other with no extra config. It grants L3
                // reach only, NOT host sessions (no sudo/admin). To restrict who
                // reaches sensitive hosts, tag those hosts and admit users with a
                // tag-scoped role (e.g. `developer`) instead of `member`.
                RoleDefinition {
                    name: "member".into(),
                    host_tags: vec!["*".into()],
                    sudo: false,
                    admin: false,
                    network_only: false,
                    user_mode: UserMode::Individual,
                    groups: vec![],
                    shell: None,
                    sandbox: SandboxPolicy::default(),
                    capabilities: Default::default(),
                    exec_tags: vec![],
                    search_tags: vec![],
                },
                RoleDefinition {
                    name: "admin".into(),
                    host_tags: vec!["*".into()],
                    sudo: true,
                    admin: true,
                    network_only: false,
                    user_mode: UserMode::Individual,
                    groups: vec!["docker".into()],
                    shell: None,
                    sandbox: SandboxPolicy::default(),
                    capabilities: Default::default(),
                    exec_tags: vec![],
                    search_tags: vec![],
                },
                RoleDefinition {
                    name: "ops".into(),
                    host_tags: vec!["*".into()],
                    sudo: true,
                    admin: false,
                    network_only: false,
                    user_mode: UserMode::Individual,
                    groups: vec!["docker".into()],
                    shell: None,
                    sandbox: SandboxPolicy::default(),
                    capabilities: Default::default(),
                    exec_tags: vec![],
                    search_tags: vec![],
                },
                // Warren-only: on the mesh with L3 reach to services it's tagged
                // for, but cannot open host sessions (shell/exec/transfer).
                RoleDefinition {
                    name: "warren-only".into(),
                    host_tags: vec![],
                    sudo: false,
                    admin: false,
                    network_only: true,
                    user_mode: UserMode::Individual,
                    groups: vec![],
                    shell: None,
                    sandbox: SandboxPolicy::default(),
                    capabilities: Default::default(),
                    exec_tags: vec![],
                    search_tags: vec![],
                },
                RoleDefinition {
                    name: "developer".into(),
                    host_tags: vec!["developer".into(), "staging".into()],
                    sudo: false,
                    admin: false,
                    network_only: false,
                    user_mode: UserMode::Individual,
                    groups: vec![],
                    shell: None,
                    sandbox: SandboxPolicy::default(),
                    capabilities: Default::default(),
                    exec_tags: vec![],
                    search_tags: vec![],
                },
                RoleDefinition {
                    name: "security".into(),
                    host_tags: vec!["production".into(), "staging".into()],
                    sudo: false,
                    admin: false,
                    network_only: false,
                    user_mode: UserMode::Individual,
                    groups: vec![],
                    shell: None,
                    sandbox: SandboxPolicy::preset_audit(),
                    capabilities: Default::default(),
                    exec_tags: vec![],
                    search_tags: vec![],
                },
                RoleDefinition {
                    name: "ci".into(),
                    host_tags: vec!["build".into()],
                    sudo: false,
                    admin: false,
                    network_only: false,
                    user_mode: UserMode::Shared,
                    groups: vec![],
                    shell: None,
                    sandbox: SandboxPolicy::preset_deploy(),
                    capabilities: Default::default(),
                    exec_tags: vec![],
                    search_tags: vec![],
                },
            ],
        };
        store.save(config_dir)?;
        Ok(store)
    }
}

// --- Fleet registration (host side) ---

// Retired (warren-first fleet, P4): the host→orchestrator binding
// (`fleet_registrations.json` / `FleetRegistrationsStore`) is obsolete — a host
// is a warren node, not "registered with" an orchestrator. `hop fleet status`
// reads the replicated netdoc snapshot instead.

// --- Aggregate invite store ---

/// A pending aggregate invite (orchestrator side).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateInvite {
    pub secret_hash: String,
    pub role: String,
    pub peer_name: String,
    pub created_at: u64,
}

/// Orchestrator-side aggregate invites, persisted as `aggregate_invites.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AggregateInvitesStore {
    pub invites: Vec<AggregateInvite>,
}

impl AggregateInvitesStore {
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("aggregate_invites.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            Ok(serde_json::from_str(&data)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, config_dir: &Path) -> Result<()> {
        let path = config_dir.join("aggregate_invites.json");
        let data = serde_json::to_string_pretty(self)?;
        write_shared_file(&path, &data)?;
        Ok(())
    }

    pub fn prune_expired(&mut self, max_age_secs: u64) {
        let now = unix_now();
        self.invites
            .retain(|inv| now.saturating_sub(inv.created_at) < max_age_secs);
    }
}

// --- Fleet admin handlers ---

pub fn handle_create_fleet_invite(
    config_dir: &Path,
    relay_url: Option<&str>,
    host_public_key: &PublicKey,
    tags: Vec<String>,
    max_uses: u32,
    expiry_secs: u64,
    tier: Option<String>,
) -> AdminResponse {
    use crate::invite::InviteTier;
    // Parse the tier; default (None) preserves the legacy admin/Creator behaviour.
    let tier = match tier.as_deref() {
        None => None,
        Some(s) => match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "client" => Some(InviteTier::Client),
            "warren-only" | "warren" | "vpn" => Some(InviteTier::WarrenOnly),
            "node" => Some(InviteTier::Node),
            "admin" => Some(InviteTier::Admin),
            other => {
                return AdminResponse::Error {
                    message: format!("unknown --tier {other:?} (expected: client, warren-only, node, admin)"),
                };
            }
        },
    };
    // Warren tiers need a warren on this host.
    if matches!(tier, Some(InviteTier::WarrenOnly | InviteTier::Node | InviteTier::Admin))
        && !config_dir.join("netdoc.ticket").exists()
    {
        return AdminResponse::Error {
            message: "a warren tier was requested but this host has no warren (enable the VPN first)".to_string(),
        };
    }
    // Tier → role (must be set BEFORE the pending invite is stored). Legacy
    // default (tier None) and admin tier are Creator; node/warren-only are Peer.
    let (peer_role, role_name) = match tier {
        None | Some(InviteTier::Admin) => (PeerRole::Creator, None),
        Some(InviteTier::WarrenOnly) => (PeerRole::Peer, Some("warren-only".to_string())),
        Some(InviteTier::Client) | Some(InviteTier::Node) => (PeerRole::Peer, None),
    };
    // A fleet invite is the reusable, warren-scoped path: one token N hosts
    // redeem. max_uses > 1 makes the underlying pending invite reusable.
    let max_uses_opt = (max_uses > 1).then_some(max_uses);
    // The tier is recorded with the pending invite; the grant (read/write
    // ticket, founder anchor) is resolved after the secret verifies and sent in
    // `AuthResultV2`. The legacy default (no tier) is an admin invite.
    let effective_tier = tier.unwrap_or(InviteTier::Admin);
    let token = match invite::generate_invite_with_tier(
        host_public_key,
        config_dir,
        relay_url,
        None,
        None,
        peer_role,
        role_name,
        expiry_secs,
        crate::sandbox::SandboxPolicy::default(),
        max_uses_opt,
        effective_tier,
    ) {
        Ok(t) => t,
        Err(e) => {
            return AdminResponse::Error {
                message: format!("failed to create fleet invite: {e}"),
            };
        }
    };
    tracing::info!("Fleet invite created (tier {}) with tags: {:?}", effective_tier.as_str(), tags);
    AdminResponse::FleetInviteCreated { token }
}


pub fn handle_list_fleet(config_dir: &Path, tag_filter: Option<&str>) -> AdminResponse {
    match FleetStore::load(config_dir) {
        Ok(store) => {
            let members: Vec<FleetMemberInfo> = store
                .members
                .iter()
                .filter(|m| {
                    tag_filter
                        .map(|t| m.tags.iter().any(|mt| mt == t))
                        .unwrap_or(true)
                })
                .map(|m| FleetMemberInfo {
                    node_id: m.node_id.clone(),
                    hostname: m.hostname.clone(),
                    tags: m.tags.clone(),
                    online: m.online,
                    last_heartbeat: m.last_heartbeat.clone(),
                })
                .collect();
            AdminResponse::FleetList { members }
        }
        Err(e) => AdminResponse::Error {
            message: format!("failed to load fleet: {e}"),
        },
    }
}

pub fn handle_remove_fleet_member(config_dir: &Path, node_id_prefix: &str) -> AdminResponse {
    match FleetStore::load(config_dir) {
        Ok(mut store) => {
            let before = store.members.len();
            store.members.retain(|m| !m.node_id.starts_with(node_id_prefix));
            let removed = store.members.len() < before;
            if removed
                && let Err(e) = store.save(config_dir)
            {
                return AdminResponse::Error {
                    message: format!("removed but failed to save: {e}"),
                };
            }
            AdminResponse::FleetMemberRemoved { success: removed }
        }
        Err(e) => AdminResponse::Error {
            message: format!("failed to load fleet: {e}"),
        },
    }
}

pub fn handle_update_fleet_tags(
    config_dir: &Path,
    node_id_prefix: &str,
    tags: Vec<String>,
) -> AdminResponse {
    match FleetStore::load(config_dir) {
        Ok(mut store) => {
            if let Some(member) = store.members.iter_mut().find(|m| m.node_id.starts_with(node_id_prefix)) {
                member.tags = tags;
                if let Err(e) = store.save(config_dir) {
                    return AdminResponse::Error {
                        message: format!("updated but failed to save: {e}"),
                    };
                }
                AdminResponse::FleetTagsUpdated { success: true }
            } else {
                AdminResponse::FleetTagsUpdated { success: false }
            }
        }
        Err(e) => AdminResponse::Error {
            message: format!("failed to load fleet: {e}"),
        },
    }
}

// --- Role management handlers ---

pub fn handle_create_role(config_dir: &Path, definition: RoleDefinition) -> AdminResponse {
    match RolesStore::load(config_dir) {
        Ok(mut store) => {
            if store.roles.iter().any(|r| r.name == definition.name) {
                return AdminResponse::Error {
                    message: format!("role '{}' already exists", definition.name),
                };
            }
            let name = definition.name.clone();
            store.roles.push(definition);
            if let Err(e) = store.save(config_dir) {
                return AdminResponse::Error {
                    message: format!("failed to save roles: {e}"),
                };
            }
            AdminResponse::RoleCreated { name }
        }
        Err(e) => AdminResponse::Error {
            message: format!("failed to load roles: {e}"),
        },
    }
}

pub fn handle_list_roles(config_dir: &Path) -> AdminResponse {
    match RolesStore::load(config_dir) {
        Ok(store) => AdminResponse::RoleList {
            roles: store.roles,
        },
        Err(e) => AdminResponse::Error {
            message: format!("failed to load roles: {e}"),
        },
    }
}

pub fn handle_update_role(config_dir: &Path, name: &str, updates: RoleUpdates) -> AdminResponse {
    match RolesStore::load(config_dir) {
        Ok(mut store) => {
            if let Some(role) = store.roles.iter_mut().find(|r| r.name == name) {
                // Apply updates
                for tag in &updates.add_tags {
                    if !role.host_tags.contains(tag) {
                        role.host_tags.push(tag.clone());
                    }
                }
                role.host_tags.retain(|t| !updates.remove_tags.contains(t));
                if let Some(sudo) = updates.sudo {
                    role.sudo = sudo;
                }
                if let Some(admin) = updates.admin {
                    role.admin = admin;
                }
                if let Some(network_only) = updates.network_only {
                    role.network_only = network_only;
                }
                if let Some(groups) = updates.groups {
                    role.groups = groups;
                }
                if let Some(shell) = updates.shell {
                    role.shell = shell;
                }
                if let Some(user_mode) = updates.user_mode {
                    role.user_mode = user_mode;
                }
                if let Some(sandbox) = updates.sandbox {
                    role.sandbox = sandbox;
                }
                if let Some(exec_tags) = updates.exec_tags {
                    role.exec_tags = exec_tags;
                }
                if let Some(search_tags) = updates.search_tags {
                    role.search_tags = search_tags;
                }
                if let Err(e) = store.save(config_dir) {
                    return AdminResponse::Error {
                        message: format!("failed to save roles: {e}"),
                    };
                }
                AdminResponse::RoleUpdated {
                    name: name.to_string(),
                }
            } else {
                AdminResponse::Error {
                    message: format!("role '{name}' not found"),
                }
            }
        }
        Err(e) => AdminResponse::Error {
            message: format!("failed to load roles: {e}"),
        },
    }
}

pub fn handle_delete_role(config_dir: &Path, name: &str) -> AdminResponse {
    match RolesStore::load(config_dir) {
        Ok(mut store) => {
            let before = store.roles.len();
            store.roles.retain(|r| r.name != name);
            if store.roles.len() < before {
                if let Err(e) = store.save(config_dir) {
                    return AdminResponse::Error {
                        message: format!("failed to save roles: {e}"),
                    };
                }
                AdminResponse::RoleDeleted {
                    name: name.to_string(),
                }
            } else {
                AdminResponse::Error {
                    message: format!("role '{name}' not found"),
                }
            }
        }
        Err(e) => AdminResponse::Error {
            message: format!("failed to load roles: {e}"),
        },
    }
}

// --- Aggregate invite handlers (Phase 3) ---

/// Aggregate invite token payload — encoded as base64url JSON.
#[derive(Debug, Serialize, Deserialize)]
pub struct AggregateInviteToken {
    pub orchestrator_node_id: String,
    pub secret: String,
    pub orchestrator_relay_url: Option<String>,
    pub role: String,
    pub peer_name: String,
}

pub fn handle_create_aggregate_invite(
    config_dir: &Path,
    relay_url: Option<&str>,
    host_public_key: &PublicKey,
    role: &str,
    peer_name: &str,
) -> AdminResponse {
    use argon2::{Argon2, PasswordHasher};
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    use base64::Engine;
    use rand::RngCore;

    // Verify the role exists
    let roles_store = match RolesStore::load(config_dir) {
        Ok(s) => s,
        Err(e) => {
            return AdminResponse::Error {
                message: format!("failed to load roles: {e}"),
            };
        }
    };
    if roles_store.find_role(role).is_none() {
        return AdminResponse::Error {
            message: format!("role '{role}' not found"),
        };
    }

    // Generate secret
    let mut secret_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut secret_bytes);
    let secret_hex = hex::encode(secret_bytes);

    // Hash for storage
    let mut salt_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt_b64 = STANDARD_NO_PAD.encode(salt_bytes);
    let salt = match argon2::password_hash::SaltString::from_b64(&salt_b64) {
        Ok(s) => s,
        Err(e) => {
            return AdminResponse::Error {
                message: format!("failed to create salt: {e}"),
            };
        }
    };
    let argon2 = Argon2::default();
    let secret_hash = match argon2.hash_password(secret_hex.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            return AdminResponse::Error {
                message: format!("failed to hash secret: {e}"),
            };
        }
    };

    // Store
    let mut store = match AggregateInvitesStore::load(config_dir) {
        Ok(s) => s,
        Err(e) => {
            return AdminResponse::Error {
                message: format!("failed to load aggregate invites: {e}"),
            };
        }
    };
    store.prune_expired(7 * 24 * 3600); // 7-day expiry
    store.invites.push(AggregateInvite {
        secret_hash,
        role: role.to_string(),
        peer_name: peer_name.to_string(),
        created_at: unix_now(),
    });
    if let Err(e) = store.save(config_dir) {
        return AdminResponse::Error {
            message: format!("failed to save aggregate invites: {e}"),
        };
    }

    // Build token
    let token = AggregateInviteToken {
        orchestrator_node_id: host_public_key.to_string(),
        secret: secret_hex,
        orchestrator_relay_url: relay_url.map(String::from),
        role: role.to_string(),
        peer_name: peer_name.to_string(),
    };
    let json = match serde_json::to_string(&token) {
        Ok(j) => j,
        Err(e) => {
            return AdminResponse::Error {
                message: format!("failed to serialize invite token: {e}"),
            };
        }
    };
    let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());

    AdminResponse::AggregateInviteCreated { token: encoded }
}

pub fn handle_redeem_aggregate_invite(
    config_dir: &Path,
    _relay_url: Option<&str>,
    _host_public_key: &PublicKey,
    secret: &str,
) -> AdminResponse {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};

    let mut store = match AggregateInvitesStore::load(config_dir) {
        Ok(s) => s,
        Err(e) => {
            return AdminResponse::Error {
                message: format!("failed to load aggregate invites: {e}"),
            };
        }
    };
    store.prune_expired(7 * 24 * 3600);

    let argon2 = Argon2::default();

    // Find matching invite
    let idx = store.invites.iter().position(|inv| {
        if let Ok(stored_hash) = PasswordHash::new(&inv.secret_hash) {
            argon2
                .verify_password(secret.as_bytes(), &stored_hash)
                .is_ok()
        } else {
            false
        }
    });

    let invite = match idx {
        Some(i) => store.invites[i].clone(),
        None => {
            return AdminResponse::Error {
                message: "invalid or expired aggregate invite".to_string(),
            };
        }
    };
    // Don't consume — aggregate invites can be reused until expiry

    // Look up role definition
    let roles_store = match RolesStore::load(config_dir) {
        Ok(s) => s,
        Err(e) => {
            return AdminResponse::Error {
                message: format!("failed to load roles: {e}"),
            };
        }
    };
    let role_def = match roles_store.find_role(&invite.role) {
        Some(r) => r.clone(),
        None => {
            return AdminResponse::Error {
                message: format!("role '{}' no longer exists", invite.role),
            };
        }
    };

    // Find matching fleet members
    let fleet = match FleetStore::load(config_dir) {
        Ok(s) => s,
        Err(e) => {
            return AdminResponse::Error {
                message: format!("failed to load fleet: {e}"),
            };
        }
    };

    let matching_members: Vec<&FleetMember> = fleet
        .members
        .iter()
        .filter(|m| {
            m.online
                && role_def.host_tags.iter().any(|tag| {
                    tag == "*" || m.tags.contains(tag)
                })
        })
        .collect();

    // For now, return the list of matching hosts.
    // In a full implementation, the orchestrator would connect to each host
    // and create per-host invites. For this initial implementation, we return
    // the host info so the client can connect directly.
    let hosts: Vec<crate::proto::RedeemHostEntry> = matching_members
        .iter()
        .map(|m| {
            // The invite_token field would be populated by actual per-host invite creation.
            // For now, this is a placeholder — the full flow requires async orchestrator-to-host calls.
            crate::proto::RedeemHostEntry {
                hostname: m.hostname.clone(),
                node_id: m.node_id.clone(),
                relay_url: m.relay_url.clone(),
                invite_token: String::new(), // Populated during async redemption
            }
        })
        .collect();

    AdminResponse::AggregateInviteRedeemed { hosts }
}

fn unix_now() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::UserMode;

    fn member_seen(last_seen: Option<&str>) -> WarrenMemberInfo {
        WarrenMemberInfo {
            node_id: "n".into(),
            name: "m".into(),
            role: "member".into(),
            vip: None,
            tags: vec![],
            last_seen: last_seen.map(String::from),
        }
    }

    #[test]
    fn member_liveness_from_last_seen() {
        let now = 1_000_000u64;
        // Fresh (10s ago) → online within a 15-min window.
        assert!(member_seen(Some("999990")).is_online(now, 900));
        assert_eq!(member_seen(Some("999990")).last_seen_age_secs(now), Some(10));
        // Stale (1 day ago) → offline within a 15-min window.
        assert!(!member_seen(Some(&(now - 86400).to_string())).is_online(now, 900));
        // No timestamp → unknown → offline (the renderer forces self online).
        assert!(!member_seen(None).is_online(now, 900));
        assert_eq!(member_seen(None).last_seen_age_secs(now), None);
        // Garbage timestamp → offline, no panic.
        assert!(!member_seen(Some("not-a-number")).is_online(now, 900));
        // Future timestamp (clock skew) → age 0 → online.
        assert!(member_seen(Some(&(now + 50).to_string())).is_online(now, 900));
    }

    fn peer(node_id: &str, name: &str, role_name: Option<&str>, vip: Option<&str>) -> crate::config::Peer {
        crate::config::Peer {
            node_id: node_id.into(),
            name: name.into(),
            authorized_at: "0".into(),
            last_seen: None,
            username: None,
            role: PeerRole::Peer,
            role_name: role_name.map(String::from),
            netdoc_author: None,
            self_doc: None,
            vip: vip.map(String::from),
            vpn_endpoint: None,
            site_id: None,
            sandbox: SandboxPolicy::default(),
        }
    }

    /// The snapshot join enriches each peer with its vIP (admin-allocated on the
    /// peer entry, else the shared ip/ table) and its tags, and carries roles.
    #[test]
    fn warren_snapshot_join() {
        let peers = vec![
            peer("aaaa", "web-1", Some("developer"), Some("100.64.0.2")),
            peer("bbbb", "ci-1", Some("ci"), None), // vIP from the ip/ table fallback
        ];
        let roles = vec![test_role("developer", vec!["staging".into()], UserMode::Individual, false, false, vec![], None)];
        let vips = vec![("100.64.0.3".parse().unwrap(), "bbbb".to_string())];
        let mut tags = std::collections::HashMap::new();
        tags.insert("aaaa".to_string(), vec!["staging".to_string()]);

        let snap = join_warren_snapshot(peers, roles, vips, tags, Some("ns123".into()));

        assert_eq!(snap.namespace.as_deref(), Some("ns123"));
        assert_eq!(snap.members.len(), 2);
        assert_eq!(snap.roles.len(), 1);
        let web = &snap.members[0];
        assert_eq!(web.name, "web-1");
        assert_eq!(web.role, "developer");
        assert_eq!(web.vip.as_deref(), Some("100.64.0.2")); // from the peer entry
        assert_eq!(web.tags, vec!["staging".to_string()]);
        let ci = &snap.members[1];
        assert_eq!(ci.vip.as_deref(), Some("100.64.0.3")); // from the ip/ table fallback
        assert!(ci.tags.is_empty());
    }

    /// Snapshot round-trips through warren-members.json.
    #[test]
    fn warren_snapshot_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let snap = WarrenSnapshot {
            namespace: Some("ns".into()),
            members: vec![WarrenMemberInfo {
                node_id: "n".into(), name: "h".into(), role: "node".into(),
                vip: Some("100.64.0.9".into()), tags: vec!["t".into()], last_seen: None,
            }],
            roles: vec![],
            updated_at: 42,
        };
        snap.save(dir.path()).unwrap();
        let loaded = WarrenSnapshot::load(dir.path()).unwrap();
        assert_eq!(loaded.members.len(), 1);
        assert_eq!(loaded.members[0].vip.as_deref(), Some("100.64.0.9"));
        assert_eq!(loaded.updated_at, 42);
    }

    /// `ensure_member` self-heals a roles.json missing the `member` role (adds it
    /// once with warren reach); idempotent if already present.
    #[test]
    fn ensure_member_seeds_when_missing() {
        // Missing → added with wildcard reach, no sessions.
        let mut store = RolesStore { roles: vec![] };
        assert!(store.ensure_member());
        let m = store.find_role("member").expect("member added");
        assert_eq!(m.host_tags, vec!["*"]);
        assert!(!m.admin && !m.sudo);
        // Already present → no-op (no duplicate).
        assert!(!store.ensure_member());
        assert_eq!(store.roles.iter().filter(|r| r.name == "member").count(), 1);
    }

    /// `warren_member_count` only trusts a snapshot that matches the queried
    /// namespace, and returns the member count (incl. self) — the solo signal
    /// for safe auto-switch.
    #[test]
    fn warren_member_count_is_namespace_scoped() {
        let dir = tempfile::tempdir().unwrap();
        // No snapshot yet → unknown.
        assert_eq!(warren_member_count(dir.path(), "ns-a"), None);
        let member = |id: &str| WarrenMemberInfo {
            node_id: id.into(), name: id.into(), role: "node".into(),
            vip: None, tags: vec![], last_seen: None,
        };
        WarrenSnapshot {
            namespace: Some("ns-a".into()),
            members: vec![member("self")],
            roles: vec![],
            updated_at: 1,
        }
        .save(dir.path())
        .unwrap();
        // Solo warren ns-a → Some(1); a snapshot for ns-a must NOT answer for ns-b.
        assert_eq!(warren_member_count(dir.path(), "ns-a"), Some(1));
        assert_eq!(warren_member_count(dir.path(), "ns-b"), None);
        // Populated warren → Some(n) > 1.
        WarrenSnapshot {
            namespace: Some("ns-a".into()),
            members: vec![member("self"), member("peer")],
            roles: vec![],
            updated_at: 2,
        }
        .save(dir.path())
        .unwrap();
        assert_eq!(warren_member_count(dir.path(), "ns-a"), Some(2));
    }

    /// Helper to build a RoleDefinition with default sandbox for tests.
    fn test_role(name: &str, host_tags: Vec<String>, user_mode: UserMode, sudo: bool, admin: bool, groups: Vec<String>, shell: Option<String>) -> RoleDefinition {
        RoleDefinition {
            name: name.into(),
            host_tags,
            user_mode,
            sudo,
            admin,
            network_only: false,
            groups,
            shell,
            sandbox: SandboxPolicy::default(),
            capabilities: Default::default(),
            exec_tags: vec![],
            search_tags: vec![],
        }
    }

    // --- RolesStore tests ---

    #[test]
    fn roles_store_load_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = RolesStore::load(dir.path()).unwrap();
        assert!(store.roles.is_empty());
    }

    #[test]
    fn roles_store_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = RolesStore {
            roles: vec![
                test_role("developer", vec!["dev".into(), "staging".into()], UserMode::Individual, false, false, vec![], None),
                test_role("ops", vec!["*".into()], UserMode::Individual, true, false, vec!["docker".into()], Some("/bin/bash".into())),
            ],
        };
        store.save(dir.path()).unwrap();

        let loaded = RolesStore::load(dir.path()).unwrap();
        assert_eq!(loaded.roles.len(), 2);
        assert_eq!(loaded.roles[0].name, "developer");
        assert!(loaded.roles[1].sudo);
        assert_eq!(loaded.roles[1].groups, vec!["docker"]);
    }

    #[test]
    fn roles_store_find_role() {
        let store = RolesStore {
            roles: vec![test_role("ci", vec!["build".into()], UserMode::Shared, false, false, vec![], None)],
        };
        assert!(store.find_role("ci").is_some());
        assert_eq!(store.find_role("ci").unwrap().user_mode, UserMode::Shared);
        assert!(store.find_role("nonexistent").is_none());
    }

    // --- FleetStore tests ---

    #[test]
    fn fleet_store_load_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = FleetStore::load(dir.path()).unwrap();
        assert!(store.members.is_empty());
    }

    #[test]
    fn fleet_store_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = FleetStore {
            members: vec![FleetMember {
                node_id: "abc123".into(),
                hostname: "web-1".into(),
                tags: vec!["developer".into(), "web".into()],
                registered_at: "1700000000".into(),
                last_heartbeat: Some("1700001000".into()),
                relay_url: Some("https://relay.example.com".into()),
                online: true,
            }],
        };
        store.save(dir.path()).unwrap();

        let loaded = FleetStore::load(dir.path()).unwrap();
        assert_eq!(loaded.members.len(), 1);
        assert_eq!(loaded.members[0].hostname, "web-1");
        assert_eq!(loaded.members[0].tags, vec!["developer", "web"]);
        assert!(loaded.members[0].online);
    }

    // --- AggregateInvitesStore tests ---

    #[test]
    fn aggregate_invites_store_load_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = AggregateInvitesStore::load(dir.path()).unwrap();
        assert!(store.invites.is_empty());
    }

    #[test]
    fn aggregate_invites_prune_expired() {
        let mut store = AggregateInvitesStore {
            invites: vec![
                AggregateInvite {
                    secret_hash: "old".into(),
                    role: "developer".into(),
                    peer_name: "alice".into(),
                    created_at: 1000,
                },
                AggregateInvite {
                    secret_hash: "recent".into(),
                    role: "ops".into(),
                    peer_name: "bob".into(),
                    created_at: unix_now(),
                },
            ],
        };
        store.prune_expired(60); // 60-second expiry
        assert_eq!(store.invites.len(), 1);
        assert_eq!(store.invites[0].peer_name, "bob");
    }

    // --- Role management handler tests ---

    #[test]
    fn handle_create_role_success() {
        let dir = tempfile::tempdir().unwrap();
        let def = test_role("developer", vec!["dev".into()], UserMode::Individual, false, false, vec![], None);
        let resp = handle_create_role(dir.path(), def);
        match resp {
            AdminResponse::RoleCreated { name } => assert_eq!(name, "developer"),
            other => panic!("expected RoleCreated, got {other:?}"),
        }

        // Verify persisted
        let store = RolesStore::load(dir.path()).unwrap();
        assert_eq!(store.roles.len(), 1);
    }

    #[test]
    fn handle_create_role_duplicate_error() {
        let dir = tempfile::tempdir().unwrap();
        let def = test_role("developer", vec!["dev".into()], UserMode::Individual, false, false, vec![], None);
        handle_create_role(dir.path(), def.clone());
        let resp = handle_create_role(dir.path(), def);
        match resp {
            AdminResponse::Error { message } => assert!(message.contains("already exists")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn handle_list_roles_empty_and_populated() {
        let dir = tempfile::tempdir().unwrap();

        match handle_list_roles(dir.path()) {
            AdminResponse::RoleList { roles } => assert!(roles.is_empty()),
            other => panic!("expected RoleList, got {other:?}"),
        }

        // Add a role
        handle_create_role(
            dir.path(),
            test_role("ops", vec!["*".into()], UserMode::Individual, true, false, vec![], None),
        );

        match handle_list_roles(dir.path()) {
            AdminResponse::RoleList { roles } => {
                assert_eq!(roles.len(), 1);
                assert_eq!(roles[0].name, "ops");
                assert!(roles[0].sudo);
            }
            other => panic!("expected RoleList, got {other:?}"),
        }
    }

    #[test]
    fn handle_update_role_add_tags_and_sudo() {
        let dir = tempfile::tempdir().unwrap();
        handle_create_role(
            dir.path(),
            test_role("developer", vec!["dev".into()], UserMode::Individual, false, false, vec![], None),
        );

        let updates = RoleUpdates {
            add_tags: vec!["staging".into(), "production".into()],
            remove_tags: vec![],
            sudo: Some(true),
            ..Default::default()
        };
        let resp = handle_update_role(dir.path(), "developer", updates);
        match resp {
            AdminResponse::RoleUpdated { name } => assert_eq!(name, "developer"),
            other => panic!("expected RoleUpdated, got {other:?}"),
        }

        let store = RolesStore::load(dir.path()).unwrap();
        let role = store.find_role("developer").unwrap();
        assert_eq!(role.host_tags, vec!["dev", "staging", "production"]);
        assert!(role.sudo);
    }

    #[test]
    fn fleet_invite_tier_recorded_on_host_not_in_token() {
        use crate::invite::{decode_invite, InviteTier, PendingInvitesStore};
        let dir = tempfile::tempdir().unwrap();
        let pk = iroh::SecretKey::from_bytes(&[7u8; 32]).public();
        let make = |tier: Option<&str>| {
            handle_create_fleet_invite(dir.path(), None, &pk, vec![], 0, 3600, tier.map(String::from))
        };
        let tok_of = |resp: AdminResponse| match resp {
            AdminResponse::FleetInviteCreated { token } => decode_invite(&token).unwrap(),
            other => panic!("expected FleetInviteCreated, got {other:?}"),
        };
        let last_entry = || {
            let store = PendingInvitesStore::load(dir.path()).unwrap();
            store.invites.last().cloned().unwrap()
        };

        // Default (no tier) → legacy Creator/admin, recorded on the host.
        let t = tok_of(make(None));
        assert_eq!(t.tier, InviteTier::Admin);
        assert_eq!(last_entry().role, PeerRole::Creator);
        assert_eq!(last_entry().tier, InviteTier::Admin);
        // A warren tier with no warren on the host → error.
        assert!(matches!(make(Some("node")), AdminResponse::Error { .. }));
        // Give the host a warren ticket; warren tiers now work, but the token
        // still carries no ticket: the grant is delivered after auth.
        std::fs::write(dir.path().join("netdoc.ticket"), "dummy-ticket").unwrap();
        std::fs::write(dir.path().join("netdoc-read.ticket"), "dummy-READ-ticket").unwrap();

        let node = tok_of(make(Some("node")));
        assert_eq!(node.tier, InviteTier::Node);
        assert!(node.warren_ticket.is_none());
        assert_eq!(last_entry().role, PeerRole::Peer);
        assert_eq!(crate::invite::grant_for_tier(dir.path(), last_entry().tier).warren_ticket.as_deref(), Some("dummy-READ-ticket"));

        let admin = tok_of(make(Some("admin")));
        assert_eq!(admin.tier, InviteTier::Admin);
        assert!(admin.warren_ticket.is_none());
        assert_eq!(crate::invite::grant_for_tier(dir.path(), last_entry().tier).warren_ticket.as_deref(), Some("dummy-ticket"));

        let client = tok_of(make(Some("client")));
        assert_eq!(client.tier, InviteTier::Client);
        assert!(crate::invite::grant_for_tier(dir.path(), last_entry().tier).warren_ticket.is_none());
    }

    #[test]
    fn handle_update_role_remove_tags() {
        let dir = tempfile::tempdir().unwrap();
        handle_create_role(
            dir.path(),
            test_role("developer", vec!["dev".into(), "staging".into(), "production".into()], UserMode::Individual, false, false, vec![], None),
        );

        let updates = RoleUpdates {
            remove_tags: vec!["production".into()],
            ..Default::default()
        };
        handle_update_role(dir.path(), "developer", updates);

        let store = RolesStore::load(dir.path()).unwrap();
        let role = store.find_role("developer").unwrap();
        assert_eq!(role.host_tags, vec!["dev", "staging"]);
    }

    #[test]
    fn handle_update_nonexistent_role() {
        let dir = tempfile::tempdir().unwrap();
        let resp = handle_update_role(dir.path(), "nonexistent", RoleUpdates::default());
        match resp {
            AdminResponse::Error { message } => assert!(message.contains("not found")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn handle_delete_role_success() {
        let dir = tempfile::tempdir().unwrap();
        handle_create_role(
            dir.path(),
            test_role("temp", vec![], UserMode::Individual, false, false, vec![], None),
        );
        let resp = handle_delete_role(dir.path(), "temp");
        match resp {
            AdminResponse::RoleDeleted { name } => assert_eq!(name, "temp"),
            other => panic!("expected RoleDeleted, got {other:?}"),
        }

        let store = RolesStore::load(dir.path()).unwrap();
        assert!(store.roles.is_empty());
    }

    #[test]
    fn handle_delete_nonexistent_role() {
        let dir = tempfile::tempdir().unwrap();
        let resp = handle_delete_role(dir.path(), "nope");
        match resp {
            AdminResponse::Error { message } => assert!(message.contains("not found")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // --- seed_defaults tests ---

    #[test]
    fn seed_defaults_creates_default_roles() {
        let dir = tempfile::tempdir().unwrap();
        let store = RolesStore::seed_defaults(dir.path()).unwrap();
        assert_eq!(store.roles.len(), 7);
        // Default `member`: reaches the warren mesh (`*`) so a fresh warren works
        // out of the box, but grants no host sessions (not admin, no sudo).
        let member = store.find_role("member").unwrap();
        assert_eq!(member.host_tags, vec!["*"]);
        assert!(!member.admin);
        assert!(!member.sudo);

        // Verify file was written
        assert!(dir.path().join("roles.json").exists());

        // admin role
        let admin = store.find_role("admin").unwrap();
        assert_eq!(admin.host_tags, vec!["*"]);
        assert!(admin.sudo);
        assert!(admin.admin);
        assert_eq!(admin.user_mode, UserMode::Individual);
        assert_eq!(admin.groups, vec!["docker"]);

        // ops role
        let ops = store.find_role("ops").unwrap();
        assert_eq!(ops.host_tags, vec!["*"]);
        assert!(ops.sudo);
        assert!(!ops.admin);
        assert_eq!(ops.groups, vec!["docker"]);

        // developer role
        let dev = store.find_role("developer").unwrap();
        assert_eq!(dev.host_tags, vec!["developer", "staging"]);
        assert!(!dev.sudo);
        assert_eq!(dev.user_mode, UserMode::Individual);

        // security role — audit sandbox preset
        let sec = store.find_role("security").unwrap();
        assert_eq!(sec.host_tags, vec!["production", "staging"]);
        assert!(!sec.sudo);
        assert!(sec.sandbox.read_only);
        assert!(sec.sandbox.no_network);

        // ci role — deploy sandbox preset
        let ci = store.find_role("ci").unwrap();
        assert_eq!(ci.host_tags, vec!["build"]);
        assert!(!ci.sudo);
        assert_eq!(ci.user_mode, UserMode::Shared);
        assert!(!ci.sandbox.read_only);
        assert!(!ci.sandbox.no_network);
        assert!(!ci.sandbox.denied_commands.is_empty()); // deploy preset has denied_commands

        // admin/ops/developer — unrestricted sandbox
        assert!(!admin.sandbox.is_restricted());
        assert!(!ops.sandbox.is_restricted());
        assert!(!dev.sandbox.is_restricted());
    }

    #[test]
    fn seed_defaults_roundtrips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        RolesStore::seed_defaults(dir.path()).unwrap();

        let loaded = RolesStore::load(dir.path()).unwrap();
        assert_eq!(loaded.roles.len(), 7);
        // member is seeded first; named lookups are order-independent.
        assert_eq!(loaded.roles[0].name, "member");
        assert!(loaded.find_role("admin").is_some());
        assert!(loaded.find_role("ci").is_some());
    }

    // --- Fleet admin handler tests ---

    #[test]
    fn handle_list_fleet_empty() {
        let dir = tempfile::tempdir().unwrap();
        match handle_list_fleet(dir.path(), None) {
            AdminResponse::FleetList { members } => assert!(members.is_empty()),
            other => panic!("expected FleetList, got {other:?}"),
        }
    }

    #[test]
    fn handle_list_fleet_with_tag_filter() {
        let dir = tempfile::tempdir().unwrap();
        let store = FleetStore {
            members: vec![
                FleetMember {
                    node_id: "aaa".into(),
                    hostname: "web-1".into(),
                    tags: vec!["web".into(), "developer".into()],
                    registered_at: "0".into(),
                    last_heartbeat: None,
                    relay_url: None,
                    online: true,
                },
                FleetMember {
                    node_id: "bbb".into(),
                    hostname: "db-1".into(),
                    tags: vec!["database".into()],
                    registered_at: "0".into(),
                    last_heartbeat: None,
                    relay_url: None,
                    online: true,
                },
            ],
        };
        store.save(dir.path()).unwrap();

        match handle_list_fleet(dir.path(), Some("web")) {
            AdminResponse::FleetList { members } => {
                assert_eq!(members.len(), 1);
                assert_eq!(members[0].hostname, "web-1");
            }
            other => panic!("expected FleetList, got {other:?}"),
        }

        match handle_list_fleet(dir.path(), None) {
            AdminResponse::FleetList { members } => assert_eq!(members.len(), 2),
            other => panic!("expected FleetList, got {other:?}"),
        }
    }

    #[test]
    fn handle_remove_fleet_member_success_and_failure() {
        let dir = tempfile::tempdir().unwrap();
        let store = FleetStore {
            members: vec![FleetMember {
                node_id: "abc123def".into(),
                hostname: "web-1".into(),
                tags: vec![],
                registered_at: "0".into(),
                last_heartbeat: None,
                relay_url: None,
                online: true,
            }],
        };
        store.save(dir.path()).unwrap();

        match handle_remove_fleet_member(dir.path(), "abc") {
            AdminResponse::FleetMemberRemoved { success } => assert!(success),
            other => panic!("expected FleetMemberRemoved, got {other:?}"),
        }

        // Verify persisted
        let loaded = FleetStore::load(dir.path()).unwrap();
        assert!(loaded.members.is_empty());

        // Remove nonexistent
        match handle_remove_fleet_member(dir.path(), "zzz") {
            AdminResponse::FleetMemberRemoved { success } => assert!(!success),
            other => panic!("expected FleetMemberRemoved, got {other:?}"),
        }
    }

    #[test]
    fn handle_update_fleet_tags() {
        let dir = tempfile::tempdir().unwrap();
        let store = FleetStore {
            members: vec![FleetMember {
                node_id: "abc123".into(),
                hostname: "web-1".into(),
                tags: vec!["old".into()],
                registered_at: "0".into(),
                last_heartbeat: None,
                relay_url: None,
                online: true,
            }],
        };
        store.save(dir.path()).unwrap();

        let resp = super::handle_update_fleet_tags(dir.path(), "abc", vec!["new1".into(), "new2".into()]);
        match resp {
            AdminResponse::FleetTagsUpdated { success } => assert!(success),
            other => panic!("expected FleetTagsUpdated, got {other:?}"),
        }

        let loaded = FleetStore::load(dir.path()).unwrap();
        assert_eq!(loaded.members[0].tags, vec!["new1", "new2"]);
    }

    // --- UserMode serialization ---

    #[test]
    fn user_mode_defaults_to_individual() {
        assert_eq!(UserMode::default(), UserMode::Individual);
    }

    #[test]
    fn user_mode_serialization() {
        let json = serde_json::to_string(&UserMode::Shared).unwrap();
        assert_eq!(json, r#""shared""#);

        let parsed: UserMode = serde_json::from_str(r#""individual""#).unwrap();
        assert_eq!(parsed, UserMode::Individual);
    }

    // --- roles.json is git-committable ---

    #[test]
    fn roles_json_human_readable_format() {
        let dir = tempfile::tempdir().unwrap();
        let store = RolesStore {
            roles: vec![test_role("developer", vec!["developer".into(), "staging".into()], UserMode::Individual, false, false, vec![], None)],
        };
        store.save(dir.path()).unwrap();

        let raw = std::fs::read_to_string(dir.path().join("roles.json")).unwrap();
        // Should be pretty-printed (contains newlines)
        assert!(raw.contains('\n'));
        // Should contain the role name
        assert!(raw.contains("developer"));
    }
}
