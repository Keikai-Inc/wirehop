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

    /// Seed opinionated default roles on first orchestrator startup.
    /// Only call this when roles.json does not yet exist.
    pub fn seed_defaults(config_dir: &Path) -> Result<Self> {
        let store = Self {
            roles: vec![
                // Least-privilege default: in the warren with an address, but
                // default-deny reach (no host tags) until elevated.
                RoleDefinition {
                    name: "member".into(),
                    host_tags: vec![],
                    sudo: false,
                    admin: false,
                    network_only: false,
                    user_mode: UserMode::Individual,
                    groups: vec![],
                    shell: None,
                    sandbox: SandboxPolicy::default(),
                    capabilities: Default::default(),
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
                },
            ],
        };
        store.save(config_dir)?;
        Ok(store)
    }
}

// --- Fleet registration (host side) ---

/// A fleet registration entry (host side) — one per orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetRegistration {
    pub name: String,
    pub orchestrator_node_id: String,
    pub orchestrator_relay_url: Option<String>,
    pub tags: Vec<String>,
    pub registered_at: String,
}

/// Host-side fleet registrations, persisted as `fleet_registrations.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FleetRegistrationsStore {
    pub registrations: Vec<FleetRegistration>,
}

impl FleetRegistrationsStore {
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("fleet_registrations.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            Ok(serde_json::from_str(&data)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, config_dir: &Path) -> Result<()> {
        let path = config_dir.join("fleet_registrations.json");
        let data = serde_json::to_string_pretty(self)?;
        write_shared_file(&path, &data)?;
        Ok(())
    }
}

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
    _max_uses: u32,
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
    let token = match invite::generate_invite_with_role(
        host_public_key,
        config_dir,
        relay_url,
        None,
        None,
        peer_role,
        role_name,
        expiry_secs,
        crate::sandbox::SandboxPolicy::default(),
    ) {
        Ok(t) => t,
        Err(e) => {
            return AdminResponse::Error {
                message: format!("failed to create fleet invite: {e}"),
            };
        }
    };
    // Stamp the explicit tier (+ founder anchor / client-tier warren strip), like
    // `hop invite --tier`. Safe post-generation: the pending-invite store records
    // only the secret/role, not the tier/warren_ticket.
    let token = match tier {
        None => token,
        Some(t) => match stamp_invite_tier(config_dir, &token, t) {
            Ok(s) => s,
            Err(e) => {
                return AdminResponse::Error {
                    message: format!("failed to stamp fleet invite tier: {e}"),
                };
            }
        },
    };
    tracing::info!("Fleet invite created (tier {:?}) with tags: {:?}", tier.map(|t| t.as_str()), tags);
    AdminResponse::FleetInviteCreated { token }
}

/// Stamp an explicit `InviteTier` onto a freshly-generated token: set the tier
/// field, pin the founder author for warren tiers, and strip the warren ticket
/// for the client tier (so it can never self-upgrade). Mirrors `cmd_invite`.
fn stamp_invite_tier(config_dir: &Path, token: &str, tier: crate::invite::InviteTier) -> anyhow::Result<String> {
    use crate::invite::InviteTier;
    let mut decoded = invite::decode_invite(token)?;
    decoded.tier = tier;
    if tier == InviteTier::Client {
        decoded.warren_ticket = None;
        decoded.founder_author = None;
    } else {
        // Founder author: persisted (federated node) or in the host's creator_invite.
        decoded.founder_author = std::fs::read_to_string(config_dir.join("netdoc-founder.author"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                std::fs::read_to_string(config_dir.join("creator_invite"))
                    .ok()
                    .and_then(|ci| invite::decode_invite(ci.trim()).ok())
                    .and_then(|t| t.founder_author)
            });
        // #3b Phase 4 — ticket scope follows the tier: node/warren-only carry the
        // READ ticket; only admin keeps write. Legacy fallback when absent.
        if matches!(tier, InviteTier::Node | InviteTier::WarrenOnly)
            && let Ok(rt) = std::fs::read_to_string(config_dir.join("netdoc-read.ticket"))
        {
            let rt = rt.trim().to_string();
            if !rt.is_empty() {
                decoded.warren_ticket = Some(rt);
            }
        }
    }
    invite::encode_invite(&decoded)
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

    // --- FleetRegistrationsStore tests ---

    #[test]
    fn fleet_registrations_store_load_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = FleetRegistrationsStore::load(dir.path()).unwrap();
        assert!(store.registrations.is_empty());
    }

    #[test]
    fn fleet_registrations_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = FleetRegistrationsStore {
            registrations: vec![FleetRegistration {
                name: "acme-corp".into(),
                orchestrator_node_id: "orch123".into(),
                orchestrator_relay_url: Some("https://relay.example.com".into()),
                tags: vec!["developer".into()],
                registered_at: "1700000000".into(),
            }],
        };
        store.save(dir.path()).unwrap();

        let loaded = FleetRegistrationsStore::load(dir.path()).unwrap();
        assert_eq!(loaded.registrations.len(), 1);
        assert_eq!(loaded.registrations[0].name, "acme-corp");
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
    fn fleet_invite_tier_stamping() {
        use crate::invite::{decode_invite, InviteTier};
        let dir = tempfile::tempdir().unwrap();
        let pk = iroh::SecretKey::from_bytes(&[7u8; 32]).public();
        let make = |tier: Option<&str>| {
            handle_create_fleet_invite(dir.path(), None, &pk, vec![], 0, 3600, tier.map(String::from))
        };
        let tok_of = |resp: AdminResponse| match resp {
            AdminResponse::FleetInviteCreated { token } => decode_invite(&token).unwrap(),
            other => panic!("expected FleetInviteCreated, got {other:?}"),
        };

        // Default (no tier) → legacy Creator/admin.
        assert_eq!(tok_of(make(None)).role, PeerRole::Creator);
        // A warren tier with no warren on the host → error.
        assert!(matches!(make(Some("node")), AdminResponse::Error { .. }));
        // Give the host a warren ticket; warren tiers now work.
        std::fs::write(dir.path().join("netdoc.ticket"), "dummy-ticket").unwrap();

        let node = tok_of(make(Some("node")));
        assert_eq!(node.tier, InviteTier::Node);
        assert_eq!(node.role, PeerRole::Peer);
        assert!(node.warren_ticket.is_some());

        let admin = tok_of(make(Some("admin")));
        assert_eq!(admin.tier, InviteTier::Admin);
        assert_eq!(admin.role, PeerRole::Creator);

        let warren_only = tok_of(make(Some("warren-only")));
        assert_eq!(warren_only.tier, InviteTier::WarrenOnly);
        assert_eq!(warren_only.role_name.as_deref(), Some("warren-only"));

        // Client tier strips the warren ticket (can't self-upgrade).
        let client = tok_of(make(Some("client")));
        assert!(client.warren_ticket.is_none());

        // Unknown tier → error.
        assert!(matches!(make(Some("bogus")), AdminResponse::Error { .. }));

        // #3b Phase 4 — once a READ ticket is persisted, node/warren-only carry
        // it (read scope); admin keeps the write ticket.
        std::fs::write(dir.path().join("netdoc-read.ticket"), "dummy-READ-ticket").unwrap();
        assert_eq!(
            tok_of(make(Some("node"))).warren_ticket.as_deref(),
            Some("dummy-READ-ticket"),
            "node tier must carry the read ticket"
        );
        assert_eq!(
            tok_of(make(Some("warren-only"))).warren_ticket.as_deref(),
            Some("dummy-READ-ticket"),
            "warren-only tier must carry the read ticket"
        );
        assert_eq!(
            tok_of(make(Some("admin"))).warren_ticket.as_deref(),
            Some("dummy-ticket"),
            "admin tier keeps the WRITE ticket"
        );
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
        // Least-privilege default exists with no reach.
        let member = store.find_role("member").unwrap();
        assert!(member.host_tags.is_empty());
        assert!(!member.admin);

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
