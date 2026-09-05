//! Admin request handler for creator peers.
//!
//! Handles remote administration: invite creation, peer management,
//! Unix user creation, fleet management, and role management.

use anyhow::Result;
use iroh::PublicKey;
use std::path::Path;

use crate::config::{PeerRole, PeersStore};
use crate::datastore::Datastore;
use crate::invite;
use crate::proto::{AdminRequest, AdminResponse, PeerInfo};

pub use crate::proto::{AdminRequest as Request, AdminResponse as Response};

/// The FULL node-id a `RemovePeer` request will remove (resolving its prefix
/// against `peers.json`), captured BEFORE the removal so the caller can write an
/// explicit netdoc revocation tombstone afterward (reconcile alone skips removals
/// in a federated namespace). `None` for any non-removal request.
pub fn removed_peer_full_id(config_dir: &Path, request: &AdminRequest) -> Option<String> {
    let AdminRequest::RemovePeer { node_id_prefix } = request else {
        return None;
    };
    let store = PeersStore::load(config_dir).ok()?;
    store
        .peers
        .iter()
        .find(|p| p.node_id.starts_with(node_id_prefix.as_str()))
        .map(|p| p.node_id.clone())
}

/// Handle an admin request from a creator peer.
///
/// Caller must verify the peer has Creator role before calling this.
/// `datastore` is passed by the daemon to avoid opening redundant handles.
pub fn handle_admin_request(
    request: AdminRequest,
    config_dir: &Path,
    relay_url: Option<&str>,
    host_public_key: &PublicKey,
    datastore: Option<&Datastore>,
) -> AdminResponse {
    match request {
        AdminRequest::CreateInvite { username, role, role_name } => {
            handle_create_invite(config_dir, relay_url, host_public_key, username, role, role_name)
        }
        AdminRequest::CreateInviteFull(params) => {
            match crate::invite::build_invite_token(host_public_key, config_dir, relay_url, &params) {
                Ok(token) => AdminResponse::InviteCreated { token },
                Err(e) => AdminResponse::Error { message: format!("{e:#}") },
            }
        }
        AdminRequest::HostIdentity => AdminResponse::HostIdentity {
            node_id: host_public_key.to_string(),
        },
        // Served asynchronously by the daemon socket (needs the registry actor).
        AdminRequest::ListSessions => AdminResponse::Error {
            message: "session listing is served by the daemon socket".to_string(),
        },
        AdminRequest::ListInvites => match invite::PendingInvitesStore::load(config_dir) {
            Ok(mut store) => {
                store.prune_expired(15 * 60);
                AdminResponse::InviteList { invites: store.list(15 * 60) }
            }
            Err(e) => AdminResponse::Error { message: format!("{e:#}") },
        },
        AdminRequest::RevokeInvite { id } => match invite::PendingInvitesStore::load(config_dir) {
            Ok(mut store) => match store.revoke(&id) {
                Ok(full) => match store.save(config_dir) {
                    Ok(()) => {
                        log_admin_action(config_dir, "revoke_invite", &full);
                        AdminResponse::InviteRevoked { id: full }
                    }
                    Err(e) => AdminResponse::Error { message: format!("{e:#}") },
                },
                Err(e) => AdminResponse::Error { message: format!("{e:#}") },
            },
            Err(e) => AdminResponse::Error { message: format!("{e:#}") },
        },
        AdminRequest::ListPeers => handle_list_peers(config_dir),
        AdminRequest::RemovePeer { node_id_prefix } => {
            handle_remove_peer(config_dir, &node_id_prefix)
        }
        AdminRequest::RenamePeer { node_id_prefix, name } => {
            handle_rename_peer(config_dir, &node_id_prefix, name)
        }
        // Prune needs async netdoc + VPN-liveness access, so the daemon socket
        // intercepts it before this sync dispatch. Reaching here means no warren.
        AdminRequest::PruneMembers { .. } => AdminResponse::Error {
            message: "prune requires the warren netdoc (handled by the daemon socket)".to_string(),
        },
        AdminRequest::SetPeerRole { node_id_prefix, role_name } => {
            handle_set_peer_role(config_dir, &node_id_prefix, &role_name)
        }
        AdminRequest::CreateUser {
            username,
            sudo,
            admin,
            groups,
            shell,
            invite: create_invite,
        } => handle_create_user(
            config_dir,
            relay_url,
            host_public_key,
            &username,
            sudo,
            admin,
            &groups,
            shell.as_deref(),
            create_invite,
        ),
        AdminRequest::Status => handle_status(config_dir),
        // Fleet admin (Phase 2)
        AdminRequest::CreateFleetInvite { tags, max_uses, expiry_secs, tier } => {
            crate::fleet::handle_create_fleet_invite(config_dir, relay_url, host_public_key, tags, max_uses, expiry_secs, tier)
        }
        AdminRequest::ListFleet { tag_filter } => {
            crate::fleet::handle_list_fleet(config_dir, tag_filter.as_deref())
        }
        AdminRequest::RemoveFleetMember { node_id_prefix } => {
            crate::fleet::handle_remove_fleet_member(config_dir, &node_id_prefix)
        }
        AdminRequest::UpdateFleetTags { node_id_prefix, tags } => {
            crate::fleet::handle_update_fleet_tags(config_dir, &node_id_prefix, tags)
        }
        // Role management (Phase 2)
        AdminRequest::CreateRole { definition } => {
            crate::fleet::handle_create_role(config_dir, definition)
        }
        AdminRequest::ListRoles => crate::fleet::handle_list_roles(config_dir),
        AdminRequest::UpdateRole { name, updates } => {
            crate::fleet::handle_update_role(config_dir, &name, updates)
        }
        AdminRequest::DeleteRole { name } => {
            crate::fleet::handle_delete_role(config_dir, &name)
        }
        // Aggregate invite (Phase 3)
        AdminRequest::CreateAggregateInvite { role, peer_name } => {
            crate::fleet::handle_create_aggregate_invite(config_dir, relay_url, host_public_key, &role, &peer_name)
        }
        AdminRequest::RedeemAggregateInvite { secret } => {
            crate::fleet::handle_redeem_aggregate_invite(config_dir, relay_url, host_public_key, &secret)
        }
        AdminRequest::PushMetrics { points } => {
            handle_push_metrics(datastore, points)
        }
    }
}

fn handle_push_metrics(datastore: Option<&Datastore>, points: Vec<crate::proto::PushMetricPoint>) -> AdminResponse {
    let ds = match datastore {
        Some(ds) => ds,
        None => {
            return AdminResponse::Error {
                message: "datastore not available".to_string(),
            }
        }
    };

    let mut count = 0;
    for point in &points {
        let metric_point = crate::datastore::types::MetricPoint {
            value: point.value,
            tags: point.tags.clone(),
        };
        if let Some(ts) = point.timestamp {
            if let Err(e) = ds.ts_insert_at(&point.metric, ts, &metric_point) {
                tracing::warn!("Failed to insert metric {}: {e}", point.metric);
                continue;
            }
        } else if let Err(e) = ds.ts_insert(&point.metric, &metric_point) {
            tracing::warn!("Failed to insert metric {}: {e}", point.metric);
            continue;
        }
        count += 1;
    }

    AdminResponse::MetricsReceived { count }
}

fn handle_create_invite(
    config_dir: &Path,
    relay_url: Option<&str>,
    host_public_key: &PublicKey,
    username: Option<String>,
    role: PeerRole,
    role_name: Option<String>,
) -> AdminResponse {
    let expiry_secs = match role {
        PeerRole::Creator => 3600,  // 1 hour for creator invites
        PeerRole::Peer => 15 * 60, // 15 minutes for regular
    };
    match invite::generate_invite_with_role(
        host_public_key,
        config_dir,
        relay_url,
        username.as_deref(),
        None,
        role,
        role_name,
        expiry_secs,
        crate::sandbox::SandboxPolicy::default(),
        None, // single-use
    ) {
        Ok(token) => {
            log_admin_action(config_dir, "create_invite", &format!("user={:?}", username));
            AdminResponse::InviteCreated { token }
        }
        Err(e) => AdminResponse::Error {
            message: format!("failed to create invite: {e}"),
        },
    }
}

fn handle_list_peers(config_dir: &Path) -> AdminResponse {
    match PeersStore::load(config_dir) {
        Ok(store) => {
            let peers = store
                .peers
                .iter()
                .map(|p| PeerInfo {
                    node_id: p.node_id.clone(),
                    name: p.name.clone(),
                    role: p.role.clone(),
                    username: p.username.clone(),
                    last_seen: p.last_seen.clone(),
                })
                .collect();
            AdminResponse::PeerList { peers }
        }
        Err(e) => AdminResponse::Error {
            message: format!("failed to load peers: {e}"),
        },
    }
}

fn handle_set_peer_role(config_dir: &Path, node_id_prefix: &str, role_name: &str) -> AdminResponse {
    match PeersStore::load(config_dir) {
        Ok(mut store) => {
            let mut found = false;
            for p in store.peers.iter_mut().filter(|p| p.node_id.starts_with(node_id_prefix)) {
                p.role_name = Some(role_name.to_string());
                found = true;
            }
            if found {
                if let Err(e) = store.save(config_dir) {
                    return AdminResponse::Error { message: format!("updated but failed to save: {e}") };
                }
                log_admin_action(config_dir, "set_peer_role", &format!("{node_id_prefix} -> {role_name}"));
            }
            // The post-admin reconcile hook mirrors the change into the document,
            // which re-resolves role-derived reach network-wide.
            AdminResponse::PeerRoleUpdated { success: found }
        }
        Err(e) => AdminResponse::Error { message: format!("failed to load peers: {e}") },
    }
}

fn handle_rename_peer(config_dir: &Path, node_id_prefix: &str, name: String) -> AdminResponse {
    match PeersStore::load(config_dir) {
        Ok(mut store) => {
            let success = store.rename_peer(node_id_prefix, name);
            if success
                && let Err(e) = store.save(config_dir)
            {
                return AdminResponse::Error { message: format!("renamed but failed to save: {e}") };
            }
            AdminResponse::PeerRenamed { success }
        }
        Err(e) => AdminResponse::Error { message: format!("failed to load peers: {e}") },
    }
}

/// The FULL node-id of a peer whose entry was changed IN PLACE (role grant or
/// rename) — resolving the request's prefix. `reconcile` only ADDS missing peers,
/// so the caller must `put_peer` this entry to push the updated role/name into the
/// doc (else the change never shows in another node's `hop fleet list`). `None`
/// for requests that don't modify an existing peer entry.
pub fn upserted_peer_full_id(config_dir: &Path, request: &AdminRequest) -> Option<String> {
    let prefix = match request {
        AdminRequest::RenamePeer { node_id_prefix, .. } => node_id_prefix,
        AdminRequest::SetPeerRole { node_id_prefix, .. } => node_id_prefix,
        _ => return None,
    };
    let store = PeersStore::load(config_dir).ok()?;
    store
        .peers
        .iter()
        .find(|p| p.node_id.starts_with(prefix.as_str()))
        .map(|p| p.node_id.clone())
}

fn handle_remove_peer(config_dir: &Path, node_id_prefix: &str) -> AdminResponse {
    match PeersStore::load(config_dir) {
        Ok(mut store) => {
            let success = store.remove_peer(node_id_prefix);
            if success {
                if let Err(e) = store.save(config_dir) {
                    return AdminResponse::Error {
                        message: format!("removed but failed to save: {e}"),
                    };
                }
                log_admin_action(config_dir, "remove_peer", node_id_prefix);
            }
            AdminResponse::PeerRemoved { success }
        }
        Err(e) => AdminResponse::Error {
            message: format!("failed to load peers: {e}"),
        },
    }
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn handle_create_user(
    config_dir: &Path,
    relay_url: Option<&str>,
    host_public_key: &PublicKey,
    username: &str,
    sudo: bool,
    admin: bool,
    groups: &[String],
    shell: Option<&str>,
    create_invite: bool,
) -> AdminResponse {
    // Validate username format (but don't check existence — we're creating it)
    if username.is_empty() || username.len() > 32 {
        return AdminResponse::Error {
            message: format!("invalid username: must be 1-32 characters, got {}", username.len()),
        };
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return AdminResponse::Error {
            message: format!("invalid username '{username}': only [a-zA-Z0-9_-] allowed"),
        };
    }

    // Create the Unix user
    if let Err(e) = create_unix_user(username, sudo, admin, groups, shell) {
        return AdminResponse::Error {
            message: format!("failed to create user: {e}"),
        };
    }

    log_admin_action(config_dir, "create_user", &format!("{username} sudo={sudo} admin={admin}"));

    // Optionally create an invite for this user
    let invite_token = if create_invite {
        match invite::generate_invite_with_role(
            host_public_key,
            config_dir,
            relay_url,
            Some(username),
            None,
            PeerRole::Peer,
            None,
            15 * 60,
            crate::sandbox::SandboxPolicy::default(),
            None, // single-use
        ) {
            Ok(token) => Some(token),
            Err(e) => {
                return AdminResponse::Error {
                    message: format!("user created but invite failed: {e}"),
                };
            }
        }
    } else {
        None
    };

    AdminResponse::UserCreated {
        username: username.to_string(),
        invite_token,
    }
}

#[cfg(not(unix))]
fn handle_create_user(
    _config_dir: &Path,
    _relay_url: Option<&str>,
    _host_public_key: &PublicKey,
    _username: &str,
    _sudo: bool,
    _admin: bool,
    _groups: &[String],
    _shell: Option<&str>,
    _create_invite: bool,
) -> AdminResponse {
    AdminResponse::Error {
        message: "user creation is only supported on Unix".to_string(),
    }
}

/// Create a Unix user on the current system.
#[cfg(unix)]
fn create_unix_user(
    username: &str,
    sudo: bool,
    admin: bool,
    groups: &[String],
    shell: Option<&str>,
) -> Result<()> {
    use std::process::Command;

    // Check if user already exists
    if crate::unix_user::user_exists(username) {
        tracing::info!("User '{username}' already exists, skipping creation");
        return Ok(());
    }

    if cfg!(target_os = "macos") {
        create_user_macos(username, admin, shell)?;
    } else {
        create_user_linux(username, groups, shell)?;
    }

    // Handle sudo access
    if sudo {
        if cfg!(target_os = "macos") {
            // On macOS, admin group members can sudo by default.
            // If not already admin, add to admin group.
            if !admin {
                let status = Command::new("dseditgroup")
                    .args(["-o", "edit", "-a", username, "-t", "user", "admin"])
                    .status()?;
                if !status.success() {
                    anyhow::bail!("failed to add {username} to admin group for sudo");
                }
            }
        } else {
            // Linux: add to sudo/wheel group
            let sudo_group = if Path::new("/etc/debian_version").exists() {
                "sudo"
            } else {
                "wheel"
            };
            let status = Command::new("usermod")
                .args(["-aG", sudo_group, username])
                .status()?;
            if !status.success() {
                anyhow::bail!("failed to add {username} to {sudo_group} group");
            }
        }
    }

    // Add extra groups on Linux (macOS groups handled separately)
    if !cfg!(target_os = "macos") && !groups.is_empty() {
        let groups_str = groups.join(",");
        let status = Command::new("usermod")
            .args(["-aG", &groups_str, username])
            .status()?;
        if !status.success() {
            tracing::warn!("failed to add {username} to groups: {groups_str}");
        }
    }

    tracing::info!("Created Unix user '{username}'");
    Ok(())
}

#[cfg(target_os = "macos")]
fn create_user_macos(username: &str, admin: bool, shell: Option<&str>) -> Result<()> {
    use std::process::Command;

    let default_shell = shell.unwrap_or("/bin/zsh");
    let mut cmd = Command::new("sysadminctl");
    cmd.args([
        "-addUser",
        username,
        "-fullName",
        username,
        "-shell",
        default_shell,
        "-home",
        &format!("/Users/{username}"),
    ]);

    if admin {
        cmd.arg("-admin");
    }

    let output = cmd.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("sysadminctl failed: {stderr}");
    }

    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn create_user_macos(_username: &str, _admin: bool, _shell: Option<&str>) -> Result<()> {
    unreachable!("macOS user creation called on non-macOS");
}

#[cfg(unix)]
fn create_user_linux(username: &str, groups: &[String], shell: Option<&str>) -> Result<()> {
    use std::process::Command;

    let default_shell = shell.unwrap_or("/bin/bash");
    let mut cmd = Command::new("useradd");
    cmd.args(["-m", "-s", default_shell]);

    if !groups.is_empty() {
        cmd.args(["-G", &groups.join(",")]);
    }

    cmd.arg(username);

    let output = cmd.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("useradd failed: {stderr}");
    }

    Ok(())
}

fn handle_status(config_dir: &Path) -> AdminResponse {
    let peer_count = PeersStore::load(config_dir)
        .map(|s| s.peers.len())
        .unwrap_or(0);

    AdminResponse::HostStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        peer_count,
        active_sessions: 0, // TODO: wire up session registry
    }
}

/// Append an entry to admin_log.json for audit trail.
fn log_admin_action(config_dir: &Path, action: &str, details: &str) {
    let path = config_dir.join("admin_log.json");
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Serialize with serde_json so `action`/`details` (which can contain
    // attacker-influenced role names or node-id fragments) are properly escaped
    // — raw interpolation allowed `"`/`\` to forge or inject log entries
    // (security-audit M8).
    let entry = match serde_json::to_string(&serde_json::json!({
        "timestamp": timestamp,
        "action": action,
        "details": details,
    })) {
        Ok(mut s) => {
            s.push('\n');
            s
        }
        Err(_) => return,
    };
    // Best-effort append
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = file.write_all(entry.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::AdminRequest;

    fn test_key() -> (iroh::SecretKey, PublicKey) {
        let key = iroh::SecretKey::from_bytes(&[10u8; 32]);
        let public = key.public();
        (key, public)
    }

    #[test]
    fn handle_create_invite_peer() {
        let dir = tempfile::tempdir().unwrap();
        let (_key, public) = test_key();

        // Don't specify a username — username validation checks the system user database,
        // so specifying a non-existent user would fail in tests.
        let resp = handle_admin_request(
            AdminRequest::CreateInvite {
                username: None,
                role: PeerRole::Peer,
                role_name: None,
            },
            dir.path(),
            None,
            &public,
            None,
        );

        match resp {
            AdminResponse::InviteCreated { token } => {
                let decoded = crate::invite::decode_invite(&token).unwrap();
                assert_eq!(decoded.role, PeerRole::Peer);
                assert_eq!(decoded.username, None);
            }
            other => panic!("expected InviteCreated, got {other:?}"),
        }
    }

    #[test]
    fn handle_create_invite_creator() {
        let dir = tempfile::tempdir().unwrap();
        let (_key, public) = test_key();

        let resp = handle_admin_request(
            AdminRequest::CreateInvite {
                username: None,
                role: PeerRole::Creator,
                role_name: None,
            },
            dir.path(),
            Some("https://relay.example.com"),
            &public,
            None,
        );

        match resp {
            AdminResponse::InviteCreated { token } => {
                let decoded = crate::invite::decode_invite(&token).unwrap();
                // The role is recorded with the pending invite, never in the token.
                assert_eq!(decoded.role, PeerRole::Peer);
                assert!(decoded.warren_ticket.is_none());
                let store = crate::invite::PendingInvitesStore::load(dir.path()).unwrap();
                assert_eq!(store.invites[0].role, PeerRole::Creator);
                assert_eq!(decoded.relay_url.as_deref(), Some("https://relay.example.com"));
            }
            other => panic!("expected InviteCreated, got {other:?}"),
        }
    }

    #[test]
    fn handle_list_peers_empty() {
        let dir = tempfile::tempdir().unwrap();
        let (_key, public) = test_key();

        let resp = handle_admin_request(AdminRequest::ListPeers, dir.path(), None, &public, None);
        match resp {
            AdminResponse::PeerList { peers } => assert!(peers.is_empty()),
            other => panic!("expected PeerList, got {other:?}"),
        }
    }

    #[test]
    fn handle_list_peers_with_entries() {
        let dir = tempfile::tempdir().unwrap();
        let (_key, public) = test_key();

        let key2 = iroh::SecretKey::from_bytes(&[11u8; 32]);
        let mut store = PeersStore::default();
        store.add_peer(&key2.public(), "alice".into(), Some("alice".into()), PeerRole::Creator, crate::sandbox::SandboxPolicy::default());
        store.save(dir.path()).unwrap();

        let resp = handle_admin_request(AdminRequest::ListPeers, dir.path(), None, &public, None);
        match resp {
            AdminResponse::PeerList { peers } => {
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].name, "alice");
                assert_eq!(peers[0].role, PeerRole::Creator);
            }
            other => panic!("expected PeerList, got {other:?}"),
        }
    }

    #[test]
    fn handle_remove_peer_success() {
        let dir = tempfile::tempdir().unwrap();
        let (_key, public) = test_key();

        let key2 = iroh::SecretKey::from_bytes(&[12u8; 32]);
        let peer_id = key2.public().to_string();
        let mut store = PeersStore::default();
        store.add_peer(&key2.public(), "bob".into(), None, PeerRole::Peer, crate::sandbox::SandboxPolicy::default());
        store.save(dir.path()).unwrap();

        let resp = handle_admin_request(
            AdminRequest::RemovePeer {
                node_id_prefix: peer_id[..10].to_string(),
            },
            dir.path(),
            None,
            &public,
            None,
        );
        match resp {
            AdminResponse::PeerRemoved { success } => assert!(success),
            other => panic!("expected PeerRemoved, got {other:?}"),
        }

        let loaded = PeersStore::load(dir.path()).unwrap();
        assert!(loaded.peers.is_empty());
    }

    #[test]
    fn handle_remove_peer_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let (_key, public) = test_key();

        let resp = handle_admin_request(
            AdminRequest::RemovePeer {
                node_id_prefix: "nonexistent".into(),
            },
            dir.path(),
            None,
            &public,
            None,
        );
        match resp {
            AdminResponse::PeerRemoved { success } => assert!(!success),
            other => panic!("expected PeerRemoved, got {other:?}"),
        }
    }

    #[test]
    fn handle_status() {
        let dir = tempfile::tempdir().unwrap();
        let (_key, public) = test_key();

        let resp = handle_admin_request(AdminRequest::Status, dir.path(), None, &public, None);
        match resp {
            AdminResponse::HostStatus {
                version,
                peer_count,
                active_sessions,
            } => {
                assert!(!version.is_empty());
                assert_eq!(peer_count, 0);
                assert_eq!(active_sessions, 0);
            }
            other => panic!("expected HostStatus, got {other:?}"),
        }
    }

    #[test]
    fn admin_log_created_on_actions() {
        let dir = tempfile::tempdir().unwrap();
        let (_key, public) = test_key();

        // Create an invite to trigger logging
        handle_admin_request(
            AdminRequest::CreateInvite {
                username: None,
                role: PeerRole::Creator,
                role_name: None,
            },
            dir.path(),
            None,
            &public,
            None,
        );

        let log_path = dir.path().join("admin_log.json");
        assert!(log_path.exists());
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("create_invite"));
    }

    #[test]
    fn handle_admin_request_routes_to_fleet() {
        let dir = tempfile::tempdir().unwrap();
        let (_key, public) = test_key();

        // ListFleet should work on empty store
        let resp = handle_admin_request(
            AdminRequest::ListFleet { tag_filter: None },
            dir.path(),
            None,
            &public,
            None,
        );
        match resp {
            AdminResponse::FleetList { members } => assert!(members.is_empty()),
            other => panic!("expected FleetList, got {other:?}"),
        }

        // ListRoles should work on empty store
        let resp = handle_admin_request(AdminRequest::ListRoles, dir.path(), None, &public, None);
        match resp {
            AdminResponse::RoleList { roles } => assert!(roles.is_empty()),
            other => panic!("expected RoleList, got {other:?}"),
        }
    }
}
