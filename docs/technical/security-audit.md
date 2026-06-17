# Security & Code-Health Audit — 2026-06-03

A source-level audit of hop (v0.6.36) across five areas: auth/invite/secrets,
warren/VPN/ACL, sandbox/transfer/exec/MCP, installers/release/ops, and
vestigial/dead code. Every finding cites `file:line` and a fix. **This is a
working report to act on**, not a sign-off.

> **Status:** the findings below describe the state at audit time (v0.6.36). Most
> were remediated in **v0.6.37** — see [Remediation status](#remediation-status--v0637-2026-06-03)
> at the end for exactly what shipped and what was deliberately **deferred** (C1
> write-authorization, H8 secrets KDF, H10 root redeem) with the reasoning.

> **Headline.** The cryptographic transport (iroh/QUIC, node-key auth), the
> invite primitives (CSPRNG secret, constant-time Argon2, atomic single-use), and
> the Cedar policy engine are sound *in isolation*. The serious problems are in
> the **trust model around them**, and they matter more because the warren VPN is
> **default-on** (`crates/hop-cli/src/main.rs:424`), despite module docs still
> calling it "experimental / opt-in." Two architectural flaws dominate and should
> gate any default-on posture.

## P0 — Critical (fix before the VPN stays default-on)

### C1. Every invite embeds a **write-capable** warren ticket → any member can rewrite the whole warren
*Flagged independently by the warren and installer audits.*
- `crates/hop-core/src/netdoc/mod.rs` (`write_ticket` = `ShareMode::Write`), embedded into every invite by `crates/hop-core/src/invite/mod.rs` (reads `<config>/netdoc.ticket`), redeemed by `hop warren join` (`crates/hop-cli/src/main.rs` ~4098-4141).
- iroh-docs write capability is **namespace-wide** — there is no per-key/per-author ACL on the CRDT. So **any** joined member can `put_peer` (self-promote to `role_name:"admin"`), `put_role`, `revoke`/tombstone any peer (DoS/eviction), `set_authored_policy` (author a Cedar `permit` granting itself universal reach), `register_host_tags` (re-tag a target to a tag it reaches), and overwrite `ip/`/`vpn/`/`name/` claims. The Cedar engine faithfully evaluates attacker-controlled inputs. **Per-invite role/sandbox auth is meaningless at the doc layer.**
- **Fix:** embed the **read** ticket (`read_ticket()` already exists but is never used) in member invites; gate write/federation behind an explicit, separately-authorized admin step; validate per-entry author capability on read (reject `acl/*`, `role/*`, `peer/*` not authored by an admin key). This is the root trust fix and is the prerequisite for C-series #2/#3 below to mean anything.

### C2. VPN data plane has **no ingress authentication**; source-vIP is spoofable → ACL bypass + impersonation
- `crates/hop-core/src/vpn/mod.rs` `VpnInbound::accept` writes any received datagram straight to the TUN with **no check** of `conn.remote_node_id()`, the source vIP, or the destination. Reach (`vpn_reach_allowed`, `netdoc/mod.rs`) is enforced **only on the sender**, keyed on the packet's self-declared source IPv4 (`parse_src_ipv4`, bytes 12-16).
- A malicious member crafts a packet with `src = <victim/admin vIP>` — its own sender check passes (it controls its daemon), and the receiver injects it into the local TUN with a spoofed trusted source. Full ACL bypass + source impersonation to local services. The receiver also applies no `is_virtual_addr`/ownership/dst filtering on ingress.
- **Fix:** enforce on **receive**. In `accept`, resolve `conn.remote_node_id()` → its authorized vIP, drop datagrams whose `parse_src_ipv4` ≠ that vIP; verify `dst` is the local host's vIP; re-run `vpn_reach_allowed(src, dst, port)` on ingress (defense in depth).

### C3. File transfer (`hop cp`/`sync`) bypasses the sandbox **entirely**
- `crates/hop-core/src/transfer/mod.rs` `host_transfer_session` takes `username` + `protocol_version` but **no `SandboxPolicy`**; `RequestTransfer` is dispatched (`crates/hop-cli/src/main.rs` ~902) without merging the peer's stored policy; `resolve_host_path` accepts any absolute `remote_path` with no `allowed_paths`/`read_only` check.
- A peer pinned to `monitor`/`audit` (read-only, scoped) can read **any** file the bound user can read (`~/.ssh/id_rsa`) and **write/delete any path** (`sync --delete`). Nullifies read-only + path-scope for every restricted peer.
- **Fix:** thread the merged effective `SandboxPolicy` into `host_transfer_session`; reject writes when `read_only`; validate canonicalized `base_path` ⊆ `allowed_paths` for both read and write.

### C4. MCP JS `readFile`/`writeFile` ignore the sandbox; `hop.http` is an SSRF
- `crates/hop-mcp/src/js/bindings.rs:105-125` — `hop.readFile`/`hop.writeFile` call `std::fs` on arbitrary absolute paths inside the un-sandboxed QuickJS process, regardless of `read_only`/`allowed_paths` (asymmetry: `hop.local` *does* honor the policy).
- `crates/hop-mcp/src/js/bindings.rs:782-847` — `hop.http` gates only on `no_network`; when network is allowed it reaches **any** URL incl. `http://169.254.169.254/...` (cloud IMDS → IAM credential theft), loopback, RFC1918; `reqwest::blocking` follows redirects by default (an allowlisted URL can 302 into IMDS).
- **Fix:** gate `readFile`/`writeFile` on the policy (or route through the sandboxed mechanism); for `hop.http`, reject loopback/link-local/private/IMDS ranges, restrict to http/https, disable or re-validate redirects.

## P1 — High

| # | Location | Issue | Fix |
|---|---|---|---|
| H1 | `netdoc/mod.rs` `claim_virtual_ip` / `register_vpn_endpoint` / `register_name` | Any member can overwrite another node's `ip/`/`vpn/`/`name/` entry → traffic interception (point `vpn/<victim>` at self), MagicDNS spoofing, vIP theft. LWW tie-break only resolves honest races. | Bind these keys to the owning author/node identity; reject replicated updates whose author ≠ claimed node. |
| H2 | `netdoc/mod.rs` `register_posture` + `enable_vpn` self-admin | Posture (`os`/`version`) is self-attested → a node lies (`os:"linux"`) to satisfy posture-gated `permit`s. Owner vs member boundary is the locally-controlled `federated` bool in `netdoc.json`. | Cryptographic posture attestation; derive admin from an owner-signed record, not a local flag. |
| H3 | `netdoc/mod.rs:119-126` reach cache | `invalidate_reach_cache` fires only on **local** writes; a revocation/ACL-tightening arriving via **replication** isn't applied until the 3s TTL lapses (plus unbounded gossip latency). Revoked peer still reachable in the window. | Subscribe to doc change events; invalidate on any reach-affecting replicated key; document the revocation SLA. |
| H4 | `sandbox/macos.rs:67-74` | SBPL profile injection: `allowed_paths` interpolated into the Scheme profile unescaped, and `merge_stricter` takes the **client's** `allowed_paths` when the host list is empty → a crafted path with `")` can append arbitrary SBPL rules = sandbox escape. | Reject paths with `"`/`\`/newline (or escape) before emitting; validate path shapes. |
| H5 | `sandbox/linux.rs:20-130` | `no_network` is **silently unenforced** on Linux (no seccomp/netns/Landlock-net); the module doc falsely advertises "seccomp-BPF". `monitor`/`audit` give zero network isolation. | Landlock ABI≥4 net rules and/or a seccomp `socket()` filter, or a netns; at minimum fail-closed + document. |
| H6 | `sandbox/linux.rs:25-27,120` | Landlock failures are non-fatal (`let _ =`, warn-and-continue); on kernels <5.13 a restricted peer runs unsandboxed with no signal to the client. | When `policy.is_restricted()`, treat Landlock unavailability as fatal (refuse the session). |
| H7 | `crates/hop-cli/src/main.rs:392` + `install.sh:216-221` + `cmd_warren` join | The warren **write** ticket (`netdoc.ticket`, `netdoc-join.ticket`, `warren-ticket`) is written with default `std::fs::write` (umask → typically 0644) on per-user installs → any local user reads it and gains warren write. | Use `write_secret_file` (0600) everywhere these tickets are written; `chmod 600` in install.sh. |
| H8 | `datastore/mod.rs:41-47` | Secrets-at-rest AEAD key = `SHA256("hop-secrets-v1" ‖ identity_secret)` — single pass, no KDF, no salt, **shared across all users**. Confidentiality of all secrets reduces to `identity.json` perms; user-scoping is non-cryptographic. | HKDF-SHA256 with a random per-store salt + domain-separated subkey distinct from the networking identity. |
| H9 | `install.sh:135-144` / `install-daemon.sh:192-201` | Checksum verification silently no-ops when no `sha256sum`/`shasum` (sets `ACTUAL=EXPECTED`). And artifacts are **unsigned** — the `.sha256` sidecar sits beside the binary in the same mutable bucket, so an origin/bucket compromise controls both. | `die` instead of warn-and-skip; sign artifacts with an offline key (minisign/cosign) and verify a signature, not a co-located hash. |
| H10 | `install-daemon.sh:43-48` | `sudo hop warren join "$INVITE"` redeems an **attacker-controlled** invite as **root** — the root daemon dials an attacker relay/node and imports a foreign namespace as root. | Redeem invites as the unprivileged user; confirm host identity before a root daemon imports a foreign namespace. |

## P2 — Medium

| # | Location | Issue | Fix |
|---|---|---|---|
| M1 | `sandbox/validator.rs:34-40` + `policy.rs:55-91` | `allowed_commands`/`denied_commands` are enforced **nowhere** (OS sandbox restricts files/net, not which binary runs). `monitor`'s 22-command allowlist and the deny-list (`rm`,`dd`,…) are decorative → false restriction. | Enforce argv[0] basename at spawn, or remove the fields/presets' reliance so the policy doesn't misrepresent guarantees. |
| M2 | `sandbox/broker.rs:336-376,524-568` | Broker runs `is_broker_safe` commands **unsandboxed** with arbitrary args; some take dangerous flags (`sysctl -w` writes kernel params, defeating read-only; `lsof`/`netstat` leak host-wide state). | Pass only known-safe argv / block write flags; run under the policy where feasible. |
| M3 | `transfer/receiver.rs:53,82-99,130,600-614` | Symlink-assisted write escape + TOCTOU: a session can create an in-tree symlink then write through it; `safe_join` skips the `starts_with(base)` check when the path/parent don't yet exist, and `rename` follows symlinks. Bounded (targets confined to base) but fragile. | Resolve each component against `base` at write time (`openat2(RESOLVE_BENEATH)`/`O_NOFOLLOW`); never follow same-session symlinks. |
| M4 | `invite/mod.rs:204-209` + `admin/mod.rs:126-157` | Creator invites skip username validation at mint → a Creator invite bound to `root`/nonexistent user enters `peers.json` and only fails at session time. (Mitigated: `check_shell_security` hard-blocks root at runtime.) | Validate the username at generation for all roles (still allowing `None`). |
| M5 | `auth/mod.rs:177-197` | The "peers.json always wins" no-lockout fallback never consults doc revocation for a locally-authorized peer → a doc-only revocation (another Creator revokes) doesn't lock the peer out on this host until the local entry is also removed. | Check `is_revoked` (doc tombstone) before the unconditional local allow. |
| M6 | `netdoc/mod.rs` `vpn_dns_loop` + member-writable `name/` | MagicDNS answers from the member-writable `name/` table → name→IP spoofing redirects victim connections. No rate limiting. | Author-bind `name/` (H1); restrict DNS to local queries. |
| M7 | `netdoc/mod.rs` `lookup_host_tags`/`list_posture` etc. | `serde_json::from_slice(...).unwrap_or_default()` on replicated entries → a hostile/corrupt posture entry silently becomes empty (policy behavior depends on attacker-supplied malformed data). | Log + hard-deny/ignore nodes with undecodable security-relevant entries. |
| M8 | `admin/mod.rs:444-463` | `log_admin_action` builds audit JSON via raw `format!` interpolation → log injection / forged entries from role names / node-id prefixes containing `"`/`\`. | Serialize with `serde_json`. |
| M9 | `pkg/com.hop.daemon.plist` + `pkg/hop.service` | Default `--host` install = root, `KeepAlive`, network-listening daemon with **no** systemd hardening (`NoNewPrivileges`/`ProtectSystem`/`User=` absent). | Add systemd hardening; run the data plane as a dedicated unprivileged user where possible. |
| M10 | `CLAUDE.md` relay one-liner | Production relay re-provisioned by `curl|bash` as root (unverified + degradable checksum). Bucket/CDN compromise → root on the relay. | Pull a signed artifact by digest; avoid root SSH. |
| M11 | `datastore/mod.rs:85-114` | `datastore.redb` (encrypted secrets) created with default umask, relaxed to `0o660` group-writable when parent is setgid → ciphertext+nonces group-readable. | Create 0600 when daemon-owned; widen only when genuinely shared. |
| M12 | `config/mod.rs:115-145` | `load_or_generate_identity` writes new keys 0600 but never re-tightens a pre-existing `identity.json` with looser perms (it's the secrets-encryption root). | On load, stat + `set_permissions(0o600)` if owned and wider. |

## P3 — Low / Info (condensed)

- **`scripts/release.sh` ~322** — pushes the **current branch** + tags unconditionally, no clean-tree/branch guard (repo is on `p2p-network`). Add a `main` + clean-worktree assertion. *(Low)*
- **`scripts/release.sh`** — the `latest` plain-text marker (read by every installer to pick the version) is unsigned; a bucket write flips all fresh installs. Sign the version manifest. *(Low)*
- **`hop-mcp/src/js/bindings.rs:1441-1446`** — `__hop_kv_get` builds JSON by string interpolation; serialize via `serde_json`. *(Low)*
- **`hop-mcp/src/js/mod.rs:164-166`** — JS deadline is cooperative (native blocking calls aren't preempted); chained calls can exceed `timeout_secs`. *(Info)*
- **`hop-cli/src/main.rs:1589`** — `hop exec` joins args with spaces and runs through `sh -lc`; shell-evaluated by design but worth documenting (no argv-vector mode). *(Info)*
- **`install.sh:228`** — client auto-redeem `hop exec <invite> -- true 2>/dev/null` hides identity/MITM failures behind a generic fallback. Surface verification failures distinctly. *(Low)*
- **`install-daemon.sh:35` vs `install.sh:64`** — daemon installer only *warns* on unknown flags (a typo'd `--no-vpn` is silently dropped → VPN unexpectedly on); install.sh `die`s. Make them consistent (die). *(Info)*
- **Good:** `setup-aws.sh` blocks public bucket access, scopes the policy to one distribution, forces HTTPS. DNS/HuJSON parsers are bounds-checked (no panic/OOM). ChaCha20 nonces are fresh-random per write. Session-resume is bound to the authenticated `PublicKey`. Admin requests are correctly gated to Creator.

## Vestigial / dead code (separate from security)

**Remove (DEAD):**
- `crates/hop-core/src/vpn/acl.rs:57-99` — `AclPolicy` + `evaluate`/`permits` (+ its tests): replaced by the Cedar engine; not on any live path.
- `crates/hop-core/src/netdoc/mod.rs` — `get_acl_policy`/`set_acl_policy`: zero callers (read/write the dead `AclPolicy`).
- `crates/hop-core/src/invite/mod.rs:50` — `suggested_tier` on `InviteToken`: write-only, only ever set to `None` in prod; never read for a decision. (`#[serde(default)]` → removal is wire-compatible.)
- `crates/hop-core/src/netdoc/mod.rs:1085` — `test_endpoint_with_key`: unused test helper (the only real dead-code build warning).
- `crates/hop-cli/src/oauth.rs` — the `#![allow(dead_code)]` legacy `detect_claude_credentials*` / `parse_claude_oauth` / `ClaudeCredentials` family: never called (live path uses `oauth_provider`/`run_oauth_flow`). Remove + drop the blanket allow.
- `crates/hop-core/src/extensions/registry.rs:147` — `#[allow(dead_code)] manifest_dir` field: stored, unused.

**Wire up (UNWIRED — currently inert):**
- `set_authored_policy` (`netdoc/mod.rs`) — **no CLI sets it**, so `get_authored_policy` can only ever return `None`; authored Cedar policies are unreachable. Wire `hop acl set-policy` (needs the daemon↔netdoc IPC channel) or remove until then.
- `RoleDefinition.capabilities` — populated by the importer + shown by `hop acl caps`, but **never delivered** to any service (no `HOP_APP_CAPS`/`hop whois`). Wire delivery or document as import-only metadata.
- `admin/mod.rs:440` — `active_sessions: 0 // TODO`: hardcoded; wire the session registry or drop the field.

**Keep (verified FINE):** `role_reaches` (live in `hop acl check` + Cedar's test oracle); `PeerRole`/`Creator` (load-bearing — gates admin auth, invite TTL, root mapping); all dependencies (no unused deps found, incl. the iroh-docs/gossip/blobs stack); the `eprintln!` logging (intentional, not debug leftovers).

**Doc drift (all since resolved):** the drift found here has been corrected — the
`acl-cedar-plan` doc has been retired as a completed plan (the Cedar engine
shipped), `orchestration.md`'s `hop auth` "(Planned)" marker was dropped, and the
VPN module docstrings now match reality: the VPN was reverted to **off by
default** (P0a below), so "opt-in / off by default" is accurate.

## Prioritized remediation plan

1. **P0a — Close the warren trust model (C1).** Read-ticket member invites + gate write/federation behind an explicit admin step + per-entry author validation on read. This is the keystone; H1, H2 (admin self-claim), M6 all collapse once writes are authorized. Until done, **disable the VPN default-on** (flip `vpn_enabled` default to false / require `--host` opt-in) and fix the stale "opt-in" docstrings to match reality.
2. **P0b — Authenticate the data plane (C2).** Ingress check: `remote_node_id()` → authorized vIP; drop spoofed source/foreign dst.
3. **P0c — Make the sandbox a real boundary (C3, C4).** Thread the policy into transfer; gate JS file bindings; block SSRF in `hop.http`.
4. **P1 — Harden:** ticket/identity/secrets file perms (H7, H8, M11, M12), SBPL injection (H4), Linux no_network + fatal Landlock (H5, H6), revocation latency (H3), artifact signing + die-on-no-checksum (H9), un-root the redeem (H10).
5. **P2/P3 — Consistency & hygiene:** enforce or drop command allow/deny lists (M1), broker arg restrictions (M2), symlink/TOCTOU (M3), doc-revocation override (M5), audit-log JSON (M8), systemd hardening (M9), release branch guard, dead-code removals, doc-drift fixes.

## Remediation status — v0.6.37 (2026-06-03)

**Fixed:**
- **P0a** — VPN flipped off-by-default (`vpn_enabled` default false; `--host` /
  `HOP_VPN=1` / `hop config set vpn on` opt in); docstrings corrected; installer
  primers opt a node back in only on explicit `--host`/node install.
- **P0b** — VPN data-plane ingress authentication: `VpnInbound` delivers a
  datagram only when the connecting node is a registered peer, the source vIP
  matches that node's registered vIP, and the destination is our own vIP.
- **P0c (C3/C4)** — transfer now enforces the peer's `SandboxPolicy`
  (read-only + `allowed_paths`); JS `readFile`/`writeFile` confined to scope and
  read-only-aware; `hop.http` blocks SSRF (loopback/private/link-local/CGNAT/
  IMDS + v6 equivalents) and disables redirects for restricted peers.
- **P1/P2** — H4 (SBPL escaping), H5/H6 (Landlock fatal-when-restricted +
  no_network via Landlock TCP rules + honest docs), H7 (ticket files 0600),
  H9 (install.sh die-on-no-checksum + ticket umask 077), M5 (doc-revocation
  overrides a local allow), M8 (audit-log via serde_json), M9 (systemd note +
  LockPersonality; heavier sandboxing intentionally omitted — sessions are
  children of the unit), M11/M12 (datastore 0600, identity re-tighten),
  release branch guard.
- **Dead code** — removed `AclPolicy`/`Action`/`Rule` + `get/set_acl_policy`,
  `suggested_tier`+`Tier`, `test_endpoint_with_key`, `manifest_dir`, and the
  legacy `oauth.rs` credential-detection family (+ blanket `allow(dead_code)`).
- **Doc drift** — orchestration.md `hop auth` marked Shipped; README already
  Shipped; VPN docstrings now accurate (off-by-default again).

### Deferred items — why, and what mitigates them now

Three findings were deliberately **not** fixed in v0.6.37. In each case the
*correct* fix is a structural change with a credible way to break legitimate
access or destroy data, while a cheaper interim mitigation already shrinks the
exposure materially. hop's operating constraint — *it may be the only way into a
system* — means a fix that risks lockout or data loss is worse than a documented,
mitigated gap. Each is tracked here so the next pass starts with the context
intact.

#### C1 — Warren trust model (the keystone)

**Finding.** Every invite embeds a `ShareMode::Write` iroh-docs `DocTicket` for
the shared warren document. That document holds *all* security-relevant warren
state: virtual-IP claims (`ip/`), VPN endpoint registrations (`vpn/`), MagicDNS
names (`name/`), device posture, and peer/role records. Because every member
holds a **write** ticket, any member can rewrite any of it — repoint
`vpn/<victim>` at their own node to intercept traffic, spoof a MagicDNS name,
claim another node's vIP, or forge posture to satisfy a posture-gated policy.
Last-writer-wins conflict resolution only arbitrates *honest* races; it offers
nothing against a malicious writer.

**Why it's the keystone.** H1 (key overwrite), H2 (self-attested posture/admin),
and M6 (DNS spoofing) are all *symptoms* of C1 — they collapse the moment writes
are authorized per author.

**Why deferred.** The real fix is structural and multi-layer: issue members
**read-only** tickets, gate write/federation behind an explicit admin action,
and validate on read that each entry's author matches the identity it claims to
speak for (`vpn/<node>` is writable only by `<node>`). That touches ticket
issuance, the replication-read path, admin gating, and migration of existing
warrens. Landing it half-right could either lock legitimate nodes out of their
own warren or silently leave the hole open; it needs its own focused pass with
its own e2e coverage. (`set_authored_policy`/`get_authored_policy` are the
inert scaffolding for the authored-policy half of this — see UNWIRED below.)

**Mitigation shipped.** This is *why* P0a flipped the VPN off-by-default. With
the warren/VPN dormant unless explicitly enabled (`--host` / `HOP_VPN=1` /
`hop config set vpn on`), a bare `hop host` no longer joins a writable shared
document at all — the blast radius shrinks to nodes that have deliberately
opted in. P0b (ingress auth) independently blocks the *traffic-interception*
exploitation path even when `vpn/` is tampered with: a forged registration
still can't produce correctly-sourced, authenticated packets.

#### H8 — Secrets-at-rest KDF

**Finding.** The AEAD key for the encrypted secrets store is
`SHA256("hop-secrets-v1" ‖ identity_secret)` — a single hash pass, no HKDF, no
per-store salt, identical derivation for every user on the box. The recommended
shape was HKDF-SHA256 with a random per-store salt and a domain-separated
subkey.

**Why deferred — two independent reasons:**
1. **The fix risks destroying data.** Any change to the derivation changes the
   *output* key, rendering every already-encrypted secret on every deployed host
   undecryptable on upgrade. The only safe path is a key-rotation migration
   (decrypt-with-old → re-encrypt-with-new → versioned marker) — real surface
   that can't be validated against live field stores in this pass, and whose
   failure mode is *permanently unreadable secrets*. That is the precise
   opposite of "rock solid."
2. **The benefit is near-zero against the real threat.** The threat is an
   attacker who can read the filesystem. The key derives from `identity.json`,
   so anyone who can read the ciphertext db can also read `identity.json` and
   re-derive the key under *any* KDF. A per-store salt doesn't help either — it
   would live in the same db the attacker is already reading. Domain separation,
   the one property that genuinely matters here, is *already* present via the
   `"hop-secrets-v1"` label.

So: high risk of data loss, negligible security gain. Revisit only alongside a
proven migration path. The actual protection for secrets-at-rest is filesystem
permissions, which *were* hardened this pass — M11 pins the datastore to `0600`,
M12 re-tightens `identity.json` to `0600` on load.

#### H10 — Root invite redeem

**Finding.** `install-daemon.sh` runs `sudo hop warren join "$INVITE"` — the
root daemon redeems an operator-supplied invite, dials the inviting node, and
imports a foreign namespace **as root**. A malicious invite points the root
daemon at an attacker's relay/node.

**Why deferred.** This is inherent to the install *model*, not a discrete bug.
The daemon runs as root because it must `su` to arbitrary users, create the TUN
device, and write `/etc/hop` — and the join ticket has to land in that
root-owned config dir. A real fix means redesigning `warren join`'s privilege
split: redeem as an unprivileged user, confirm host identity, then hand only the
validated ticket to the daemon. And critically: an operator pasting `--invite`
into a root install command *is* the authorization — a malicious invite here is
a social-engineering vector that exists for any "paste this to join" UX, root or
not.

**Mitigation shipped.** Same lever as C1 — VPN off-by-default. A bare daemon
install no longer auto-joins a warren; the foreign-namespace import happens only
when the operator explicitly passes `--invite`/`--join`, making the trust
decision explicit rather than implicit.

#### Lower-severity / inert (next pass)
- **H1 / H2 / H3 / M6** — all collapse into C1 (author-bound keys); revisit with C1.
- **M1 / M2 / M3** — command allow/deny enforcement, broker argument
  restrictions, transfer symlink/TOCTOU hardening: real but lower-severity.
- **UNWIRED (not security bugs)** — `set_authored_policy` /
  `RoleDefinition.capabilities` / `active_sessions` remain inert; wire or remove
  in a later pass.

*Last updated: v0.6.37*
