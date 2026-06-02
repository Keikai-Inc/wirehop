# Architecture

## Workspace Layout

hop is a Cargo workspace with three crates:

```
Cargo.toml              # workspace root
crates/
  hop-cli/              # Binary crate (binary name: "hop")
  hop-core/             # Library crate (networking, PTY, auth, config, protocol)
  hop-mcp/              # MCP server + JS runtime for orchestration
```

Workspace-level settings in the root `Cargo.toml`:

```toml
[workspace.package]
version = "0.6.33"
edition = "2024"
license = "LicenseRef-Proprietary"
```

## Dependency Flow

```
hop-cli ──depends-on──> hop-core
hop-cli ──depends-on──> hop-mcp
hop-mcp ──depends-on──> hop-core
```

`hop-core` is the foundation. Both `hop-cli` and `hop-mcp` depend on it. `hop-cli` also depends on `hop-mcp` for MCP server functionality.

## Crate: hop-core

The core library providing networking, authentication, protocol, file transfer, sandboxing, and configuration. All heavy lifting lives here.

**Modules:**

| Module | Purpose |
|---|---|
| `admin/` | Host-side admin command handlers (create user, fleet management) |
| `auth/` | Authentication flow (invite verification, peer authorization) |
| `config/mod.rs` | Identity management, peer/known-host stores, host config |
| `datastore/` | Embedded redb database: KV, time-series, cron, secrets |
| `fleet/` | Fleet membership, heartbeat, tagging |
| `invite/mod.rs` | Invite token generation/verification (Argon2 hashing) |
| `net/mod.rs` | iroh endpoint creation, QUIC connection management |
| `net/netmon.rs` | Network interface polling, reconnection triggers |
| `netdoc/mod.rs` | **Warren network document**: iroh-docs/gossip/blobs CRDT (on an isolated endpoint) holding membership, roles, revocations, virtual IPs, VPN endpoints, host tags, names; virtual-IP allocation, role→tag→ACL reach resolver, federation (DocTickets), MagicDNS |
| `vpn/` | **Warren VPN data plane** (unix): TUN device (`100.64.0.0/10`, MTU 1280), ALPN `hop/vpn/1` over QUIC datagrams, `VpnInbound` handler, `role_reaches` ACL (`acl.rs`), DNS A-record codec (`dns.rs`), CGNAT-conflict guard |
| `proto/mod.rs` | Wire protocol: message enums, frame encoding, ALPN versions |
| `sandbox/` | OS-native sandboxing (macOS Seatbelt, Linux Landlock) |
| `shell/` | PTY session management, session registry |
| `transfer/` | File copy/sync: delta algorithm, negotiation, sender/receiver |
| `unix_user.rs` | Unix user lookup and validation |
| `lib.rs` | Public re-exports |

**Key dependencies:**

```toml
iroh          # QUIC-based P2P networking (custom fork: thedracle/iroh@hop-relay-fix-0.97, iroh 0.97)
iroh-docs     # CRDT document replication for the warren network document (0.97)
iroh-gossip   # Gossip overlay backing iroh-docs (0.97)
iroh-blobs    # Content-addressed blob store backing iroh-docs (0.99)
tun           # TUN/utun device for the VPN data plane (unix)
tokio         # Async runtime
bincode       # Binary serialization for wire protocol
redb          # Embedded key-value database
argon2        # Password hashing for invite auth
chacha20poly1305  # AEAD encryption for secrets
portable-pty  # Cross-platform PTY spawning
landlock      # Linux filesystem sandbox (cfg(target_os = "linux"))
```

> The custom iroh fork is wired in via `[patch.crates-io]` in the root
> `Cargo.toml` (iroh + iroh-base + iroh-relay → `thedracle/iroh@hop-relay-fix-0.97`,
> which is iroh 0.97.0 plus a macOS relay-cascade fix).

## Crate: hop-cli

Thin CLI wrapper that provides the `hop` binary. Handles argument parsing, TUI, connection multiplexing, and delegates to `hop-core` and `hop-mcp`.

**Modules:**

| Module | Purpose |
|---|---|
| `main.rs` | Entry point, clap command dispatch |
| `cli.rs` | CLI argument definitions |
| `agent.rs` | Connection multiplexer agent (singleton process with QUIC pool) |
| `mux.rs` | IPC protocol for agent communication (MuxConnect/MuxResult) |
| `reconnect.rs` | Reconnection TUI (inline banner + full alternate-screen) |
| `progress_ui.rs` | Transfer progress display |
| `itemize.rs` | Sync dry-run itemization display |

**Key dependencies:**

```toml
hop-core      # Core library
hop-mcp       # MCP server functionality
clap          # CLI argument parsing
ratatui       # TUI framework for reconnection UI
crossterm     # Terminal manipulation
```

## Crate: hop-mcp

MCP (Model Context Protocol) server with an embedded QuickJS JavaScript runtime for orchestration scripts.

**Modules:**

| Module | Purpose |
|---|---|
| `lib.rs` | Public re-exports |
| `server.rs` | MCP server (JSON-RPC over stdio) |
| `protocol.rs` | MCP message types |
| `policy.rs` | MCP capability policies |
| `audit.rs` | MCP audit logging (mcp_audit.jsonl) |
| `cron.rs` | Cron job scheduler |
| `js/mod.rs` | QuickJS runtime factory and sandbox configuration |
| `js/bindings.rs` | Rust-to-JS bindings (`hop.*` global API) |
| `js/types.rs` | JS binding result types |
| `backend/` | OrchestratorBackend trait and implementations |
| `capabilities/` | MCP capability definitions |
| `skills/` | MCP skill handlers |
| `tools/` | MCP tool handlers |

**Key dependencies:**

```toml
hop-core      # Core library
rquickjs      # QuickJS JavaScript engine bindings
reqwest       # HTTP client (blocking mode for JS thread)
async-trait   # Async trait definitions
chrono        # Date/time for cron scheduling
cron          # Cron expression parsing
```

## Key Workspace Dependencies

All versions are pinned in the workspace root and referenced via `.workspace = true` in each crate.

| Dependency | Version | Purpose |
|---|---|---|
| `iroh` | git (custom fork) | QUIC-based P2P networking |
| `tokio` | 1 | Async runtime (multi-thread, signal, net, sync) |
| `bincode` | 2 | Binary serialization with serde |
| `serde` / `serde_json` | 1 | Serialization framework |
| `redb` | 2 | Embedded database (ACID, zero-copy reads) |
| `argon2` | 0.5 | Password hashing for invite auth |
| `chacha20poly1305` | 0.10 | AEAD encryption for secrets |
| `sha2` | 0.10 | SHA-256 for key derivation |
| `zstd` | 0.13 | Compression for wire frames and file transfer |
| `xxhash-rust` | 0.8 | Fast hashing for file sync and delta transfer |
| `nix` | 0.29 | Unix system calls |
| `landlock` | 0.4 | Linux filesystem sandbox |

## Release Profile

```toml
[profile.release]
lto = true           # Full link-time optimization
codegen-units = 1    # Single codegen unit for max optimization
strip = true         # Strip debug symbols
panic = "abort"      # No unwinding overhead

[profile.release-cross]
inherits = "release"
lto = "thin"         # Faster cross-compilation (QEMU)
codegen-units = 4    # Parallel codegen
```

*Last updated: v0.6.33*
