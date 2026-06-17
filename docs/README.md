# hop Documentation

## Product Documentation (`docs/product/`)

What hop does — user-facing behavior, CLI commands, JS APIs.

| Document | Description |
|----------|-------------|
| [overview.md](product/overview.md) | Vision, why hop exists, core user flows, architecture diagram |
| [cli-reference.md](product/cli-reference.md) | Every CLI command with flags and examples |
| [capabilities.md](product/capabilities.md) | `hop cap` — built-in automation (health, log-search, security-baseline) |
| [orchestration.md](product/orchestration.md) | Secrets store, HTTP binding, OAuth proxy, email monitoring |
| [js-api.md](product/js-api.md) | Complete `hop.*` JS runtime reference (all bindings) |
| [datastore.md](product/datastore.md) | KV, time-series, cron scheduling, secrets, retention |
| [fleet.md](product/fleet.md) | Fleet management = your warren at scale — RBAC roles, tags, aggregate invites over replicated (no-orchestrator) membership |
| [warren.md](product/warren.md) | **(Product design)** The warren — hop's zero-config private network: client vs node, role-is-the-access model, onboarding, roadmap |
| [warren-gaps.md](product/warren-gaps.md) | **(Living)** Consistency gaps between the warren docs and the implementation, triaged (resolved-by-decision / doc-fix / open work) |
| [transfer.md](product/transfer.md) | `hop cp`, `hop sync`, delta transfer, compression |
| [security.md](product/security.md) | Sandbox system, auth, invites, privilege separation |
| [mcp.md](product/mcp.md) | MCP server, tools, skills library, AI agent integration |
| [sessions.md](product/sessions.md) | Shell sessions, persistence, reconnection, connection agent |
| [tap.md](product/tap.md) | hop-tap — eBPF terminal session audit (visibility, auditability, control) |

## Technical Documentation (`docs/technical/`)

How hop works — protocols, algorithms, internal architecture.

| Document | Description |
|----------|-------------|
| [architecture.md](technical/architecture.md) | Crate layout, module map, dependency flow |
| [protocol.md](technical/protocol.md) | Wire protocol (ALPN V1/V2/V3), message types, admin protocol |
| [crypto.md](technical/crypto.md) | Ed25519 identity, Argon2 auth, ChaCha20-Poly1305 secrets |
| [datastore.md](technical/datastore.md) | redb tables, IPC protocol, DsRequest/DsResponse, retention |
| [sandbox.md](technical/sandbox.md) | Validator, broker, macOS Seatbelt, Linux Landlock, policy composition |
| [transfer.md](technical/transfer.md) | Delta algorithm, negotiation, privilege-separated helper |
| [js-runtime.md](technical/js-runtime.md) | QuickJS, async bridge, binding architecture |
| [networking.md](technical/networking.md) | iroh endpoint, relay, netmon, **warren netdoc + VPN data plane**, agent/mux IPC, reconnection |
| [p2p-network.md](technical/p2p-network.md) | **(Shipped + design)** Orchestratorless P2P VPN — iroh-docs state, virtual IPs, TUN data plane, MagicDNS, decentralized invites/roles, write-isolation (C1); the 13 design decisions + rationale |
| [acl-vs-tailscale.md](technical/acl-vs-tailscale.md) | **(Comparison + shipped ACL)** hop's warren ACL (role→tag reach via a Cedar policy engine + OS-sandbox confinement) vs Tailscale's ACL/grants/app-capabilities — distribution, expressiveness, the capability gap. (Canonical ACL reference; the Cedar engine + Tailscale-ACL importer shipped.) |
| [security-audit.md](technical/security-audit.md) | **(Action report + remediation status)** Source-level security + dead-code audit — write-capable warren ticket, VPN ingress spoofing, sandbox-bypass in transfer/MCP, secrets-at-rest KDF; severities + fixes + what shipped and what's still **deferred** (C1 enforce-default flip, H8 KDF, H10 root redeem) with rationale |
| [install-and-invite-tiers.md](technical/install-and-invite-tiers.md) | **(Largely shipped)** Unified one-install convention (client by default; daemon as an on-demand self-upgrade) + invite capability tiers (client / warren-only / node / admin); the C1 enforce-default flip is the remaining deferred gate |
| [per-member-self-docs.md](technical/per-member-self-docs.md) | **(Shipped)** C1 warren write-isolation: each member owns a write-isolated iroh-docs namespace for self-state; admin doc holds membership + `peer/N.vip`/`.vpn_endpoint`. Includes the convergence-blocker root-cause analysis |
| [tap.md](technical/tap.md) | hop-tap internals — eBPF program, CO-RE, off-screen emulator, streaming dispatcher |
