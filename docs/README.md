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
| [fleet.md](product/fleet.md) | Fleet management, roles, aggregate invites |
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
| [p2p-network.md](technical/p2p-network.md) | **(Shipped MVP + design)** Orchestratorless P2P VPN — iroh-docs state, virtual IPs, TUN data plane, MagicDNS, decentralized invites/roles; commercial control plane (Planned) |
| [acl-vs-tailscale.md](technical/acl-vs-tailscale.md) | **(Comparison)** hop's warren ACL (role→tag reach + OS-sandbox confinement) vs Tailscale's ACL/grants/app-capabilities — distribution, expressiveness, the capability gap |
| [acl-cedar-plan.md](technical/acl-cedar-plan.md) | **(Shipped)** Cedar standard policy engine, Tailscale-ACL importer, and the closed feature gaps (port/proto, explainability, app capabilities, posture, autogroups) |
| [security-audit.md](technical/security-audit.md) | **(Action report + remediation status, 2026-06-03)** Source-level security + dead-code audit — write-capable warren ticket, VPN ingress spoofing, sandbox-bypass in transfer/MCP, secrets-at-rest KDF, vestigial code; severities + fixes + what shipped in v0.6.37 and what's **deferred** (C1 write-auth, H8 KDF, H10 root redeem) with rationale |
| [tap.md](technical/tap.md) | hop-tap internals — eBPF program, CO-RE, off-screen emulator, streaming dispatcher |
