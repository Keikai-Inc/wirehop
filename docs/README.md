# hop Documentation

Organized into two categories: **product** (what hop does — user-facing behavior,
CLI, JS APIs) and **technical** (how it works — protocols, algorithms, internals).
Each document is a self-contained topic; related features that used to live in
separate files have been consolidated here.

## Product Documentation (`docs/product/`)

| Document | Description |
|----------|-------------|
| [quickstart.md](product/quickstart.md) | Copy-pasteable recipes for the three core jobs (reach a machine · private network · expose a device) — the same commands the first-run acceptance suite gates on |
| [overview.md](product/overview.md) | Vision, why hop exists, core user flows, architecture diagram |
| [cli-reference.md](product/cli-reference.md) | Every CLI command with flags and examples |
| [warren.md](product/warren.md) | The warren — hop's zero-config private network: client vs node, role-is-the-access model, onboarding, plus **fleet/RBAC at scale** and the living gap analysis |
| [data-and-automation.md](product/data-and-automation.md) | The datastore (KV, time-series, cron, secrets, retention), `hop cap` capabilities, and orchestration bindings (HTTP, OAuth proxy, email monitoring) |
| [remote-access.md](product/remote-access.md) | Interactive shell sessions (persistence, reconnection, connection agent) and file transfer (`hop cp`, `hop sync`, delta + compression) |
| [run-your-own-relay.md](product/run-your-own-relay.md) | `hop host --relay` — run a **member-only** BYO relay so your warren never depends on the public relay (the open-relay fix) |
| [ai-and-scripting.md](product/ai-and-scripting.md) | MCP server, tools, skills library, AI-agent integration, and the complete `hop.*` JS runtime API |
| [security.md](product/security.md) | Sandbox system, auth, invites, privilege separation (user-facing) |
| [posture.md](product/posture.md) | Device posture: the signed health card (disk-encryption, OS version, firewall) and gating reach on it with `hop acl policy` |
| [tap.md](product/tap.md) | hop-tap — eBPF terminal session audit (visibility, auditability, control) |

## Technical Documentation (`docs/technical/`)

| Document | Description |
|----------|-------------|
| [architecture.md](technical/architecture.md) | Crate layout, module map, dependency flow, and the wire protocol (ALPN V1/V2/V3, message types, admin protocol) |
| [warren-internals.md](technical/warren-internals.md) | The warren's full internal design: iroh endpoint/relay/netmon networking + VPN data plane, orchestratorless iroh-docs state (the 13 design decisions), per-member write-isolated self-docs (C1), install/invite capability tiers, and the Cedar-based ACL (with a Tailscale comparison) |
| [security.md](technical/security.md) | Security internals: Ed25519/Argon2/ChaCha20 crypto, the sandbox (validator/broker, Seatbelt, Landlock), privilege separation (monitor/worker), and the standing source-level security audit with remediation status |
| [datastore.md](technical/datastore.md) | redb tables, IPC protocol, DsRequest/DsResponse, retention |
| [transfer.md](technical/transfer.md) | Delta algorithm, negotiation, privilege-separated helper |
| [js-runtime.md](technical/js-runtime.md) | QuickJS, async bridge, binding architecture |
| [tap.md](technical/tap.md) | hop-tap internals — eBPF program, CO-RE, off-screen emulator, streaming dispatcher |
