# Agents Guide

WireHop's binary is named `hop`. This file is the working guide for AI agents
(and humans) developing in this repository.

## Workspace layout

```
crates/hop-cli/    # Binary crate (thin CLI wrapper, binary name: "hop")
crates/hop-core/   # Library crate (networking, PTY, auth, config, protocol)
crates/hop-mcp/    # MCP server + JS runtime bindings
crates/hop-vt/     # Terminal emulation
vendor/            # Vendored crates (see each Cargo.toml for why)
pkg/               # macOS .pkg installer scripts and plists
tests/e2e/         # Docker-based end-to-end suite
docs/              # Product + technical documentation
```

## Documentation rules

- `docs/product/` — WHAT the product does; `docs/technical/` — HOW it works.
- Read the relevant docs before implementing or modifying a feature; update
  them after. New feature areas get a new file.
- Each doc is self-contained; prefer tables and code blocks over prose.
- Mark unimplemented features "(Planned)"; never leave shipped features so.

## Building

Rust 2024 edition, default stable toolchain.

```bash
cargo build -p hop-cli              # development build
cargo build --release -p hop-cli    # release build → target/release/hop
```

Linux cross-builds use [cross](https://github.com/cross-rs/cross) + Docker:

```bash
AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target aarch64-unknown-linux-gnu -p hop-cli
```

## Testing

```bash
cargo test                    # all workspace tests
./tests/e2e/run.sh            # full e2e suite (Docker; REBUILD=1 after Rust changes)
```

**Run e2e before merging changes** that touch networking (`hop-core/src/net/`),
auth, protocol (`hop-core/src/proto/`), shell/exec, transfer, sandbox, MCP/JS
bindings, agent/mux, fleet, or CLI dispatch. The suite spins up Docker
containers and exercises the full connection/auth/exec/transfer/fleet surface.

After Rust changes ALWAYS use `REBUILD=1 ./tests/e2e/run.sh` — the harness
skips the cross-build otherwise and you'd test a stale binary.

### Gate harnesses

`tests/e2e/` also holds harnesses that each enforce one product claim and commit
a `*-results.md` artifact, so a regression shows up as a diff:

| Harness | Claim |
|---|---|
| `first-run.sh` | each core job completes cold within its time budget |
| `soak-resilience.sh` | the network reconverges after perturbation within SLA |
| `session-resilience.sh` | interactive-session recovery reaches VPN parity |
| `agent-coldstart.sh` | an AI agent can build a working network with no human |

`agent-coldstart.sh` drives a real model against two bare containers that have no
`hop` binary, then scores the containers itself — the agent's own report is
ignored. It needs `ANTHROPIC_API_KEY` and spends tokens, so it is run
deliberately rather than on every change. `--self-test` checks the harness
without touching the API.

## Code style

- Commit messages: imperative mood, 1–2 sentence summary of the *why*.
- Workspace dependencies live in the root `Cargo.toml`; crates use
  `.workspace = true`.
- **Zero warnings policy**: run `cargo clippy --workspace` and resolve every
  warning before finishing any change. Clean compiler output is mandatory.
- Machine-readable output: user-facing commands support `--json` (see
  `crates/hop-cli/src/agent_out.rs`); errors leave through the structured
  envelope. New commands should follow suit.

## Protocol compatibility

- ALPN strings (`hop/0`..`hop/3`, `hop/vpn/1`) are wire-internal and keep the
  `hop/` prefix permanently by design — renaming them breaks mixed-version
  fleets for zero user-visible benefit.
- bincode ignores `#[serde(default)]`: never add fields to existing wire
  messages; append new enum variants at the END of the enum instead.
- Transfer listing encoding is gated on the negotiated
  `features_version` (see `docs/technical/transfer.md`).
