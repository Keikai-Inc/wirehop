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
./tests/e2e/gate.sh           # the merge gate (Docker; REBUILD=1 after Rust changes)
```

**Run the gate before merging changes** that touch networking (`hop-core/src/net/`),
auth, protocol (`hop-core/src/proto/`), shell/exec, transfer, sandbox, MCP/JS
bindings, agent/mux, fleet, VPN/netdoc, privsep, or CLI dispatch. `gate.sh` runs
these suites and fails if any fails:

| Suite | Covers |
|---|---|
| `run.sh` | the connection/auth/exec/transfer/fleet surface (55 tests) |
| `vpn-e2e.sh` | the only suite with a real TUN: routing, reboot, read-ticket members, VPN self-repair |
| `session-resilience.sh` | interactive-session recovery SLA through the daemon mux (net flap, zombie path, host and worker restart, degraded path, relay-pinned, paste across a restart) |
| `privsep-e2e.sh` | privilege split, TUN handoff, non-root operator IPC, the monitor's crash-loop fallback |
| `embedded-profile.sh` | hop as an unsupervised PID 1 in a read-only, memory-capped container: re-exec restarts, VPN self-repair, short-lived members |

`run.sh` alone is not enough: `vpn-e2e.sh`'s reboot stage failed on every build
up to 0.9.40 unnoticed because only `run.sh` was in this gate.

After Rust changes ALWAYS use `REBUILD=1 ./tests/e2e/gate.sh` — the harnesses
skip the cross-build otherwise and you'd test a stale binary.

### Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request and **needs no
secrets**, so it runs green on fork PRs:

| job | what it gates |
|---|---|
| `test` (ubuntu + macOS) | clippy `-D warnings --all-targets`, workspace tests, release build, binary-version match |
| `shell scripts` | `bash -n` over every tracked `.sh`, plus `shellcheck -S error` |
| `workflow lint` | actionlint |
| `site style` | `./site/check-style.sh` |

`.github/workflows/soak.yml` runs `tests/e2e/long-soak.sh` nightly (4 h of
randomized faults on a native arm64 runner, no secrets); a failure there is a
recovery that is slow or broken only sometimes. Its results and logs are kept
as a run artifact.

Run the same checks locally before pushing:

```bash
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets
cargo test --workspace
./site/check-style.sh
```

**The OS matrix is load-bearing.** Code behind `#[cfg(target_os = ...)]` is only
linted on the platform that compiles it, so clippy on a Mac cannot see a Linux
lint (or vice versa). If you touch platform-gated code, expect CI to know things
your laptop does not.

`cargo fmt --check` is intentionally not a gate; the tree is not rustfmt-clean
and normalising it is a separate change.

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
