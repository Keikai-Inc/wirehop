# Contributing to WireHop

Thanks for your interest! A few ground rules keep the project healthy.

## Before you start

- For anything beyond a small fix, open an issue first to discuss the change.
- Read `AGENTS.md` — it's the working guide for the codebase (build, test,
  docs rules, compatibility constraints), for humans and AI agents alike.

## Requirements for a mergeable PR

1. `cargo clippy --workspace` is clean — zero warnings.
2. `cargo test --workspace` passes.
3. Changes touching networking, auth, protocol, transfer, exec, fleet, or CLI
   dispatch pass the e2e suite: `REBUILD=1 ./tests/e2e/run.sh` (needs Docker).
4. Docs under `docs/` updated to match behavior changes.
5. Wire-protocol changes follow the compatibility rules in `AGENTS.md`
   (append-only enums, no new fields on existing messages, version gating).

## Security issues

Do not open public issues for vulnerabilities — see `SECURITY.md`.

## License

By contributing, you agree that your contributions are dual-licensed under
MIT OR Apache-2.0, matching the project.
