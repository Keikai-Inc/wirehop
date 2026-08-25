# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities through GitHub's **private
vulnerability reporting** on this repository (Security → Report a
vulnerability). Do not open public issues for security reports. We aim to
acknowledge within 72 hours. Coordinated disclosure is appreciated; we will
credit reporters in release notes unless you prefer otherwise.

WireHop does not currently operate a paid bug-bounty program.

## Known, intentional non-vulnerabilities

Automated scanners will flag the following. They are deliberate, documented
decisions — reports about them will be closed as informational.

### No embedded credentials

`hop auth gmail` uses a Google **Desktop-app** OAuth client. Those credentials
are *not* in this repository: they are injected at build time from the release
environment (`crates/hop-cli/build.rs`) and stored obfuscated in the binary.

To be explicit, since it would otherwise look like a security control: this is
**obfuscation, not encryption**. Google does not treat installed-app client
secrets as confidential — PKCE and the loopback redirect are the actual
protection — and the pair necessarily ships inside every distributed binary,
so anyone determined can recover it. The point is to keep the source tree free
of credential-shaped strings so scanners and push protection don't fire on
maintainers and contributors.

Self-hosters can supply their own client (also the way to escape the shared
client's API quota) with `HOP_GOOGLE_CLIENT_ID` / `HOP_GOOGLE_CLIENT_SECRET`
at runtime.

### Synthetic credentials in tests

Test fixtures (e.g. the `sk-ant-oat01-…` token in `oauth.rs`) are synthetic
values exercising parsers. They are not live credentials.

## Security model

For the product's threat model — invite scoping, capability tiers, role-based
reach, sandboxing, and per-node audit — see `docs/technical/security.md`.
