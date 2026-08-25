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

### Embedded Google OAuth client credentials

`crates/hop-cli/src/oauth.rs` contains the client ID and client secret of
WireHop's registered Google **Desktop-app** OAuth client, used by
`hop auth gmail`. This is intentional:

- For installed applications, Google's own documentation states the client
  secret "is obviously not treated as a secret"
  (<https://developers.google.com/identity/protocols/oauth2#installed>).
  User security comes from PKCE and the loopback redirect, not from client
  secrecy — the pair necessarily ships inside every distributed binary
  regardless of whether it appears in source.
- This is the standard pattern for open-source desktop tools (rclone and
  gcloud, among many others, embed theirs the same way).
- Self-hosters can substitute their own client via
  `HOP_GOOGLE_CLIENT_ID` / `HOP_GOOGLE_CLIENT_SECRET`.

Possession of these values does not grant access to any user's data or to any
WireHop infrastructure.

### Synthetic credentials in tests

Test fixtures (e.g. the `sk-ant-oat01-…` token in `oauth.rs`) are synthetic
values exercising parsers. They are not live credentials.

## Security model

For the product's threat model — invite scoping, capability tiers, role-based
reach, sandboxing, and per-node audit — see `docs/technical/security.md`.
