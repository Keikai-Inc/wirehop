# Build plan — Cedar ACL engine + Tailscale compatibility (Planned)

> **Status: Planned / design.** Closes the ACL gaps identified in
> [acl-vs-tailscale.md](acl-vs-tailscale.md): adopt **Cedar** as hop's standard
> policy engine, add a **Tailscale-ACL importer**, and address the feature gaps
> (port/proto granularity, explainability, app capabilities, posture,
> autogroups). Nothing here is implemented yet.

## Principles (don't regress these)

- **Keep the decentralized core.** Cedar policies + the entity inputs live in the
  replicated iroh-docs document (`acl/*` keys); there is **no coordinator**. This
  is hop's defining guarantee.
- **Keep the role model.** A role still carries reach **and** the OS-sandbox
  confinement. Cedar replaces the *reach evaluator*, not the role concept.
- **Default-deny, always.** Cedar is deny-by-default (no `permit` ⇒ deny), which
  matches today's behavior.
- **Hot path stays fast.** Reach is evaluated per packet; Cedar evaluation must be
  cached (see Phase 1) so the forwarding loop never blocks on policy.
- **Rock-solid rollout.** Every phase: behavior-parity tests, the 53-test
  regression suite, and the live `vpn-e2e.sh` must stay green.

## Cedar mapping (the foundation)

hop's `role → tag` reach becomes a Cedar schema + a generated default policy.

**Entities** (derived from the netdoc each refresh — not a new source of truth):

| Cedar entity | From | Attributes |
|---|---|---|
| `Peer` (principal) | `peer/<node>` | `role: Role`, `vip` |
| `Host` (resource) | `ip/` + `tag/` tables | `tags: Set<String>`, `vip` |
| `Role` | `role/<name>` | `tags: Set<String>`, `wildcard: Bool`, `admin: Bool` |

**Action:** `Action::"connect"`. **Context:** `{ port: Long, proto: String }`.

**Generated default policy** (encodes today's `role_reaches`):

```cedar
permit ( principal, action == Action::"connect", resource )
when {
  principal.role.wildcard ||
  principal.role.tags.containsAny(resource.tags)
};
```

Advanced/explicit rules (and imported Tailscale rules) are *additional* Cedar
policies stored in the doc. `vpn_reach_allowed(src, dst, port)` becomes an
`is_authorized` query against (generated default + authored) policies.

## Phases (each compiles, tests, and ships independently)

### Phase 1 — Cedar engine, behavior-preserving
- Add the `cedar-policy` crate (Rust-native, Apache-2.0).
- Define the schema + entity provider (`netdoc` → Cedar entities) + the generated
  default policy above.
- New `AclEngine::is_reach_allowed(src_node, dst_node, port, proto)` evaluating
  Cedar; `vpn_reach_allowed` delegates to it.
- **Reach cache:** build entities/policies once per doc version; the per-packet
  path is a memoized `(src, dst, port) → Allow/Deny` lookup, invalidated on doc
  change. (Today's path already does several async doc reads per packet — this is
  also a latency win.)
- **Parity:** keep `role_reaches` as the test oracle — fuzz/assert Cedar decisions
  equal `role_reaches` across wildcard / intersection / empty-role / untagged.
- Validate: unit parity tests, 53-test regression, `vpn-e2e.sh` ping unchanged.

### Phase 2 — Port/proto granularity + explainability
- Thread the destination port/proto (already parsed in the forwarding loop) into
  the Cedar `context`, so policies can scope reach per port/proto.
- **`hop acl explain <src> <dst> [port]`** — uses Cedar's authorizer diagnostics
  to report *which policy* allowed/denied and *why* ("permitted: role `dev`
  reaches `tag:staging`"). Big understandability win, unique vs Tailscale.
- **`hop acl`** — show the effective entities + policies (the current state).

### Phase 3 — Authored policy surface (the conventional editing experience)
- Persist an authored Cedar policy set in the doc (`acl/cedar`), evaluated
  alongside the generated default. `hop acl set/edit` round-trips it.
- Cedar text is the canonical, human-readable, analyzable form (IAM-like).
- Validate the policy set on write (Cedar parses + type-checks against the schema)
  so a bad policy can't brick reach; reject-and-keep-previous on parse error.

### Phase 4 — Tailscale-ACL importer
- `hop acl import <policy.hujson> [--dry-run]`. Add a small JWCC reader
  (strip comments/trailing commas → `serde_json`).
- Translation map:

  | Tailscale | hop |
  |---|---|
  | `tags` / `tag:x` | host tags |
  | `groups` (users) | roles |
  | `acls`/`grants` `src → dst:port` (accept) | Cedar `permit` policies (principal group/role, resource tag, `context.port`) |
  | `autogroup:members` / `:admin` | Cedar groups (all peers / admin-role peers) |
  | `ip` (ports/proto) | Cedar `context` |
  | `tagOwners` | **unsupported** (advisory — hop assigns tags at install/role) |
  | `app` capabilities | hop capability grants (Phase 5) or reported skipped |
  | `ssh` rules | **unsupported** (hop session auth is separate) |
  | `postures` / `nodeAttrs` | Phase 6, else reported skipped |

- Output a clear **import report**: what mapped, what was skipped and why. "Paste
  your tailnet policy" as the on-ramp; never silently drop a rule.

### Phase 5 — Application-layer capability grants (the biggest gap)
- Add a typed capability map to roles/grants — `{domain}/{path}` names, value =
  array of JSON config objects (mirrors Tailscale's shape for portability).
  Stored in the doc, replicated.
- **Delivery (hop is L3, so this needs an app-facing surface):**
  - `hop whois <vip|peer>` / a local query API returning the peer's granted
    capabilities, so a service co-located with a hop node can authorize.
  - Inject resolved capabilities into the `hop exec`/session environment
    (`HOP_APP_CAPS`) for hop-spawned workloads.
  - (Optional, later) an HTTP header surface if hop ever fronts a service proxy,
    analogous to `Tailscale-App-Capabilities`.
- This is the largest L3-vs-app mismatch; design the delivery API first.

### Phase 6 — Device posture (optional; commercial-adjacent)
- Collect posture into peer attributes in the doc (OS, hop version, sandbox state,
  last-seen). Surface as Cedar **principal/context attributes**.
- Policies can gate reach on posture (`when { principal.os == "linux" }`). Ties to
  the trust-root work for trustworthy attestation.

### Phase 7 — Autogroups & ergonomics
- `autogroup:members` / `:admin` / `:self` as Cedar groups/entities for familiar,
  terse policies. Worked examples in docs + a `hop acl` quickstart.

## Rollout order & dependencies

`1 (engine, parity) → 2 (ports + explain) → 3 (authored surface) → 4 (importer)`
delivers the standards-based engine and the Tailscale on-ramp. `5 (app caps)`,
`6 (posture)`, `7 (autogroups)` are independent feature-gap closers afterward,
prioritizable on demand. Phase 1 is the keystone — everything compiles to Cedar.

## Risks / open questions

- **Per-packet performance** — mitigated by the Phase-1 reach cache; measure under
  the e2e before flipping the live path.
- **Binary size / dependency surface** — `cedar-policy` pulls in a parser/evaluator;
  acceptable for a single binary, but measure.
- **App-capability delivery on an L3 VPN** — Tailscale leans on its Serve/WhoIs
  app layer; hop needs an explicit query API (Phase 5) since it forwards packets,
  not HTTP. This is a genuine design problem, not a port.
- **Migration fidelity** — `tagOwners`, `ssh`, posture, and app caps don't map
  cleanly; the importer must report rather than silently approximate.

## Validation (every phase)

Unit (Cedar parity / policy round-trip / importer translation), the 53-test
regression suite (default behavior unchanged), and `vpn-e2e.sh` (reach + reboot).
Phase 4 adds an importer golden-file test; Phase 5 adds a capability-delivery e2e.

*Last updated: v0.6.35*
