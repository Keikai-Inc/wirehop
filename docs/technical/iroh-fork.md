# The iroh fork, and migrating off it

WireHop pins a forked `iroh` rather than the published crate. This records why,
what is actually in the fork, what it costs, and what upgrading to current
upstream would involve. Written 2026-08-27 against upstream `main` at
`3677ec6210` (iroh **1.1.0**); WireHop is on iroh **0.97.0**.

Read this before changing anything in the `[patch.crates-io]` block in the root
`Cargo.toml`, or before deciding WireHop should publish to crates.io.

## What is in the fork

Two patches, **both client-side**. The `iroh-relay` *server* code is untouched:
`hop host --relay` runs stock upstream logic and interoperates with any iroh
relay. Only the `iroh` crate is modified (`socket/`, `address_lookup.rs`).

### 1. Relay connection cascade on network change

macOS emits several `AF_ROUTE` events for a single network transition. During
one, an interface address can briefly leave the interface list while the socket
is still fine. Upstream `CheckConnection` reads "my local address is not in the
list" as "this connection is dead" and tears it down; the reconnect is
immediate; the relay server evicts the previous connection for that node when a
new one arrives, knocking out the one still closing, which trips another
reconnect. Measured at the relay: **906-1620 evictions/hour** from otherwise
idle clients.

Three changes:

- `CheckConnection` pings instead of tearing down when the local address is
  missing from the interface list. The 5s ping timeout is the real liveness
  test and still catches genuinely dead connections.
- Wait 2s before reconnecting after an *established* connection drops, so a
  reconnect does not land on top of one still closing.
- Rate-limit rebind-triggered checks to one per 5s, since the events arrive in
  bursts.

### 2. `addr_filter` not applied to NAT traversal candidates

The endpoint's `addr_filter` is applied when publishing to address lookup
services, but **not** to the direct-address set, which is sent to peers in-band
as NAT traversal candidates. A filtered range therefore still reached peers and
they tried to hole-punch to it. For WireHop this meant advertising its own
`100.64/10` overlay address as a reachable path, so peers punched back through
the tunnel those addresses belong to. Fix applies the same filter in
`store_direct_addresses`.

## Why three crates are patched

Only `iroh` is modified, but `[patch.crates-io]` redirects `iroh`, `iroh-base`
and `iroh-relay` together. `iroh-docs`/`gossip`/`blobs` pull `iroh-base` and
`iroh-relay` from crates.io; mixing those with the fork's copies yields two
`iroh_base` versions and a `PublicKey` type mismatch. Cargo patches a whole git
workspace, so all three move as a unit.

## Branches on the fork (`github.com/thedracle/iroh`, public)

| Branch | SHA | Base | Purpose |
|---|---|---|---|
| `hop-relay-fix-0.97` | | v0.97.0 | **What WireHop currently pins.** Original commits |
| `wirehop-patches-0.97` | `6a9360fc1e` | v0.97.0 | Same code, cleaned-up messages. Drop-in replacement for the above |
| `relay-cascade-fix` | `493faadda5` | `main` (1.1) | Upstream PR #1 |
| `addr-filter-direct-addrs` | `82f9f465d8` | `main` (1.1) | Upstream PR #2 |
| `wirehop-patches` | `2b5253dffb` | `main` (1.1) | Both, for pinning if we ever move to 1.1 |

The three `main`-based branches each compile clean, carry **zero clippy
warnings**, and pass **116 iroh lib tests**.

`relay-cascade-fix` changes `test_active_relay_reconnect`, which asserted the
old behaviour directly (it passed an empty `local_ips` and expected a
reconnect). It is renamed to `test_active_relay_connection_check_keeps_connection`
and asserts the connection is pinged and survives. Any upstream PR must be
upfront about that.

## Both bugs are still present upstream

Verified against `main` @ `3677ec6210` (1.1.0):

| | Status in 1.1 |
|---|---|
| `CheckConnection` tears down on IP mismatch | still `break Err(LocalIpInvalid)` |
| Immediate reconnect after established drop | comment still reads "attempt to reconnect immediately" |
| Rebind rate limit | none, 0 matches for cooldown/rate-limit |
| `addr_filter` on direct addresses | `store_direct_addresses` still unfiltered |

So the PRs are current and still needed; they are not stale 0.98-era work.

## crates.io is blocked, and public repos do not help

`cargo publish` rejects **any** git dependency, regardless of repository
visibility. Demonstrated with the public fork URL:

```
error: all dependencies must have a version requirement specified when publishing.
  dependency `iroh` does not specify a version
  Note: The published dependency will use the version from crates.io,
  the `git` specification will be removed from the dependency declaration.
```

That last line is the trap: adding `version = "0.97"` alongside the git URL
makes it publish successfully **against crates.io's unpatched iroh**, silently
dropping both fixes. Worse than failing.

Options considered, and why each is closed:

- **Vendor `iroh/` into the repo as a path dependency.** Same rejection. A path
  dep is only allowed when it also carries a `version` that resolves on
  crates.io, which is how our own workspace publishes `hop-core` -> `hop-vt`.
  Vendoring only works if the vendored crate is itself published.
- **Publish a renamed fork (`wirehop-iroh`).** Closer than it looks: our patches
  touch only the `iroh` crate, and `iroh` depends on its siblings by version, so
  a published fork would pull stock `iroh-base`/`iroh-relay`. But `iroh-docs`
  depends on `iroh ^1` from crates.io, so the graph gets two different `iroh`
  crates and `iroh_docs` will not accept our `Endpoint`. Fixing that means
  renaming `iroh-docs`, `iroh-gossip` and `iroh-blobs` as well: four crates to
  track against an upstream that ships every few weeks.
- **Get the fixes upstream.** The only clean unlock. Then drop `[patch]`
  entirely and depend on released crates.

Until then: ship via `install.sh`, npm, the macOS `.pkg`s and ghcr, all of which
work fine with a git dependency, and say plainly that `cargo install` is not
supported yet.

## Migrating to 1.1: actual scope

Attempted 2026-08-27, reverted. **15 compile errors in `hop-core` alone**
(`hop-cli` and `hop-mcp` not yet assessed). Nothing turned out to be a blocker;
it is ordinary 1.0-cleanup churn plus two relocations.

| Error | Count | Nature |
|---|---|---|
| `presets::N0` not found | 3 | preset API cleanup |
| struct takes 0 generic args but 1 supplied | 2 | signature change |
| cannot create non-exhaustive struct | 2 | must use builders |
| `iroh_relay::server::AccessConfig` unresolved | 2 | relocated, see below |
| `Access::Deny` now a struct variant | 1 | relocated, see below |
| `MdnsAddressLookup` not found | 1 | relocated, see below |
| `set_max_remote_nat_traversal_addresses` renamed | 1 | now `max_remote_nat_traversal_addresses` |
| `Endpoint::reset_node` not found | 1 | removed or renamed, unresolved |
| type mismatch in closure arguments | 1 | follows from AccessControl change |
| function takes 0 args but 1 supplied | 1 | signature change |

Also required: bump `iroh-docs` 0.97 -> 0.101, `iroh-gossip` 0.97 -> 0.101,
`iroh-blobs` 0.99 -> 0.103, and `hop-core`'s own direct `iroh-relay` pin
(0.97 -> 1.1, otherwise `ed25519-dalek` conflicts: iroh 1.1 wants `>=3.0.0-rc.0`
while iroh-base 0.97 pins `=3.0.0-pre.1`).

### Two things that look like lost features but are not

Both were initially misread as removals. They are relocations:

- **mDNS address lookup.** Extracted in `5dc3a064ca` to
  **`iroh-mdns-address-lookup`** (crates.io, 0.5.0), explicitly "to keep it out
  of the 1.0 API". The `address-lookup-mdns` cargo feature is gone; add the
  crate instead. This matters because mDNS is what fixed the Tart federation
  flakiness and cut founder-restart recovery.
- **Relay access control.** `AccessConfig::Restricted(closure)` became a
  `DynAccessControl` trait on `RelayConfig::access`, with the same
  `Access::Allow`/`Access::Deny`. The member-only relay
  (`hop-core/src/net/relay.rs`) maps onto it; it is a rewrite of that one
  function, not a lost capability.

## What upgrading would buy

- **n0's public relays become usable.** Measured: the 0.97 client repeatedly
  times out against `use1-1.relay.iroh.network` (`Failed to connect to relay
  server: timeout (>10s)`), while connecting to `relay.keik.ai` instantly. That
  is a relay-protocol version gap. On 1.1 we could add n0's relays as fallbacks
  and get EU/APAC points of presence, instead of relaying everything through one
  Hetzner box in Hillsboro.
- **Dropping `[patch.crates-io]`**, if the PRs land, which in turn is the only
  route to crates.io.

Note the positioning tradeoff on n0 relays: "no third party, including us" is a
homepage claim, and n0 would be able to observe that two node IDs exchange
traffic and roughly how much (not contents). Also, iroh picks its home relay by
lowest latency, so with both configured most users would land on n0 and
`relay.keik.ai` would go mostly unused. Adding them as explicit *fallbacks*
rather than latency competitors would keep the default path, if `RelayMode` can
express that.

## Recommended sequencing

1. **Stay on 0.97.** Launch does not depend on any of this.
2. Open the two upstream issues, then draft PRs from the `main`-based branches.
   `CONTRIBUTING.md` asks for an issue first and PRs opened as drafts; title
   format is `type(crate): description`. Note there is a
   `Frando/addr-filter-combinator` branch upstream, so a maintainer is already
   working in that area: for PR #2 especially, an issue describing the symptom
   will land better than an unannounced PR.
3. Migrate to 1.1 as its own task, gated on the full e2e suite plus
   `session-resilience.sh` and `soak-resilience.sh`, when the launch is not
   riding on it.
4. Revisit crates.io only after the PRs merge.
