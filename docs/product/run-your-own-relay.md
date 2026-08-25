# Run your own relay

hop nodes connect peer-to-peer. When two machines can hole-punch a direct path,
traffic never touches a relay. A **relay** is the fallback: it helps peers discover
each other and carries traffic when a direct path can't be established (strict NATs,
asymmetric firewalls). By default hop uses a public relay for this. `hop host
--relay` lets you run your **own** relay so your warren never depends on someone
else's infrastructure — and, because it is **member-only**, it is not free transport
for strangers.

## Why a member-only relay

A public relay is open by design: anyone who learns its URL can use it as a transit
hop. That is fine for a shared community relay, but for your own warren you usually
want the relay to serve **only your members**. `hop host --relay` gates every
incoming endpoint against the warren roster — a non-member is rejected at the
handshake (`AccessConfig::Restricted`). This closes the "open-relay problem": your
relay's bandwidth is yours.

The relay is **blind** regardless of gating: every byte it carries is end-to-end
encrypted by iroh. The relay only ever sees ciphertext — it cannot read your
traffic. Member-gating controls *who may use the transport*, not confidentiality.

## Start a relay

Run it on any warren host (typically one with a stable public address):

```bash
hop host --relay                 # member-only relay on :3340 (HTTP)
hop host --relay --relay-port 8443
```

You'll see in the log:

```
relay: member-only BYO relay up on http://0.0.0.0:3340 (members point HOP_RELAY_URL here)
```

The host keeps doing everything it did before (shell, exec, transfer, VPN); the
relay is additive. If the port can't bind, the relay is skipped and members fall
back to the public relay — it never blocks the host from serving.

## Point members at it

Each member that should use the relay sets `HOP_RELAY_URL` to the relay's address:

```bash
HOP_RELAY_URL=http://relay.example.com:3340 hop host
```

Or persist it in the daemon's environment (systemd `Environment=`, launchd
`EnvironmentVariables`, or the container's `-e`).

## The join caveat (important)

Membership is what the relay gates on — but a node that **hasn't joined yet is not a
member**, so it cannot use the member-only relay for the join itself. Resolve this
one of two ways:

1. **Join over a direct path.** If the joining node shares a network with the
   founder (or any reachable warren host), the join uses that direct path and the
   member-only relay is never needed. After joining, the node is in the roster and
   the relay admits it.
2. **Join via a fallback/public relay.** Leave `HOP_RELAY_URL` unset (or pointed at
   the public relay) for the first `hop connect … --warren`, then switch it to your
   BYO relay once the node is a member.

The admit-set refreshes from the roster every `HOP_RELAY_REFRESH_SECS` (default
`15`), so a freshly-joined member becomes admittable within that window. Lower it
for tighter convergence (e.g. `HOP_RELAY_REFRESH_SECS=3`).

## What's gated, and how

| Aspect | Behavior |
|---|---|
| Admit decision | endpoint is in the warren roster (members) **or** is this host itself → **Allow**; otherwise **Deny** at the handshake |
| Source of truth | the host's live netdoc roster (`list_peers`) + self, refreshed every `HOP_RELAY_REFRESH_SECS` |
| Endpoints admitted per member | **both** the main host node-id (hop/3 connect) **and** the netdoc/VPN endpoint id (iroh-docs sync + the `hop/vpn/1` data plane, recorded in `peer/N.vpn_endpoint`) — each hop node registers two endpoints with its relay |
| Confidentiality | always end-to-end encrypted by iroh — the relay sees only ciphertext |
| Transport | HTTP/WebSocket (no TLS on the relay's own endpoint by default) |

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `HOP_RELAY_URL` | public relay | The relay a node registers its home/fallback path with — point members here |
| `HOP_RELAY_REFRESH_SECS` | `15` | How often `--relay` rebuilds its admit-set from the roster |

## Limitations / follow-ups

- **No TLS yet.** The relay serves plain HTTP. Confidentiality is unaffected (iroh
  E2E encryption), but an internet-facing relay behind an HTTPS terminator / native
  ACME is a follow-up.
- **QUIC discovery path disabled.** The relay runs the HTTP/WebSocket relay only
  (`quic: None`); this is sufficient for relayed transport and fallback.

## Verifying

`tests/e2e/byo-relay-e2e.sh` proves the end-to-end behavior: a `hop host --relay`
founder bridges two members on **disjoint** networks (so the only possible path is
the relay), and the gating is checked deterministically by the
`member_gating_admits_members_denies_strangers` unit test in
`crates/hop-core/src/net/relay.rs`.
