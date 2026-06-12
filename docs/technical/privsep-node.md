# Privilege-Separated Warren Node (Design)

> **Status: Phase 1 implemented (flag-gated `HOP_PRIVSEP`, off by default),
> Linux-validated end-to-end; Phases 2–4 planned.** The monitor/worker split, the
> `SCM_RIGHTS` fd-passing, the 3-primitive control protocol with its validation
> boundary, and the worker's passed-fd TUN wrapper all ship and are exercised by
> `tests/e2e/privsep-e2e.sh` (two privsep nodes route real packets over the
> monitor-passed TUN fd). In Phase 1 the worker still runs as root — the `_hop`
> privilege drop (Phase 2) and the `SpawnSession` setuid relocation (Phase 3) are
> the remaining work. **macOS feasibility gate (§8.1) is still unrun** — the
> Linux e2e proves the mechanic, but a passed *utun* fd surviving non-root I/O on
> macOS (the B-full vs B-lite decision) is unverified, so privsep must not be
> activated on macOS hosts yet.
>
> Goal: shrink the warren node's root attack surface from
> "the entire daemon" to a minimal, non-network-facing privileged monitor, while
> the large, attackable, network-facing daemon (QUIC, protocol parsing, the
> netdoc replication stack, the VPN data plane, DNS logic) runs as an
> unprivileged service user. This is the OpenSSH privilege-separation model
> applied to `hop host`. It preserves all node capabilities (addressable vIP,
> full mesh, kernel-TUN performance, MagicDNS, host sessions) while making a
> remote code-execution bug in the network-facing code a compromise of an
> unprivileged service account, **not root**.
>
> This is the chosen direction (option **B** from the user-level-reach
> discussion): full node capability with a minimal root surface, as opposed to a
> userspace netstack (option A, zero-root but non-transparent / slower).

## 1. Why the daemon is root today, and why that's too much

`hop host` runs entirely as root. But root is needed for only **three** narrow
operations; everything else is the unprivileged-capable bulk:

| Privileged operation | Where | Why root |
|---|---|---|
| **TUN create + addr/MTU/route** | `vpn/mod.rs:102` `create_tun` (the `tun` crate sets `.address/.netmask/.mtu/.up`); kernel auto-installs the `100.64.0.0/10` route | creating a network interface + writing the route table needs root / `CAP_NET_ADMIN` |
| **Bind `:53` on the vIP (MagicDNS)** | `enable_vpn` spawns `vpn_dns_loop` (`netdoc/mod.rs:1464`) which binds the vIP UDP `:53` | port < 1024 is privileged |
| **Spawn a session as the bound unix user** | `plain_shell` / `sandboxed_shell` → `login -fp <user>` (macOS) / `su - <user>` / setuid+`initgroups` (Linux) — `sandbox/mod.rs:236`, `transfer/helper.rs:60-91` | only root can become an arbitrary user |

Everything else — and it is the overwhelming majority of the code, and **all of
the remotely-reachable attack surface** — needs no privilege:

- The iroh QUIC endpoints (main + the derived netdoc endpoint, `net/mod.rs:131`),
  `accept` loops, ALPN dispatch, protocol decoding (`proto/`), auth handshake.
- The entire netdoc replication stack (iroh-docs/gossip/blobs), reconcile, C1
  author validation, the Cedar reach engine (`vpn/cedar.rs`).
- The VPN data plane: `vpn_outbound_loop` (`netdoc/mod.rs:1570`), the inbound
  `pump_vpn_datagrams` + ingress anti-spoof (`vpn/mod.rs:137`), vIP→endpoint
  resolution, the per-packet parse (`parse_dest_ipv4` etc., `vpn/mod.rs:25`).
- Reading the node's own secret (`identity.json`) and writing its self-doc.

So today a memory-safety bug or logic flaw anywhere in the QUIC/protocol/netdoc/
packet-parsing surface — all of it fed by untrusted remote input — yields
**root**. The privilege the daemon actually needs is three small, well-defined
sysc90l clusters. That mismatch is the whole motivation.

## 2. Threat model

- **T1 — Remote RCE in network-facing code.** An attacker who can reach the
  node's QUIC endpoint (any warren peer, or anyone who can send to the relay/
  direct path) exploits a bug in QUIC, ALPN dispatch, protocol decode, the
  netdoc/iroh-docs stack, or the VPN packet path. *Today → root. Goal → an
  unprivileged service account.*
- **T2 — Local non-service user reads node secrets.** Another local account
  tries to read `identity.json` / the netdoc store to clone the node's identity.
  *Must stay denied (today: 0600 root; after: 0600 `_hop`).*
- **T3 — Compromised worker escalates.** Having popped the unprivileged worker
  (T1), the attacker tries to use the privileged monitor to regain root.
  *The monitor must expose only a fixed, validated set of primitives — never a
  general "run as root".*
- **T4 — Worker abuses the TUN.** The worker holds the TUN fd, so it can inject/
  read warren L3 packets. *This is inherent to any data plane; reach is still
  ACL-gated, and the worker cannot reconfigure interfaces/routes (monitor-only).*

Out of scope: a root-level local compromise (already game over); HSM-backed key
custody (a later evolution — see §9 residual risk).

## 3. Target architecture — monitor + worker

```
              launchd / systemd  (RunAtLoad, KeepAlive)
                        │  starts as root
                        ▼
            ┌───────────────────────────┐
            │  hop-monitor  (root)       │   tiny, NON-network-facing
            │  - owns the canonical TUN  │   only talks to its own child
            │  - holds priv-port :53 fd  │   over an inherited socketpair
            │  - performs the 3 prims    │   no untrusted input
            │  - supervises the worker   │
            └─────────────┬─────────────┘
                          │ AF_UNIX socketpair (SCM_RIGHTS) — private, inherited
                          │ drops privilege → execs worker as _hop
                          ▼
            ┌───────────────────────────┐
            │  hop host  (user _hop)     │   the entire existing daemon
            │  - iroh endpoints, accept  │   MINUS the 3 privileged prims
            │  - netdoc stack, C1, Cedar │   ← all remote attack surface
            │  - VPN data plane (TUN I/O)│   ← runs unprivileged
            │  - DNS logic (on passed fd)│
            │  - reads _hop-owned secret │
            └───────────────────────────┘
```

- The **monitor** is a few hundred lines: create the socketpair, do the three
  privileged primitives on validated request, hold the canonical TUN/`:53` fds
  (so the interface survives worker restarts), supervise + restart the worker.
  It takes **no network input** and never execs anything but the known worker and
  the validated session-spawn helper.
- The **worker** is the current `hop host` codebase, with the three privileged
  call-sites replaced by requests to the monitor. It runs as a dedicated service
  user (`_hop`) and holds the node identity (now `_hop`-owned, 0600).

This is structurally identical to OpenSSH's `sshd` privsep (unprivileged
net-facing child + privileged monitor exposing a small validated API), which is
the canonical precedent for "don't run the parser as root."

## 4. The privileged-primitive protocol (the security crux)

The monitor↔worker channel is a single inherited `AF_UNIX` `SOCK_SEQPACKET`
socketpair (no on-disk path → no other process can connect; created before the
worker drops privilege so the worker inherits one end). The protocol is a
**fixed, closed** set of requests; the monitor validates each and refuses
anything else. Minimality here is the entire security argument for §T3.

**P1 — `CreateTun { vip: Ipv4Addr }` → `fd`.**
- Monitor asserts `vip ∈ 100.64.0.0/10`. Creates the utun (macOS
  `SYSPROTO_CONTROL`) / `/dev/net/tun` (Linux `TUNSETIFF`, `IFF_NO_PI`), sets
  address = `vip`, netmask `255.192.0.0`, MTU `1280`, `up`; kernel installs the
  `/10` route. Sends the fd via `SCM_RIGHTS`. Monitor **retains the canonical
  fd** so the interface + route persist across worker restarts.
- Returned once at worker start. A second `CreateTun` for a *different* vip is
  the multi-home path (§8.7); for the same vip it's idempotent.

**P2 — `BindPrivPort { addr: Ipv4Addr, port: u16 }` → `fd`.**
- Monitor asserts `addr == vip` and `port == 53` (the only privileged port hop
  binds). Binds a UDP socket, sends the fd. Worker runs `vpn_dns_loop` on it.
- Hard-allowlisted to `(vip, 53)` — not a general "bind any port as root".

**P3 — `SpawnSession { user, kind, pty_size, argv… }` → `pty_fd`/streams.**
- The worker authenticates the peer and decides the bound unix user (existing
  auth path). It then asks the monitor to *become that user* and exec the
  shell/exec/transfer helper — i.e. the existing `login -fp` / `su -` /
  setuid+`initgroups` logic (`sandbox/mod.rs`, `transfer/helper.rs`) **moves into
  the monitor**. The monitor re-validates: `validate_username` (`unix_user.rs`:
  format, **not root**, exists), the sandbox policy, the command class — then
  spawns and hands back the PTY/stdio fds. The worker proxies bytes over QUIC as
  it does today.
- This is the part people miss: making the daemon non-root is *not* just the
  TUN — the daemon's core feature (sessions as the bound user) is itself a root
  operation, and it must be brokered, not held.

Everything else the worker does itself (no monitor round-trip): open QUIC
endpoints, replicate the netdoc, resolve vIPs, parse/forward packets on the TUN
fd, enforce the Cedar ACL, write its self-doc.

## 5. File-descriptor passing

hop does **not** pass fds today (grep: no `SCM_RIGHTS`/`sendmsg`/`recvmsg` cmsg
in non-vendor code). We add it on the monitor socketpair using `nix`'s cmsg
helpers (`nix` is already a dependency with the `net` feature). A `SEQPACKET`
socketpair gives message framing for the small control protocol; fds ride as
ancillary data. Because the socketpair is created in the monitor and one end is
inherited across the privilege-dropping exec, there is **no named socket** for a
third party to reach — the channel is private to the monitor/worker pair.

Worker-side TUN I/O does **not** use the `tun` crate's `create_as_async` (that
makes a *new* device). It wraps the *passed* fd: `tokio::io::unix::AsyncFd` over
the raw fd, with manual handling of the macOS utun **4-byte address-family
prefix** (`AF_INET`/`AF_INET6` prepended on write, stripped on read) — on Linux
with `IFF_NO_PI` there is no prefix. This is a small, well-understood amount of
raw I/O code; correctness is covered by a loopback unit test.

## 6. Service user & secret ownership

Introduce a dedicated **`_hop`** service account (created at install; macOS
`dscl`/`sysadminctl` hidden uid < 500, Linux `useradd --system`). Re-own:

| Path | Today | After |
|---|---|---|
| `identity.json` | `root:wheel 0600` | `_hop:_hop 0600` |
| `netdoc/` store (+ self-doc keys, iroh-docs-managed) | root | `_hop` `0700` |
| `netdoc-read.ticket`, `netdoc-founder.*` | root `0600` | `_hop 0600` |
| `peers.json`, `host_config.json`, `roles.json`, `warren-members.json` | `root:admin 0660` | `_hop:hop 0660` (group-readable for the operator's CLI) |
| **`netdoc.ticket` (warren WRITE)** | root `0600` | `_hop 0600` *only if this node is the founder/admin* |

The worker (as `_hop`) reads `identity.json` directly — **no root, no permission
papercut** (this is the same class of bug as the earlier `hop warren status` /
`hop invite` EACCES: those resolve to a root-owned file). The host secret is
still protected from *other* local users (0600 `_hop`).

This composes with the host-admin permission model discussed separately: the
human operator's CLI ops that need the secret/ticket go through the worker's
group-readable `daemon.sock` IPC (or self-escalate via `sudo` for genuinely
root operations), never by reading `_hop`'s 0600 files.

**Key fact (from the audit) that makes this clean:** a plain *node* never needs
the warren **write** ticket or any *other* node's secret. It holds only its own
identity, the admin-doc **read** ticket, and its own self-doc (whose write key
iroh-docs manages inside the `_hop`-owned store). So moving the node's custody
from root to `_hop` exposes only the node's own identity to the `_hop`
account — which is exactly the account that must use it. No admin/founder
authority moves.

## 7. macOS vs Linux specifics

| | macOS | Linux |
|---|---|---|
| TUN | `socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` + connect `UTUN_CONTROL_NAME`; **4-byte AF prefix** on each frame | `/dev/net/tun` + `TUNSETIFF`, `IFF_TUN\|IFF_NO_PI` (no prefix) |
| addr/route | `ioctl` `SIOCSIFADDR`/`SIOCSIFNETMASK` + `PF_ROUTE` socket (root) | `ioctl` / `rtnetlink` (root or `CAP_NET_ADMIN`) |
| become-user | `login -fpq <user> …` — establishes a fresh **audit session** (without it, a bare setuid from launchd's root audit session can't touch user-owned files — `transfer/helper.rs:60`) | setuid+setgid+`initgroups` in `pre_exec`; `su -` for login env |
| `:53` bind | privileged-port, needs root | `CAP_NET_BIND_SERVICE` (the monitor can hold just this cap, not full root) |
| monitor privilege | root (no fine-grained caps) | could be reduced to `CAP_NET_ADMIN`+`CAP_NET_BIND_SERVICE`+`CAP_SETUID/SETGID` ambient — strictly less than full root |

On Linux the monitor can be *capability-bounded* (it never needs full root),
tightening §T3 further. On macOS it must be root, so the monitor's minimality is
the only lever — hence the fixed 3-primitive protocol.

## 8. Edge cases

**8.1 — macOS utun fd usable by a non-root process? (THE feasibility gate.)**
The entire design assumes that after the monitor (root) creates+configures the
utun, a *passed* fd can be `read`/`write`n by the unprivileged worker. The
privilege checks are at socket *creation* (`SYSPROTO_CONTROL` connect) and
*interface configuration* (`SIOCSIF*`), not per-I/O — so this is expected to
work (it's how OpenVPN/Tailscale-style fd hand-off works), but macOS has been
known to re-check entitlements in surprising places. **This must be empirically
proven before any other work** (a 30-line standalone test: root creates utun,
fork+drop to `_hop`, pass the fd, child `write`s an ICMP echo and `read`s the
reply). If macOS *does* re-check on I/O, fall back to either keeping packet I/O
in the monitor (a thinner "B-lite", §10) or option A (userspace netstack).

**8.2 — Worker crash / restart.** The monitor holds the **canonical** TUN/`:53`
fds, so the interface, address, and route **persist** across worker restarts
(no flap). On worker exit the monitor re-spawns it and passes fresh `dup`s. The
worker is otherwise stateless w.r.t. the interface. (The monitor is the launchd/
systemd-supervised top process; it supervises the worker, not the reverse.)

**8.3 — Clean teardown.** On monitor exit (or system shutdown) the canonical fds
close → the kernel removes the interface + its `/10` route automatically. No
stale routes. (`KeepAlive` restarts the monitor; a deliberate stop tears down.)

**8.4 — vIP reallocation.** The vIP is admin-allocated and static
(`peer/N.vip`), so reconfiguration is rare. If it changes, the worker sends a new
validated `CreateTun{vip}`; the monitor reconfigures the interface it owns.
Never the worker (no `CAP_NET_ADMIN`).

**8.5 — Privileged-port `:53`.** Covered by P2; hard-allowlisted to `(vip, 53)`.
If we later add more listeners, each privileged port is an explicit allowlist
entry, not a general capability.

**8.6 — Sessions need root (the non-obvious one).** Covered by P3 — the
setuid-to-bound-user logic moves into the monitor. The worker never holds
setuid. macOS `login -fpq` (audit session) still happens, in the monitor.

**8.7 — Multi-home (future).** Multiple warren memberships → multiple vIPs/TUNs:
the monitor creates N interfaces (N `CreateTun`), passes N fds. The protocol and
ownership model extend unchanged.

**8.8 — Migration on upgrade.** A one-time step re-owns the existing root-owned
config dir to `_hop` (`chown -R _hop`), creates the `_hop` user if absent, and
rewrites the launchd plist / systemd unit to launch the monitor. Must be
idempotent and reversible (back up before chown). The current
`hop __install-daemon` is the natural home for this.

**8.9 — Reboot ordering.** The monitor starts at boot (root), creates the TUN,
spawns the worker (`_hop`); the worker's netdoc/relay reconnect is unchanged
from today (and is the subject of the separate "reachable only after SSH"
investigation — privsep neither helps nor hurts it). The worker starting before
the network is up is the same race as today.

**8.10 — Argument / path injection into the monitor.** Every `SpawnSession`
argument is validated (`validate_username`, allowlisted command classes, no
shell interpolation — exec argv directly, never `sh -c` on attacker strings).
`CreateTun`/`BindPrivPort` take only typed `Ipv4Addr`/`u16` with range checks.
The monitor never reflects worker-supplied paths into privileged exec.

**8.11 — `_hop` compromise blast radius.** If the worker is popped (T1), the
attacker is `_hop`: they can act as **this node's identity** on the warren
(the key is necessarily usable by the data plane), sniff/inject this node's
warren packets, and read `_hop`-owned files. They **cannot**: become root, read
other users' files, reconfigure interfaces/routes, become other unix users
(P3 is monitor-validated and refuses `root`), or obtain admin/founder authority
(a node never holds the write ticket). Reach stays ACL-bounded. Recovery =
revoke the node (`revocation/<node>`), rotate its key.

## 9. Security analysis

**Attack-surface reduction (the headline).** Every byte of untrusted remote
input — QUIC frames, ALPN, the wire protocol, iroh-docs sync, VPN datagrams — is
parsed by the **worker (`_hop`)**. A memory-safety or logic bug there yields an
unprivileged account, not root. The monitor parses only its own child's fixed
3-primitive protocol over a private socketpair; it has **no network surface**.

**Monitor soundness.** The monitor's power is exactly: make-`100.64/10`-iface,
bind-`(vip,53)`, become-a-validated-non-root-user-and-exec-a-known-helper. There
is no primitive that runs attacker-chosen code as root. Each primitive has a
narrow, typed, range/allowlist-checked input. This is the §T3 argument.

**Comparison.**

| Capability if the network code is compromised | Today (all-root daemon) | Privsep (monitor + `_hop` worker) |
|---|---|---|
| Execute as root | ✅ | ❌ |
| Read any local user's files | ✅ | ❌ (only `_hop`'s) |
| Reconfigure host network / routes | ✅ | ❌ (monitor-only, fixed `/10`) |
| Become arbitrary unix users | ✅ | ❌ (P3 validates, refuses root) |
| Act as this node on the warren | ✅ | ✅ (irreducible — the data plane needs the key) |
| Obtain warren admin/founder authority | only if this node is admin | only if this node is admin (unchanged) |

**Residual risk — the node key must be online.** A data plane that forwards
warren traffic inherently needs a usable node key, so an `_hop` compromise can
impersonate *this node*. This is irreducible without an HSM/Secure-Enclave-backed
key with per-operation user-presence (a possible future evolution: keep the key
in the Secure Enclave and have the monitor or a separate signer mediate). The
mitigation today is least privilege (it's only the node's *own* key, never
admin/founder) + fast revocation. Privsep does not make this worse than today;
it makes *everything else* better.

**Receiver-side ACL becomes more important.** Today reach is enforced
sender-side only (`vpn_outbound_loop`, `netdoc/mod.rs:1590`); `warren-gaps.md`
already flags receiver-side enforcement as the intent. With the data plane
unprivileged and the node key potentially reachable via T1, **receiver-side ACL
enforcement** (the receiving worker dropping packets its ACL forbids, regardless
of what a compromised sender does) should land alongside this work — it's the
defense that doesn't depend on every peer's worker being honest.

## 10. Phased plan

- **Phase 0 — Feasibility gate.** Prove a passed TUN fd survives I/O by a
  different uid (§8.1). **Linux: PROVEN** — `privsep-e2e.sh` routes packets over a
  monitor-passed TUN fd, and a TUN fd is uid-agnostic on Linux. **macOS: still
  unrun** — `hop __privsep-probe` (built) must run as root to decide whether a
  passed *utun* fd survives non-root I/O. If it fails on macOS, pivot to B-lite
  (packet I/O stays in the monitor) or option A. macOS activation is contingent on
  this passing.
- **Phase 1 — fd-passing + the monitor skeleton. ✅ DONE (flag-gated, Linux-validated).**
  Stream socketpair (macOS AF_UNIX has no `SEQPACKET`), the `CreateTun`/`BindPrivPort`
  primitives + their validation boundary (warren-range vIP only, `:53` only),
  `SCM_RIGHTS` send/recv (nix cmsg), and the worker-side passed-fd TUN wrapper
  (`tun::Configuration::raw_fd`, wrap-only). `run_monitor` spawns the worker
  (`HOP_PRIVSEP_WORKER` + the control fd) and serves the primitives, holding the
  devices alive for the worker's lifetime. `enable_vpn` calls `acquire_tun` (the
  single integration point); the non-privsep path is byte-equivalent. **The worker
  still runs as root here** — the only change is *who creates the TUN* and that the
  fd crosses the control channel; the privilege drop is Phase 2.
- **Phase 2 — `_hop` service user + ownership migration.** Create `_hop`,
  re-own the config dir, run the worker as `_hop`, plist/unit launches the
  monitor. This is where the EACCES papercuts (`hop invite`/`id`/…) dissolve,
  because the worker reads its own `_hop`-owned secret and the operator's CLI
  goes through the group-readable IPC.
- **Phase 3 — Move `SpawnSession` (P3) into the monitor.** Relocate the
  `login`/`su`/setuid logic from the (now-unprivileged) worker into the monitor;
  the worker requests sessions. This is the larger refactor — until it lands, the
  worker can't host sessions, so sequence it as a single careful change with the
  e2e session tests as the gate.
- **Phase 4 — Hardening + e2e.** macOS daemon-install e2e (the harness we built)
  extended to assert the monitor is root / the worker is `_hop` / sessions still
  work / VPN still routes; Linux container e2e; receiver-side ACL (§9).

## 11. Reused components (don't rebuild)

- **Spawn-as-user** (`sandbox/mod.rs:236` `plain_shell`, `sandbox/macos.rs:165`,
  `sandbox/linux.rs:223`, `transfer/helper.rs:36`) → becomes the monitor's P3.
- **`unix_user`** (`is_running_as_root`, `validate_username`, uid/gid lookup,
  `initgroups`) → monitor's validation.
- **Data-plane loops** (`vpn_outbound_loop` `netdoc/mod.rs:1570`,
  `pump_vpn_datagrams` `vpn/mod.rs:137`) → move verbatim into the worker; only
  `create_tun` is replaced by "use the passed fd".
- **launchd plist / systemd unit** (`pkg/com.hop.daemon.plist`, `pkg/hop.service`,
  the embedded `hop __install-daemon`) → launch the monitor; add the `_hop` user.
- **`nix`** (already a dep) for the cmsg/`SCM_RIGHTS` plumbing.

## 12. Open questions (resolve during Phase 0/1)

1. macOS: does a passed utun fd survive I/O by a different uid? (§8.1 — the gate.)
2. macOS: can the worker bind `:53` on the vIP via a *passed* socket fd, or must
   the monitor also own the socket for the lifetime? (Likely pass-and-use, mirror
   the TUN.)
3. Linux: reduce the monitor from full root to ambient
   `CAP_NET_ADMIN`+`CAP_NET_BIND_SERVICE`+`CAP_SETUID/SETGID`? (Strictly better;
   confirm systemd `AmbientCapabilities` covers the setuid-spawn path.)
4. Does any current code assume the daemon euid==0 beyond the 3 primitives (e.g.
   reading other root-owned files, the datastore IPC socket perms)? Audit before
   flipping the worker to `_hop`.
