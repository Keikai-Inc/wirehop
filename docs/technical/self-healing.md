# Self-healing and automatic recovery

The plan for making hop recover from every failure class without a human:
no `hop recover`, no `hop agent stop`, no restart of the other side. hop runs on
embedded devices and short-lived containers where nobody is around to do those
things, and often no launchd/systemd either.

Builds on [host-resilience.md](host-resilience.md) (host endpoint guards, the
inbound probe, `hop recover` without root) and the gate harnesses in
`tests/e2e/` (`soak-resilience.sh`, `session-resilience.sh`).

Status: everything below is **(Planned)** unless a row says otherwise.

---

## The 2026-10-12 incident

A laptop member and the RexMundi founder, both on 0.9.40.

| Symptom | Cause | What recovered it | Why nothing automatic did |
|---|---|---|---|
| Warren VPN dead both ways (ping/ssh to vIP) for weeks | The member's netdoc endpoint stopped completing `hop/vpn/1` dials; the founder's dials to it failed too | `hop recover` on the **member** (restarting the founder did not help) | The dial error is logged at `debug` and counted as `DROP no route/endpoint`; the inbound probe covers only the host endpoint; no member-side probe exists |
| `hop <host>` shell slow and hanging while ssh-over-VPN was real-time | The client agent's long-lived pooled connection was on a degraded path | `hop agent stop`, reconnect | The agent's zombie watchdog only fires on **zero** received datagrams; 5 s keepalives keep that counter moving on a bad path |
| Stdin dead in one of two windows, moving between them; stdout fine | `read_setup_messages` ran the non-cancel-safe `proto::read_message` under a 2 s `timeout`; a timeout mid-frame desynced the session's input stream. Evidence: 267 of 355 `No data from client for 75s` detaches in RexMundi's log fired 74–77 s after a resume, with no re-attach in between (the session never decoded one message), while another session on the same connection kept working. Reproduced in a unit test (the old path reads payload bytes as a 1.95 GB length). **Fixed** (see Phase 2). | Host's 75 s read deadline, then reconnect (which re-rolls which window breaks) | No echo of client heartbeats, so the client cannot see a one-way stall |
| Every shell lost on `hop recover` | The privsep monitor drops its PTY master after passing the dup to the worker (`privsep/mod.rs` `spawn_session`), so the worker's exit hangs up every shell | Not recoverable; `hop sessions restore` relaunches | — |
| Client stuck forever after the host restarted | An await with no deadline in the client/agent reconnect path (sample: all threads parked, stdin reader in `read`) | `kill` | Stripped release binary; no deadline |
| Worker exited 10 s after a restart (`endpoint driver … internal error`) | Unknown | privsep monitor respawn (fast failure 1/3) | Worked as designed; cause still open |

Found while gating the first fix: `vpn-e2e.sh`'s REBOOT TEST had been failing on
every build including 0.9.40, and `run.sh` does not run it, so nothing noticed.
An admin member that restarts anchored C1 on its own author and lost the VPN for
good (fixed; see "The founder-author anchor" in warren-internals.md). The new
dial WARN named the cause on its first run. Its Phase 4 checks had not run
since `73ae567` moved the warren grant out of the invite token; the read-scope
check now reads the member's stored ticket instead.

### Found while building the probes (2026-10-12)

| Finding | Effect | Fix |
|---|---|---|
| The agent quality probe pinged connections that were blacked out | Recovery after a 25 s blackout went from ~2 s to 24–30 s in 3 of 17 `zombie_path` cycles (0 of 13 with the probe off) | Skip a probe when no datagram arrived since the last one (the zombie watchdog's case); 20 of 20 cycles then recovered in ≤ 1.8 s |
| `mux::restart_user_agent` removed `agent.sock` even with no user agent recorded | Where the client shares its config dir with the host daemon (containers, single-config installs), three failed dials deleted the **daemon's** mux socket, so every later connect spawned a user agent: a second endpoint under the same node id | Only remove the socket after killing a recorded user agent |
| `run_agent` unlinked any existing `agent.sock` | A second agent orphaned the first (connections and probes still running), and an agent could take the daemon's mux socket | Exit if the socket answers; only a dead socket is stale |
| The daemon mux and user agents shared `<config>/agent.sock` | With client and daemon on one config dir, whichever bound last left the other listening on an unlinked socket: an unreachable daemon mux, or an orphaned agent holding a second endpoint under the node id | The daemon mux listens on `mux.sock` (plus `agent.sock` only in the system config dir, for older clients); clients try `mux.sock` first and wait for it while `daemon.sock` answers |
| A user agent outlived the daemon starting beside it, and its shutdown removed `agent.sock`/`agent.pid` unconditionally | Orphans, and one agent's exit unlinking another's socket | A user agent exits once `mux.sock` answers and it has no sessions; it removes its socket only if nothing answers there and its PID file only if it holds its own PID |
| The client could not see a stalled client→host direction | After a path change (direct path blackholed, relay up) a freshly dialed connection carried host output but not client input — most likely the transport keeping that stream's data on the dead direct path and backing off its retransmits (open: a transport-level issue). The host gave up at its 75 s read deadline while the client, still receiving, never reconnected (`relay_pinned`: 61–64 s, 4 of 4) | Heartbeat echo: the host answers a mid-session `Ping` with `Pong`. Once any `Pong` has arrived in the process, the client pings every 5 s and reconnects on a fresh stream when 12 s pass with no `Pong` **while host messages still arrive** (a true one-way stall; a full blackout is left to the read deadline, since reconnecting early only lands in the backed-off tier). Old hosts never answer, so the client stops probing after 3 heartbeats. `relay_pinned` now recovers in 1.7–2.4 s |
| A network-change pool flush closed connections dialed after the change | netmon signals ~2 s after it sees a change; by then the client had redialed on the new network, and the flush dropped that session 2–3 s after it recovered, tripping flap backoff (`net_flap`: 2 of 10 cycles at ~30 s) | The flush spares connections dialed in the last 5 s (`FLUSH_SPARES_YOUNGER_THAN`); `net_flap` 10 of 10 ≤ 2.4 s, no flapping |
| A requested restart without a supervisor ended the daemon | Every self-restart path (reachability probe, VPN ladder, `hop recover`) exits and relies on the privsep monitor, launchd or systemd; a container's PID 1 or an embedded device with no init has none, so self-repair killed hop | `finish_requested_restart`: a non-worker re-executes itself in place (same pid, current binary). Every fd is marked close-on-exec first — the TUN fd is not, and each re-exec otherwise left the old `tun0` and its route alive and unread, black-holing the VPN |
| iroh's `Endpoint::close` can panic on shutdown (`JoinSet::join_all` sees a cancelled relay task, "task N was cancelled") | With `panic = "abort"` a requested restart died of SIGABRT (worker exit 134), which the monitor counted as a fast failure toward its crash-loop fallback | A panic hook completes the restart (exit 0 / re-exec) when one is in progress; other panics are unchanged. The real fix belongs in the iroh fork's relay actor (drain with `join_next`, tolerate cancelled) |
| `HOP_PRIVSEP=0` turned privsep **on** | The gate tested presence, not value | `0`/`false`/`off`/`no`/empty mean off |
| The VPN probe trusted `vpn_last_rx`, which an inbound accept seeds | A peer redialing a node whose data plane is dead kept it looking "fresh", so the probe never dialed and the ladder never escalated | `vpn::LAST_DATAGRAM`: written only when a datagram is delivered (≤ 1 write/s/peer); the probe's freshness uses it |
| A dial started during an outage ran to its 10 s timeout after the path returned | Its QUIC handshake retransmits were asleep in exponential backoff; recovery took two dial timeouts (`zombie_path` after `net_flap`: 21–23 s, 3 of 6) | `agent.rs::hedged_dial`: a fresh dial alongside at 3 s and 6 s, first to complete wins, inside the same 10 s budget; 6 of 6 ≤ 0.8 s |
| `privsep-e2e.sh` failed on every build up to 0.9.40 (found by running the harnesses nobody ran) | `hop connect <invite> --warren` judged the redemption by the `true` exec that carries it; a host that won't run commands as the invite's bound user (a uid < 1000 service account) refused the exec after granting membership, so the join failed and the node founded a warren of its own | Join on the grant, not the exec outcome (WARN when the exec was refused); `privsep-e2e.sh` passes. Open: `first_regular_user` accepts uid ≥ 500 (macOS) while the Linux monitor refuses < 1000 |
| Only `run.sh` was in the documented merge gate | `vpn-e2e.sh` and `privsep-e2e.sh` were each broken for releases without anyone noticing | `tests/e2e/gate.sh` runs `run.sh`, `vpn-e2e.sh` and `session-resilience.sh`; AGENTS.md documents it as the gate |
| `session-resilience.sh` claimed the client routed through the member daemon's mux | Because of the rows above it had been running through stray user agents, so the daemon-mux path real clients use on a host was untested | Fixed by the rows above, and the harness now FAILs if any user agent runs on the member. It also keeps `agent.log`, creates its `HOP_DUMP_LOGS` dir, has `HOP_KEEP_CONTAINERS=1`, and gained `degraded_path` and `relay_pinned` |

## What the incident says about the design

1. **Health was inferred from proxies.** Datagrams arriving, relay HTTPS up, endpoint bound: all green for weeks while the VPN and the shell path were useless.
2. **One component had a watchdog.** The inbound probe covers the host endpoint. The netdoc endpoint, the member side and the client agent have none.
3. **The harnesses test short, total outages.** 8–25 s flaps, restarts, blackholes. Not slow rot (hours to weeks) and not a degraded-but-alive path.
4. **Recovery is expensive, so it is avoided.** A worker restart kills every shell.
5. **Unbounded waits.** Several setup/reconnect/IPC awaits have no deadline.

## Principles

| Principle | Meaning |
|---|---|
| Health = work completed end to end | A ping/pong round trip, an acknowledged keepalive, an echoed byte. Never "packets arrived" or "socket bound". |
| One escalation ladder per component | detect → nudge (re-discover) → rebuild the connection → rebuild the endpoint in-process → restart the worker. Rate-limited, backed off, and never tears down a working session to fix a different component. |
| Restarts are cheap | So the ladder can use them. Shells survive a worker restart. |
| Healing is visible | Every recovery action is counted, logged at WARN, and shown in `hop status`. A system that heals every five minutes is still broken. |
| No unbounded awaits | Every await on a network, IPC or setup path has a deadline. |
| No supervisor assumed | Containers and embedded targets may have no launchd/systemd. Recovery must work in-process. |
| Detect before the user does | Health is probed continuously in the background, not discovered by the first packet or keystroke. An idle VPN or an idle agent connection is still checked, and a degraded one is replaced before anyone uses it. |

---

## Phase 1: Visibility

| Item | Detail |
|---|---|
| Health registry | One in-process registry (`hop-core::health`): per component (host endpoint, netdoc endpoint, each VPN peer, each agent connection, relay) the last real success, RTT/loss where known, and a recovery-action log. The existing `net::health` counters move into it. |
| `hop status` (**shipped**) | `status.rs`: host health over the daemon socket + the agent's `agent-health.json`, a problem list (`assess`, unit-tested), exit 1 on any problem. `hop doctor` (guided repair) remains Planned. |
| VPN dial failures (shipped) | `crate::health` records every VPN dial outcome per peer. First failure of a streak and then every 5 min: WARN with the error; recovery: INFO. `hop debug net-stats` shows a `VPN DIALS` section (`health` in `--json`), read over a new `DsRequest::Health` whose payload is JSON so the registry can grow across versions. The drop stays counted under `no route/endpoint` so existing dashboards keep their totals. |
| Agent connection status | `hop agent status` shows, per host connection: age, direct/relay, RTT, loss, last ping/pong. |
| `hop fleet list` hint (**shipped**) | When every other member is offline from this node, a note points at `hop status`. |
| Symbolicated samples (**shipped**) | `profile.dist` (release + line tables, unstripped) is what the release workflow builds; it splits the symbols from the very binary it ships — `dsymutil` → `hop-darwin-*.dSYM.zip`, `llvm-objcopy --only-keep-debug` → `hop-linux-*.debug` (+ a debuglink) — strips, and publishes both next to the binary. Verified locally: a `sample` of a stripped `dist` binary with its `.dSYM` beside it names every frame with file:line (the field sample on 2026-10-12 was all `???`); see the Linux check below. The release workflow itself can only be exercised by a release. |
| Memory trend (**shipped**) | The daemon samples its own RSS every 5 min into the health registry (24 h ring; `/proc/self/status` on Linux, `proc_pidinfo` on macOS); `hop status` shows the least-squares slope and flags ≥ 20 MB/h over ≥ 3 h. In memory only, so the trend restarts with the worker. |

## Pre-emptive detection

Both 2026-10-12 failures were found by a person trying to use the path. The
VPN had been dead since at least 2026-09-25 with nothing on it to notice. The
probes below run whether or not anyone is using the path, and feed the Phase 2
ladders, so a failure is usually repaired before the next use.

| Probe | Runs on | What it measures | Healthy | Acts on failure |
|---|---|---|---|---|
| VPN peer probe (**shipped**) | every node with the VPN up, every ~60 s jittered (`HOP_VPN_PROBE_SECS`) | `NetDoc::vpn_probe_round`: for each roster peer with a VPN endpoint and no VPN traffic in the last 30 s, dial its **host** endpoint with `hop/probe/1` and its VPN endpoint with `hop/vpn/1` (10 s each, concurrently). A peer whose host answers is a *witness* | The VPN dial succeeds to at least one witness | `conn_quality::VpnLadder` in `main.rs::spawn_vpn_peer_probe`: VPN failed to **every** witness for 3 rounds → re-discovery on the netdoc endpoint; 5 rounds → worker restart (≤ 1 per ~30 rounds). No witnesses (peers offline) or one bad peer among good ones → nothing. Per-peer results and the ladder state are in the daemon's `Health` (`hop debug net-stats --json` → `health.vpn_probes`, `health.vpn_ladder`) |
| Roster coverage | founder and members | Folded into the VPN peer probe: "reachable over the host endpoint but not over the VPN, for every witness" is the "this node is the broken one" signal | — | As above. Planned: the `hop fleet list` hint, and in-process endpoint rebuild in place of the restart (Phase 3) |
| Agent connection quality (**shipped**) | client agent (and the host daemon's mux pool), every pooled hop/4 connection, including idle ones, every ~15 s jittered | `Ping`/`Pong` RTT through the host's stream path, and the selected path (direct/relay) | `conn_quality::QualityTracker`: not 3 bad probes in a row, where bad = unanswered, or ≥ 3× and ≥ +250 ms over the connection's best recent RTT, or on the relay after direct worked | `agent.rs::spawn_quality_probe`: dial + ping a replacement; swap it in (`AgentCommand::ReplaceConnection`, only if the measured connection is still pooled) when clearly better, closing the old one so its sessions resume on the new; otherwise keep the old one and rebase. ≤ 1 attempt / 2 min. Visible in `hop agent status` (`agent-health.json`) and the daemon's `Health`. Loss/retransmit counters are not used yet. |
| Path upgrade check | client agent, VPN | A connection stuck on the relay while a direct path to the same peer has worked recently | Direct within N min of a relay fallback | Ask iroh to re-run hole punching (`network_change` / path reset); dial fresh if it does not upgrade |
| Shell stream echo | client, per live session | Host echoes the client heartbeat on the session's stream | Echo within 30 s | Reconnect the session (new stream, same session id) |
| Host-endpoint self-probe (shipped) | host | Throwaway endpoint dials this host through the home relay | Handshake | Existing ladder in host-resilience.md |

Rules for every probe:

| Rule | Why |
|---|---|
| Probes are cheap and jittered | Embedded and battery devices; a fleet must not synchronise its probes onto the relay |
| Compare against the connection's own baseline, not a fixed threshold | A satellite link's normal is a fibre link's outage |
| Replace before tearing down | A degraded path still carries traffic; the old connection stays until the new one has answered (the 2026-09 lesson: a 2 s ping that tore down every session on a slow path made things worse) |
| Every probe result lands in the health registry | `hop status` shows when each path was last proven and by what |

## Phase 2: Per-component self-healing

| Component | Detection | Ladder |
|---|---|---|
| Agent pooled connection | Periodic ping/pong RTT plus `conn.stats()` loss/retransmits; degraded = RTT or loss above threshold for N s, or a ping unanswered | Mark degraded → dial a fresh connection → new sessions use it; live sessions move at their next reconnect. Also redial when the host's daemon restarts (new endpoint) instead of reusing the survivor. |
| netdoc / VPN endpoint, founder **and** member | **Shipped:** the VPN peer probe above (witness = peer whose host endpoint answers) | **Shipped:** re-discovery → worker restart. Planned: in-process netdoc endpoint rebuild before the restart (Phase 3). Proven by `vpn-e2e.sh`'s SELF-REPAIR stage: a member whose VPN data plane is wedged (test-only `HOP_FAULT_VPN_WEDGE_FILE`; outbound dials fail, VPN datagrams dropped both ways, host endpoint fine — the 2026-10-12 laptop) detects it, restarts itself and routes again in ~73 s at a 10 s probe interval, with no manual step |
| Interactive shell | Host echoes Input heartbeats so the client sees a one-way stall in ~30 s | **Shipped:** cancel-safe setup read — one `FramedReader` per attachment, used by `read_setup_messages` (one 4 s budget for the batch) and then handed to `run_attached_loop`, the view loop and the legacy V0 loop, so a frame the setup read left half-done is finished, not misparsed (`shell::setup_read_tests`). **Shipped:** heartbeat echo (`Ping`/`Pong` mid-session, armed by the first `Pong`, 30 s one-way stall → reconnect). **Shipped (unbounded awaits):** a sweep of the client connect/reconnect/IPC paths found every await bounded except two, now fixed: the input replayed on resume was written inline before the session loop (no deadline, nobody reading — able to deadlock client, agent and host against each other); it now goes through the loop's writer task. The agent's `open_bi` held the per-host semaphore with no deadline; it is now bounded (10 s) and raced against the client leaving. The deadlock was found by reading the code and matches the frozen client's sample (every thread parked, no timer); `session-resilience.sh`'s `paste_restart` (a 64 KB paste replayed across a host restart) passes before and after, so it is not a reproduction. **Shipped:** a proxy whose client process is gone (its socket fully closed) now ends even if the host never sends again — it used to park forever on the QUIC read, and the leaked proxy kept the host's session count up, turning every reconnect's evict-and-dial-fresh into a no-op. A client that only finished its input (`hop exec cmd < /dev/null`) keeps its output (`agent.rs::client_gone`, two tests over real QUIC). |
| Agent dial | — | **Shipped:** `do_connect` steps down from hop/4 only on an ALPN refusal (TLS alert 120). It used to step down on any non-timeout error, so one handshake aborted on a flaky path pinned the pooled connection to an older protocol for its life and switched off the hop/4 `Ping` check. |
| Worker | Monitor liveness (already detects fast failures) | Restart with backoff; crash-loop detection reported, not silent |

## Phase 3: Cheap restarts

| Item | Detail |
|---|---|
| Monitor keeps PTY masters (**shipped**) | The privsep monitor keeps a dup of each session master (dropped when its reaper sees the shell exit, or on `ReleaseSession` when the worker removes the session). A new worker sends `AdoptSessions` (only when the monitor advertised `HOP_PRIVSEP_CAPS=adopt-sessions` — an older monitor treats an undecodable request as the worker exiting), matches each master to its checkpoint entry by PTY slave name (`CheckpointFile::ttys`, JSON-only), and registers it detached under its original id. With the capability, every persistent session is spawned through the monitor, including a root worker's (containers without a `hop` user). A clean worker exit no longer counts as a crash-loop fast failure. Proven by `session-resilience.sh`'s `worker_restart`: `hop recover` on the founder, and the client resumes the same shell. Limits: screen history is lost (the screen restarts empty); a session younger than the last checkpoint at an unclean exit is left running in the monitor, unreachable, until it exits. |
| Non-privsep hosts | A requested restart re-executes in place (see above), so the daemon survives it; its shells do not (no monitor holds their PTYs). Planned: keep session PTYs across the re-exec (inherit their masters through the exec) |
| In-process endpoint rebuild | Rebuilding the host or netdoc endpoint without a process restart, so most recoveries never touch sessions. Required where no supervisor exists. |

## Phase 4: Proof

| Harness addition | Covers |
|---|---|
| Degraded path (tc netem 5–30 % loss, 300 ms+ delay) in `session-resilience.sh` and `soak-resilience.sh` | The agent-connection case |
| Endpoint wedge (test-only fault hook that freezes one endpoint's dials/accepts) | The netdoc case |
| Member-side failure, not only founder | Who has to restart |
| Client across a host restart, asserting no stuck client (**shipped** as `paste_restart`) | The unbounded-await case |
| Worker crash shortly after start (**shipped**, `privsep-e2e.sh`) | A test-only `HOP_FAULT_WORKER_CRASH_FILE` makes the worker die at startup; the monitor counts the crashes (not the requested restart before them), falls back to a non-privsep daemon after 3, and the node routes again |
| `vpn-e2e.sh` in the standard gate (`run.sh` or CI): it is the only suite with a real TUN, and a failure in it went unnoticed across releases | VPN regressions |
| Long soak (**shipped**, `long-soak.sh`; scheduling Planned) | One long-lived founder/member pair under randomized perturbations for `SOAK_HOURS` (all of `session-resilience.sh`'s, in random order), no manual step; fails on any recovery over budget or timed out, a stray user agent, the founder's crash-loop fallback, or a steady memory climb on either node (`hop status`, ≥ 20 MB/h over ≥ 3 h). Results in `long-soak-results.md`. Running it nightly needs a Docker-capable runner; CI does not run e2e today |
| Embedded/container profile (**shipped**, `embedded-profile.sh`) | `hop host` as a container's PID 1 with no privsep and no init, read-only root, 128 MB cap, pid limit: joins and routes, ~18 MiB resident, `hop status` healthy, `hop recover` re-executes in place, a wedged VPN self-repairs by re-exec (~45 s at a 10 s probe), and 5 members that join and vanish within a minute do not make the founder escalate. Not covered yet: clock jumps |

Results are committed as `*-results.md` like the other gate harnesses.

---

## Order

| Step | Content |
|---|---|
| 1 | Phase 1 visibility (dial-failure WARN + counter first); pre-emptive agent-connection quality probe with background replacement |
| 2 | Pre-emptive VPN peer probe + roster coverage driving the netdoc/VPN ladder on founder and members; shell setup + deadlines + stream echo |
| 3 | Phase 4 degraded-path and endpoint-wedge harnesses (before Phase 3, so Phase 3 is measured) |
| 4 | Phase 3 PTY-surviving restarts and in-process endpoint rebuild |
| 5 | Phase 4 long soak and embedded profile as a standing release gate |

Every step ends with `REBUILD=1 ./tests/e2e/run.sh` plus the relevant harness.
