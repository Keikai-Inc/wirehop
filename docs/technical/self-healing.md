# Self-healing and automatic recovery

The plan for making hop recover from every failure class without a human:
no `hop recover`, no `hop agent stop`, no restart of the other side. hop runs on
embedded devices and short-lived containers where nobody is around to do those
things, and often no launchd/systemd either.

Builds on [host-resilience.md](host-resilience.md) (host endpoint guards, the
inbound probe, `hop recover` without root) and the gate harnesses in
`tests/e2e/` (`soak-resilience.sh`, `session-resilience.sh`).

Status: **implemented** (2026-10-13). Every row is shipped except the in-process
endpoint rebuild, which was superseded (Phase 3 says why). Evidence: `tests/e2e/gate.sh`
(five suites) passes, and a 2 h randomized `long-soak.sh` ran 96 faults with every
recovery inside its budget and no manual step. The soak now runs nightly
(`.github/workflows/soak.yml`). Shipping it to running hosts is a release and deploy,
outside this plan.

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
| iroh's `Endpoint::close` can panic on shutdown (`JoinSet::join_all` sees a cancelled relay task, "task N was cancelled") | With `panic = "abort"` a requested restart died of SIGABRT (worker exit 134), which the monitor counted as a fast failure toward its crash-loop fallback | A panic hook completes the restart (exit 0 / re-exec) when one is in progress; other panics are unchanged. The real fix is in the fork and pinned: `thedracle/iroh@hop-relay-fix-0.97-closedrain` (`98b08a4`) drains the relay tasks with `join_next` and logs cancelled/panicked ones. The guard stays as a backstop for other shutdown panics |
| `HOP_PRIVSEP=0` turned privsep **on** | The gate tested presence, not value | `0`/`false`/`off`/`no`/empty mean off |
| The VPN probe trusted `vpn_last_rx`, which an inbound accept seeds | A peer redialing a node whose data plane is dead kept it looking "fresh", so the probe never dialed and the ladder never escalated | `vpn::LAST_DATAGRAM`: written only when a datagram is delivered (≤ 1 write/s/peer); the probe's freshness uses it |
| A dial started during an outage ran to its 10 s timeout after the path returned | Its QUIC handshake retransmits were asleep in exponential backoff; recovery took two dial timeouts (`zombie_path` after `net_flap`: 21–23 s, 3 of 6) | `agent.rs::hedged_dial`: a fresh dial alongside at 3 s and 6 s, first to complete wins, inside the same 10 s budget; 6 of 6 ≤ 0.8 s |
| `privsep-e2e.sh` failed on every build up to 0.9.40 (found by running the harnesses nobody ran) | `hop connect <invite> --warren` judged the redemption by the `true` exec that carries it; a host that won't run commands as the invite's bound user (a uid < 1000 service account) refused the exec after granting membership, so the join failed and the node founded a warren of its own | Join on the grant, not the exec outcome (WARN when the exec was refused); `privsep-e2e.sh` passes. `first_regular_user` (no production caller) now shares the monitor's threshold, `unix_user::MIN_REGULAR_UID` |
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
| Health registry (**shipped**, `hop_core::health`) | One in-process registry (`hop-core::health`): per component (host endpoint, netdoc endpoint, each VPN peer, each agent connection, relay) the last real success, RTT/loss where known, and a recovery-action log. The existing `net::health` counters move into it. |
| `hop status` (**shipped**) | `status.rs`: host health over the daemon socket + the agent's `agent-health.json`, a problem list (`assess`, unit-tested), exit 1 on any problem. `hop doctor [--fix]` (**shipped**): each problem with its remedy (`status::remedy_for`, unit-tested); `--fix` stops a degraded client agent and/or asks the daemon to restart over its socket. |
| VPN dial failures (shipped) | `crate::health` records every VPN dial outcome per peer. First failure of a streak and then every 5 min: WARN with the error; recovery: INFO. `hop debug net-stats` shows a `VPN DIALS` section (`health` in `--json`), read over a new `DsRequest::Health` whose payload is JSON so the registry can grow across versions. The drop stays counted under `no route/endpoint` so existing dashboards keep their totals. |
| Agent connection status (**shipped**) | `hop agent status` (`agent-health.json`) shows, per host connection: direct/relay, last RTT and its baseline, bad probes in a row, the last verdict (including `Lossy`), the last probe time and the last replacement. |
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
| Roster coverage | founder and members | Folded into the VPN peer probe: "reachable over the host endpoint but not over the VPN, for every witness" is the "this node is the broken one" signal | — | As above; the `hop fleet list` hint is shipped. The endpoint rebuild was superseded (Phase 3) |
| Agent connection quality (**shipped**) | client agent (and the host daemon's mux pool), every pooled hop/4 connection, including idle ones, every ~15 s jittered | `Ping`/`Pong` RTT through the host's stream path, and the selected path (direct/relay) | `conn_quality::QualityTracker`: not 3 bad probes in a row, where bad = unanswered, or ≥ 3× and ≥ +250 ms over the connection's best recent RTT, or on the relay after direct worked | `agent.rs::spawn_quality_probe`: dial + ping a replacement; swap it in (`AgentCommand::ReplaceConnection`, only if the measured connection is still pooled) when clearly better, closing the old one so its sessions resume on the new; otherwise keep the old one and rebase. ≤ 1 attempt / 2 min. Visible in `hop agent status` (`agent-health.json`) and the daemon's `Health`. **Loss:** a probe whose selected path lost ≥ 30 % of what it sent since the previous probe (judged only once ≥ 50 packets were sent) is `Lossy`, a bad probe like a slow one. |
| Path upgrade check (**shipped**, inside the agent quality probe) | client agent and daemon mux | A connection on the relay although a direct path worked on it (`Verdict::StuckOnRelay`) | Direct | A bad probe like a slow one: after 3 the probe dials a fresh connection — which hole-punches anew — and swaps it in if it is better. `relay_pinned` in `session-resilience.sh` measures the return to direct (≤ 120 s; the 2 h soaks: 16–69 s) |
| Shell stream echo (**shipped**, see Phase 2 "Interactive shell") | client, per live session | Host echoes the client heartbeat on the session's stream | Echo within 30 s | Reconnect the session (new stream, same session id) |
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
| Agent pooled connection (**shipped**) | The quality probe above: ping/pong RTT against the connection's baseline, ≥ 30 % loss over a probe interval (`Lossy`), or unanswered; 3 bad in a row = degraded | Dial a fresh connection, swap it in when clearly better; the old one is closed and its sessions resume on the new one. A client's failed attempt withdraws the pooled connection's vouching, so a dud is pinged and force-removed instead of handed out again |
| netdoc / VPN endpoint, founder **and** member | **Shipped:** the VPN peer probe above (witness = peer whose host endpoint answers) | **Shipped:** re-discovery → worker restart. (The in-process endpoint rebuild planned before the restart was superseded; Phase 3.) Proven by `vpn-e2e.sh`'s SELF-REPAIR stage: a member whose VPN data plane is wedged (test-only `HOP_FAULT_VPN_WEDGE_FILE`; outbound dials fail, VPN datagrams dropped both ways, host endpoint fine — the 2026-10-12 laptop) detects it, restarts itself and routes again in ~73 s at a 10 s probe interval, with no manual step |
| Interactive shell | Host echoes Input heartbeats so the client sees a one-way stall in ~30 s | **Shipped:** cancel-safe setup read — one `FramedReader` per attachment, used by `read_setup_messages` (one 4 s budget for the batch) and then handed to `run_attached_loop`, the view loop and the legacy V0 loop, so a frame the setup read left half-done is finished, not misparsed (`shell::setup_read_tests`). **Shipped:** heartbeat echo (`Ping`/`Pong` mid-session, armed by the first `Pong`, 30 s one-way stall → reconnect). **Shipped (unbounded awaits):** a sweep of the client connect/reconnect/IPC paths found every await bounded except two, now fixed: the input replayed on resume was written inline before the session loop (no deadline, nobody reading — able to deadlock client, agent and host against each other); it now goes through the loop's writer task. The agent's `open_bi` held the per-host semaphore with no deadline; it is now bounded (10 s) and raced against the client leaving. The deadlock was found by reading the code and matches the frozen client's sample (every thread parked, no timer); `session-resilience.sh`'s `paste_restart` (a 64 KB paste replayed across a host restart) passes before and after, so it is not a reproduction. **Shipped:** a proxy whose client process is gone (its socket fully closed) now ends even if the host never sends again — it used to park forever on the QUIC read, and the leaked proxy kept the host's session count up, turning every reconnect's evict-and-dial-fresh into a no-op. A client that only finished its input (`hop exec cmd < /dev/null`) keeps its output (`agent.rs::client_gone`, two tests over real QUIC). |
| Agent dial | — | **Shipped:** `do_connect` steps down from hop/4 only on an ALPN refusal (TLS alert 120). It used to step down on any non-timeout error, so one handshake aborted on a flaky path pinned the pooled connection to an older protocol for its life and switched off the hop/4 `Ping` check. |
| Worker (**shipped**) | Monitor liveness | Restart with backoff; a requested restart (exit 0) or a duplicate start (exit 75) is not a crash; 3 fast failures → non-privsep fallback, logged at ERROR and failing the long soak |

## Phase 3: Cheap restarts

| Item | Detail |
|---|---|
| Monitor keeps PTY masters (**shipped**) | The privsep monitor keeps a dup of each session master (dropped when its reaper sees the shell exit, or on `ReleaseSession` when the worker removes the session). A new worker sends `AdoptSessions` (only when the monitor advertised `HOP_PRIVSEP_CAPS=adopt-sessions` — an older monitor treats an undecodable request as the worker exiting), matches each master to its checkpoint entry by PTY slave name (`CheckpointFile::ttys`, JSON-only), and registers it detached under its original id. With the capability, every persistent session is spawned through the monitor, including a root worker's (containers without a `hop` user). A clean worker exit no longer counts as a crash-loop fast failure. Proven by `session-resilience.sh`'s `worker_restart`: `hop recover` on the founder, and the client resumes the same shell. Limits: screen history is lost (the screen restarts empty); a session younger than the last checkpoint at an unclean exit is left running in the monitor, unreachable, until it exits. |
| Non-privsep hosts (**shipped**) | A requested restart re-executes in place, and the sessions' PTY masters go through the exec: dups are left open (every other fd is close-on-exec) and named in `HOP_INHERITED_PTYS`; the new image adopts them with the same tty-matching as the privsep path, keeps each shell's pid (it is still our child) and reaps it. `embedded-profile.sh` resumes the same shell (same pid) after `hop recover` on an unsupervised PID 1 |
| In-process endpoint rebuild (**superseded**, not built) | Its two purposes are met by what shipped: recoveries no longer touch sessions (the monitor keeps PTYs across a worker restart; an unsupervised daemon carries them through its re-exec), and no supervisor is needed (re-exec in place, proven as PID 1 by `embedded-profile.sh`). A worker restart now costs ~2 s with shells kept (`worker_restart`, 2 h soak max 11 s). Rebuilding iroh's endpoint inside a live process would mean tearing down and re-attaching the docs engine, gossip, blobs and the protocol router while they are in use: a large, risky change for that ~2 s. Revisit only if a measured recovery needs it |

## Phase 4: Proof

| Harness addition | Covers |
|---|---|
| Degraded path (**shipped**, `degraded_path` in `session-resilience.sh`: 600 ms, 10 % loss) | The agent-connection case |
| Endpoint wedge (**shipped**, `HOP_FAULT_VPN_WEDGE_FILE`; `vpn-e2e.sh` SELF-REPAIR, `embedded-profile.sh`) | The netdoc case |
| Member-side failure, not only founder (**shipped**: the wedged node in SELF-REPAIR is a member) | Who has to restart |
| Client across a host restart, asserting no stuck client (**shipped** as `paste_restart`) | The unbounded-await case |
| Worker crash shortly after start (**shipped**, `privsep-e2e.sh`) | A test-only `HOP_FAULT_WORKER_CRASH_FILE` makes the worker die at startup; the monitor counts the crashes (not the requested restart before them), falls back to a non-privsep daemon after 3, and the node routes again |
| `vpn-e2e.sh` in the standard gate (**shipped**, `tests/e2e/gate.sh` with `run.sh`, the session suite, `privsep-e2e.sh`, `embedded-profile.sh`) | VPN regressions |
| Duplicate daemon on one config (**shipped**) | Found by the first long soak: the harness's restart left the old monitor alive (its pattern matched only the worker's command line), so every restart added a second daemon, whose monitor counted lock refusals as a crash loop and dropped privsep. A held lock now ends the duplicate with `EXIT_ALREADY_RUNNING` (75), which its monitor treats as final, not a crash; the harness kills the whole daemon. See host-resilience.md |
| Slow restart behind a dead path (**shipped**) | Second long soak: 7 of ~15 worker restarts took ~60 s, each with a client on a black-holed path. `endpoint.close()` waits for every connection to acknowledge the close and that one never does, so the old worker sat until the 60 s QUIC idle timeout before exiting; its adopted shells were unreachable meanwhile. Shutdown now bounds the close at 3 s (`ENDPOINT_CLOSE_BUDGET`). |
| Dud connection after a blackout (**shipped**) | ~1 in 5 `zombie_path` cycles took ~23 s. A dial completed its handshake as the blackout lifted, but its stream data never reached the host (no auth arrived; the host closed it on its 20 s auth deadline). Each client retry asked the mux to evict it, and each eviction was skipped because the previous retry's session — stuck on the same dud — counted as active. A skipped eviction now withdraws the connection's vouching, so the next hand-out pings it and a dud is force-removed with its dead sessions; a healthy shared connection costs one ping. The ping's budget is 8 s while other sessions use the connection (a false eviction would drop them) and 3 s when none do (it costs only a fresh dial) — the third soak's one remaining over-budget cycle was a dud caught at 8 s, 14.9 s in all. A second cause in the same perturbation: after the blackout the relay connection reconnects with backoff, and dials carried only the relay URL — with the endpoint having forgotten the host's paths, dials timed out for ~20 s while the LAN path was open. `hop_core::net` now remembers each host's last direct path (on every dial and each quality-probe round) and adds it to the next dial's address. Measured: 30/30 `zombie_path` cycles within budget (max 4.6 s), from ~1 in 5 at ~23 s |
| Dead first stream after a host restart (**shipped**) | 3–5 of 15 `paste_restart` cycles took ~28 s (budget 20 s) under both iroh pins; earlier gates passed by luck. After a full host restart the client resumes on a freshly dialed connection; when that stream's first packets go out while the connection moves from the relay to the direct path, the client's input (a 64 KB replayed paste, and every heartbeat `Ping` queued behind it) never reaches the host, while the connection itself stays healthy — a transport-level stream stall (multipath handling), not fixed here. Only the 12 s one-way rule ended it. Now, once a host has proven it echoes, a fresh attachment sends a `Ping` **before** any replayed input and reconnects if no `Pong` arrives within 4 s (`FIRST_ECHO`); the host answers a `Ping` even when it is the message the setup read stopped at. Measured: 15/15 cycles within budget (max 13.6 s, mean ~11 s). Debugging aids: `SESS_LOG_FOUNDER` / `SESS_LOG_DAEMON` raise daemon logging without changing the interactive client's timing (client-side debug logging hid the race) |
| Replacement rejected by the host (**shipped**) | 2026-10-27, RexMundi: a hop session crawled and kept reconnecting while ssh over the VPN was smooth; `hop agent stop` cured it at once. The quality probe saw the degradation, but it pings a replacement before any session has used it, so the `Ping` is the connection's first message — and the host's auth accepted only session requests there (`Unexpected first message: Ping`) and closed the connection. Every replacement "did not answer", so the agent kept the bad path, retrying every 2 min. The agent tests missed it because their stand-in host answers `Ping` on any stream. The host now authorizes a known peer whose first message is `Ping`, answers `Pong` and keeps the connection (`auth::tests::an_authorized_peer_may_open_with_a_ping`). Only the host needs the fix; existing clients' probes start working against it |
| Soak health in CI | `hop status` exits 1 when it reports any problem; under `set -e` and pipefail the soak-health block ended the run (the first CI soak: every perturbation passed, the job failed). It now reads the status once, tolerates the exit code, and prints any non-memory problems as information |
| Soak measurement: back-to-direct after a pin (**shipped**) | In randomized order the next perturbation (a blackout, a restart, another pin) started while the 120 s back-to-direct watcher still ran, so its TIMEOUTs measured the follow-up fault (3 of 15 pins in the third soak). A randomized soak now lets that measurement finish before the next cycle; the gate's fixed order is unchanged |
| Long soak (**shipped**, `long-soak.sh`; nightly in `.github/workflows/soak.yml`) | One long-lived founder/member pair under randomized perturbations for `SOAK_HOURS` (all of `session-resilience.sh`'s, in random order), no manual step; fails on any recovery over budget or timed out, a stray user agent, the founder's crash-loop fallback, or a steady memory climb on either node (`hop status`, ≥ 20 MB/h over ≥ 3 h). Results in `long-soak-results.md`. Nightly: `soak.yml` builds natively on a free `ubuntu-24.04-arm` runner (public repo; no secret), hands the binary over with `HOP_BIN` (no cross-build), soaks 4 h (`workflow_dispatch` takes `hours`, ≤ 6 h job cap), and keeps the results and logs as an artifact for 14 days |
| Embedded/container profile (**shipped**, `embedded-profile.sh`) | `hop host` as a container's PID 1 with no privsep and no init, read-only root, 128 MB cap, pid limit: joins and routes, ~18 MiB resident, `hop status` healthy, `hop recover` re-executes in place, a wedged VPN self-repairs by re-exec (~45 s at a 10 s probe), and 5 members that join and vanish within a minute do not make the founder escalate. |
| Clock steps and skew (**shipped**) | A device that boots at 1970 and syncs later, an NTP step, a peer with a fast clock. Found: the vendored iroh-docs tolerated only 0.6 s of skew (a ms constant against µs timestamps) and dropped faster peers' gossip silently — fixed to the documented 10 min (iroh-fork.md). Refusals beyond that are counted and `hop status` flags them as `clock`, as it does a local clock before 2026. The RSS leak trend uses a monotonic clock; a fleet `last_seen` more than 10 min in the future is treated as unknown instead of "seen just now" until real time catches up (`fleet::parse_last_seen`). Self-repair timers were already monotonic (tokio sleeps, `Instant`) |

Results are committed as `*-results.md` like the other gate harnesses.

---

## Order

| Step | Content |
|---|---|
| 1 (done) | Phase 1 visibility (dial-failure WARN + counter first); pre-emptive agent-connection quality probe with background replacement |
| 2 (done) | Pre-emptive VPN peer probe + roster coverage driving the netdoc/VPN ladder on founder and members; shell setup + deadlines + stream echo |
| 3 (done) | Phase 4 degraded-path and endpoint-wedge harnesses (before Phase 3, so Phase 3 is measured) |
| 4 (done; endpoint rebuild superseded) | Phase 3 PTY-surviving restarts and in-process endpoint rebuild |
| 5 (done) | Phase 4 long soak (nightly, `soak.yml`) and embedded profile (in `gate.sh`) as standing gates |

Every step ends with `REBUILD=1 ./tests/e2e/run.sh` plus the relevant harness.
