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
| The client could not see a stalled client→host direction | After a path change the session's stream carried host output but not client input; the host gave up at its 75 s read deadline while the client, still receiving, never reconnected (`relay_pinned`: 63–64 s) | Heartbeat echo: the host answers a mid-session `Ping` with `Pong`; once one `Pong` arrives, 30 s without another makes the client reconnect on a fresh stream. Old hosts never answer, so the client stops probing after 3 heartbeats |
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
| `hop status` / `hop doctor` | Read the registry over the daemon socket (host) and agent socket (client). Listed as open in host-resilience.md. |
| VPN dial failures (shipped) | `crate::health` records every VPN dial outcome per peer. First failure of a streak and then every 5 min: WARN with the error; recovery: INFO. `hop debug net-stats` shows a `VPN DIALS` section (`health` in `--json`), read over a new `DsRequest::Health` whose payload is JSON so the registry can grow across versions. The drop stays counted under `no route/endpoint` so existing dashboards keep their totals. |
| Agent connection status | `hop agent status` shows, per host connection: age, direct/relay, RTT, loss, last ping/pong. |
| `hop fleet list` hint | When every other member is offline from this node, say so and name the likely component (this node's netdoc endpoint). |
| Symbolicated samples | Release builds keep a split debug-info artifact (`split-debuginfo = "packed"`, `.dSYM` / `.debug` published next to each release) so `sample` / `gdb` output from a wedged field binary can be symbolized. |
| Memory trend | `ts` series of worker RSS (and footprint where readable) recorded by the daemon itself; `hop status` reports the slope. A leak shows as a line, a cause shows as steps. |

## Pre-emptive detection

Both 2026-10-12 failures were found by a person trying to use the path. The
VPN had been dead since at least 2026-09-25 with nothing on it to notice. The
probes below run whether or not anyone is using the path, and feed the Phase 2
ladders, so a failure is usually repaired before the next use.

| Probe | Runs on | What it measures | Healthy | Acts on failure |
|---|---|---|---|---|
| VPN peer probe | every member, for every online peer (founder included), low rate (e.g. one round trip per peer per 60 s, jittered) | A `hop/vpn/1` dial to the peer's VPN endpoint plus an **acknowledged** datagram round trip (new probe/echo datagram, appended wire variant). Keepalives alone are one-way and prove nothing about the reverse direction. | Echo within budget | Ladder: reset path → redial → rebuild this node's netdoc endpoint if **all** peers fail, a single peer's state if one fails |
| Roster coverage | founder and members | "Members whose self-doc is fresh but who are unreachable over the VPN" vs "members we can reach"; a node that can reach none of its peers is the broken one | ≥ 1 reachable peer when any is online | Rebuild this node's netdoc endpoint; WARN naming this node |
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
| netdoc / VPN endpoint, founder **and** member | Self-probe through the home relay (as `spawn_inbound_probe` does for the host endpoint), plus "members exist, dials failing, no keepalive answered for N min" | `network_change()` → per-peer `reset_node` → rebuild the netdoc endpoint in-process → restart the worker |
| Interactive shell | Host echoes Input heartbeats so the client sees a one-way stall in ~30 s | **Shipped:** cancel-safe setup read — one `FramedReader` per attachment, used by `read_setup_messages` (one 4 s budget for the batch) and then handed to `run_attached_loop`, the view loop and the legacy V0 loop, so a frame the setup read left half-done is finished, not misparsed (`shell::setup_read_tests`). **Shipped:** heartbeat echo (`Ping`/`Pong` mid-session, armed by the first `Pong`, 30 s one-way stall → reconnect). Planned: a deadline on every await in `reconnect.rs`, `agent.rs` IPC and `cmd_connect`. |
| Agent dial | — | **Shipped:** `do_connect` steps down from hop/4 only on an ALPN refusal (TLS alert 120). It used to step down on any non-timeout error, so one handshake aborted on a flaky path pinned the pooled connection to an older protocol for its life and switched off the hop/4 `Ping` check. |
| Worker | Monitor liveness (already detects fast failures) | Restart with backoff; crash-loop detection reported, not silent |

## Phase 3: Cheap restarts

| Item | Detail |
|---|---|
| Monitor keeps PTY masters | The privsep monitor retains each session's PTY master and hands the set back to a fresh worker over the existing fd channel, with the session registry rebuilt from the checkpoint. Shells survive `hop recover`, self-restart and upgrade. |
| Non-privsep hosts | A small fd-holder helper process, or re-exec with inherited fds, gives containers and simple root installs the same property. |
| In-process endpoint rebuild | Rebuilding the host or netdoc endpoint without a process restart, so most recoveries never touch sessions. Required where no supervisor exists. |

## Phase 4: Proof

| Harness addition | Covers |
|---|---|
| Degraded path (tc netem 5–30 % loss, 300 ms+ delay) in `session-resilience.sh` and `soak-resilience.sh` | The agent-connection case |
| Endpoint wedge (test-only fault hook that freezes one endpoint's dials/accepts) | The netdoc case |
| Member-side failure, not only founder | Who has to restart |
| Client across a host restart, asserting no stuck client | The unbounded-await case |
| Worker crash shortly after start | Monitor backoff |
| `vpn-e2e.sh` in the standard gate (`run.sh` or CI): it is the only suite with a real TUN, and a failure in it went unnoticed across releases | VPN regressions |
| Long soak, 24–72 h, randomized faults, nightly | Slow rot; asserts **zero manual steps** — a run that needed `hop recover` fails |
| Embedded/container profile | Low memory cap, no supervisor, read-only root, clock jumps, sleep/wake, containers living under a minute |

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
