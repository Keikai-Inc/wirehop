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
| Stdin dead in one of two windows, moving between them; stdout fine | Likely: `read_setup_messages` runs the non-cancel-safe `proto::read_message` under a 2 s `timeout`; a timeout mid-frame desyncs the session's input stream (1,387 `Unexpected message during shell session` in the founder's log show the 2 s window is regularly too short) | Host's 75 s read deadline, then reconnect (which re-rolls which window breaks) | No echo of client heartbeats, so the client cannot see a one-way stall |
| Every shell lost on `hop recover` | The privsep monitor drops its PTY master after passing the dup to the worker (`privsep/mod.rs` `spawn_session`), so the worker's exit hangs up every shell | Not recoverable; `hop sessions restore` relaunches | — |
| Client stuck forever after the host restarted | An await with no deadline in the client/agent reconnect path (sample: all threads parked, stdin reader in `read`) | `kill` | Stripped release binary; no deadline |
| Worker exited 10 s after a restart (`endpoint driver … internal error`) | Unknown | privsep monitor respawn (fast failure 1/3) | Worked as designed; cause still open |

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
| VPN dial failures (shipped) | `crate::health` records every VPN dial outcome per peer. First failure of a streak and then every 5 min: WARN with the error; recovery: INFO. `hop debug net-stats` shows a `VPN DIALS` section (`vpn_dials` in `--json`), read over a new `DsRequest::Health` whose payload is JSON so the registry can grow across versions. The drop stays counted under `no route/endpoint` so existing dashboards keep their totals. |
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
| Agent connection quality | client agent, every pooled connection, including idle ones | Ping/pong RTT (application level, through the host's stream path) plus `conn.stats()` loss, retransmits, congestion events, and the selected path (direct/relay) | RTT and loss within N× of the connection's own best recent baseline | Dial a replacement in the background; swap new sessions to it when it answers; retire the old one once its sessions move |
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
| Interactive shell | Host echoes Input heartbeats so the client sees a one-way stall in ~30 s | Cancel-safe setup read: one `FramedReader` for `read_setup_messages` and `run_attached_loop` (and the view path). Deadline on every await in `reconnect.rs`, `agent.rs` IPC and `cmd_connect`. |
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
