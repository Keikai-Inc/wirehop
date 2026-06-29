# Federated observability

hop gives you fleet-wide observability **without a central collector**. Logs never
leave a node unless they match your query; each machine searches its own data
locally and read-only, and the results are reduced on the spot. There's no agent to
deploy, no log pipeline to run, and nothing to store centrally — the warren *is* the
substrate.

This is the complement to the per-node pieces:

| Piece | What it gives you |
|---|---|
| [Per-node audit & flow log](data-and-automation.md#per-node-audit--flow-log) (`hop audit`) | each node's own structured logbook of who connected / what ran / what flowed |
| [`event-webhook` cap](data-and-automation.md#event_webhookjs) | each node POSTs its own events (join / posture-fail / denial-spike) to your URL |
| **`hop fleet grep`** (this doc) | search **all** nodes' logs at once, reduced into one answer |
| **`log-insights` cap** | the same search, summarized by AI |

## Search the fleet — `hop fleet grep`

```bash
# Search every node's structured audit log (identical across macOS + Linux)
hop fleet grep all rejected --source audit

# Search system logs across a tag group (each node resolves its own log source)
hop fleet grep web "failed password" --source system --since 1h

# Search a specific app log file across a role
hop fleet grep prod 500 --source /var/log/nginx/access.log

# Machine-readable, for piping to jq or a script
hop fleet grep web OOM --source system --json | jq '.total'
```

It fans the query across the warren members matching the selector (a role, tag, or
known-host group), each node searches **its own** source locally, and the matches are
reduced into one table (or `--json`).

### Three source tiers (cross-platform, resolved per-node)

The platform problem is solved at the **edge** — each node knows its own OS and
translates the one logical query into its own native command:

1. **`audit`** *(default)* — the structured hop audit log via `hop audit --json`.
   Byte-identical on every OS, already reach-respecting and queryable. **Start here:**
   for security/connection events the cross-platform problem disappears entirely.
2. **`system`** — well-known system logs, resolved at the node: `journalctl` on
   systemd Linux, `/var/log/{syslog,auth.log,messages}` on other Linux,
   `/var/log/system.log` on macOS.
3. **`<path>`** — an operator-named file (any `--source` value containing `/`).

### Read-only by guarantee

The search runs under the `audit` sandbox preset (`read_only` + `no_network`),
requested via `RequestExecV2` and merged **stricter** by each host — so a node
**cannot be mutated** by a search, regardless of what its invite allows. The pattern
is single-quoted into the command (data, never shell code), and a per-node timeout
keeps one slow node from stalling the run.

### Who can search? (access control)

Searching a host is the **exec** path, so it is gated by **capability scoping** — a
role grants `reach` / `search` / `exec` **per host tag**, and search is *not*
something every warren member can do to everyone:

- **Membership** — the host must have admitted you (an unauthorized node is reported
  as unreachable, not searched).
- **`search` is a distinct, read-only tier** between `network_only` (no sessions at
  all) and full `exec`. A host derives it from the request: a read-only operation
  (`hop fleet grep`, an exec under `--read-only`) needs the **`search`** capability;
  anything that could mutate the host needs **`exec`**.
- **Scoped by host tag.** A role's `exec_tags` / `search_tags` say *which* hosts it
  may exec / search (by tag; `*` = all). Examples:

  | Role | `exec_tags` | `search_tags` | Can do |
  |---|---|---|---|
  | `it` | `*` | — | exec + search every host |
  | `developer` | `dev` | `staging` | exec `dev`; **search** `dev`+`staging`; nothing on `prod` |
  | `marketing` | — | — (+`network_only`) | reach a shared service; **no** search/exec |

- **Open by default, lockable.** Empty `exec_tags` = open (a small team just works);
  set tags to restrict. A host can require explicit grants with
  `require_explicit_access` (see below). Admin roles are never locked out.

Manage it with [`hop role`](cli-reference.md#hop-role-action):

```bash
hop admin <host> role update developer --exec-tags dev --search-tags dev,staging
```

Every denied attempt is recorded in the audit log (category `reach`,
`session.deny`), so refusals are visible to `hop fleet grep` over the audit source.

#### Lock a host so peers can't search/exec it

Default access is open within the warren. To make a host (e.g. a personal laptop)
accessible only to roles **explicitly** granted its tags — denying unscoped roles —
set on that host:

```bash
hop config set require-explicit-access true
```

Admin roles and explicit grants still pass; everyone else is denied (and audited).

## AI-aggregated search — `log-insights`

For a one-paragraph answer instead of raw lines, the `log-insights` capability runs
the same read-only fan-out and reduces the matches with Claude:

```bash
hop auth anthropic                                              # one-time credential
hop cap run log-insights --targets web --param query="failed password"
hop cap run log-insights --targets prod --param query=OOM --param source=audit
```

It returns `{ hosts_searched, hosts_matched, summary, results }` — `summary` is the AI
reduction (what's happening, anomalies across hosts, the key finding). Without an
Anthropic credential it still returns the raw per-host aggregation.

## Why no central collector

Every other tool ships your logs somewhere — an agent on each box forwarding to a
SaaS or a self-hosted pipeline you operate. hop inverts it: the query travels to the
data, each node answers for itself over the same encrypted warren transport, and the
answer is reduced where you ran the command. Nothing is stored centrally, so there's
nothing to secure, bill, or breach. (When you *do* want logs in an external system —
Datadog, Splunk, an OTLP pipeline — that's the opt-in export layer, roadmap G22; the
audit schema is already OTel-aligned for it.)
