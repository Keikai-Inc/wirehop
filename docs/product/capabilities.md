# Capabilities

Capabilities are self-contained monitoring, operations, and security scripts that ship with hop. Each capability includes a JavaScript script, a sandbox permission tier, a trigger mode, and a data storage pattern. The framework handles enabling (as cron jobs), disabling, deploying to fleet nodes, and on-demand execution.

## CLI Commands

```bash
hop cap list                        # list all available capabilities
hop cap enable <id>                 # enable as a cron job (default schedule)
hop cap enable <id> --targets web   # enable with fleet targeting
hop cap enable <id> --schedule "0 */10 * * * *"  # custom schedule
hop cap disable <id>                # remove the cron job
hop cap status                      # show which capabilities are enabled
hop cap run <id>                    # run once (on-demand)
hop cap run <id> --targets web      # run against fleet group
hop cap run <id> --param query=OOM  # pass parameters
hop cap deploy <id> --targets prod  # deploy to remote nodes
```

## Built-in Capabilities

| ID | Name | Description | Tier | Trigger | Default Schedule | Category | Data Pattern |
|---|---|---|---|---|---|---|---|
| `health` | Health Monitor | CPU load, memory, disk usage, uptime. Dual-mode: orchestrator fans out to targets, or node monitors itself locally. | Observe | Scheduled | `0 */5 * * * *` (every 5 min) | monitor | Push |
| `log-search` | Log Search | Searches system logs across fleet nodes. Each node greps locally, returns matching lines. | Observe | OnDemand | -- | operations | FanOut |
| `security-baseline` | Security Baseline | Audits SUID binaries, open ports, failed auth, SSH keys, world-writable files. Dual-mode with push. | Audit | Both | `0 0 3 * * *` (daily 3 AM) | security | Push |
| `email-monitor` | Email Monitor | Daily Gmail triage and morning briefing. Classifies emails as URGENT/ACTION/FYI using Claude, sends briefing, marks FYI as read. | Connect | Both | `0 0 7 * * *` (daily 7 AM) | automation | Push |

### Parameters

| Capability | Parameter | Required | Default | Description |
|---|---|---|---|---|
| `log-search` | `query` | Yes | -- | Search term to grep for in system logs |

## Permission Tiers

Each capability declares a `PermissionTier` that maps to a sandbox preset. This controls what the capability's JS script can do on the host.

| Tier | Sandbox Preset | Filesystem | Network | Use Case |
|---|---|---|---|---|
| **Observe** | `monitor` | Read-only, system paths only | Blocked | Health checks, metrics collection |
| **Audit** | `audit` | Read-only, full filesystem read | Blocked | Security scanning, log analysis |
| **Connect** | `connect` | Read-only, full filesystem read | Allowed | API integrations, email monitoring |
| **Operate** | `deploy` | Write + network allowed, deny destructive | Allowed | Deployments, service management |

## Trigger Modes

| Mode | Can Schedule | Can Run On-Demand | Description |
|---|---|---|---|
| `Scheduled` | Yes | No | Runs only on a cron schedule. `hop cap enable` creates the job. |
| `OnDemand` | No | Yes | Runs only via `hop cap run`. Cannot be enabled as a cron job. |
| `Both` | Yes | Yes | Can be scheduled and also run ad-hoc. Has a default schedule. |

## Data Patterns

| Pattern | Description |
|---|---|
| **Push** | Node collects data locally, pushes summary to orchestrator's datastore (KV + time-series). |
| **FanOut** | Orchestrator dispatches query to all target nodes. Each node filters locally and returns results. |

## How Capabilities Work

### Enabling

`hop cap enable health` creates a cron job with:
- **Name:** derived from the capability name
- **Schedule:** the capability's default (overridable with `--schedule`)
- **Script:** the capability's built-in JS source
- **Catalog ID:** `cap:<id>` (e.g., `cap:health`) for tracking

### Deploying

`hop cap deploy health --targets production` pushes the capability's cron job to all fleet members matching the `production` tag. Each node then runs the capability locally on its own schedule.

### On-Demand Execution

`hop cap run log-search --targets web --param query=OOM` executes the capability's script immediately. Parameters are injected as `hop.params` in the JS runtime. Fleet targets are injected as `hop.targets`.

## Capability Scripts

### health.js

Collects hostname, OS, load average, memory (total/free), disk usage, and uptime. Works on both macOS and Linux. Stores metrics in time-series (`health.load`, `health.mem_pct`, `health.disk_pct`) and latest snapshot in KV (`cap:health:<hostname>:latest`).

**Dual-mode:** When `hop.targets` is empty, monitors the local node. When targets are provided, fans out via `hop.exec()` to each target.

### log_search.js

Searches `/var/log/syslog`, `/var/log/system.log`, `/var/log/messages`, and `/var/log/auth.log` on each target node. Requires the `query` parameter. Returns matching lines (up to 20 per log file per host).

**Fan-out only:** Requires `--targets`. Each node greps locally -- logs never leave the node unless they match.

### security_baseline.js

Audits five areas on each host:
1. SUID binaries (`find / -perm -4000`)
2. Open listening ports (`ss -tlnp` or `netstat -tlnp`)
3. Failed auth attempts (last 24h from journal or auth.log)
4. SSH authorized keys (count per user)
5. World-writable files in `/etc` and `/usr`

Stores full report in KV (`cap:security:<hostname>:latest`).

**Dual-mode:** Runs locally or fans out to targets.

### email_monitor.js

Daily Gmail monitoring with AI-powered triage:

1. Refreshes OAuth token inline (using `hop.secrets` for token storage)
2. Fetches up to 50 unread messages via Gmail API
3. Sends email list to Claude for classification (URGENT / ACTION / FYI)
4. Generates a structured morning briefing grouped by priority
5. Sends briefing email to self via Gmail API
6. Marks FYI messages as read; URGENT and ACTION stay unread
7. Archives briefing to KV (`briefings:<date>`)

**Setup required:** See [Email Monitor Setup](#email-monitor-setup) below.

## Email Monitor Setup

### Prerequisites

1. Google Cloud project with Gmail API enabled
2. OAuth 2.0 credentials (Web application type)
3. Anthropic API key

### Step-by-Step

```bash
# 1. Store Google OAuth credentials
hop secrets set google_client_id YOUR_CLIENT_ID
hop secrets set google_client_secret YOUR_CLIENT_SECRET

# 2. Get OAuth tokens (one-time browser flow)
#    Open this URL in your browser (replace YOUR_CLIENT_ID):
#    https://accounts.google.com/o/oauth2/v2/auth?client_id=YOUR_CLIENT_ID&
#      redirect_uri=http://localhost:8080/callback&response_type=code&
#      scope=https://www.googleapis.com/auth/gmail.readonly+
#      https://www.googleapis.com/auth/gmail.modify+
#      https://www.googleapis.com/auth/gmail.send&
#      access_type=offline&prompt=consent
#
#    After consent, exchange the auth code:
#    curl -s -X POST https://oauth2.googleapis.com/token \
#      -d "code=AUTH_CODE&client_id=YOUR_CLIENT_ID&\
#      client_secret=YOUR_CLIENT_SECRET&\
#      redirect_uri=http://localhost:8080/callback&\
#      grant_type=authorization_code"

# 3. Store tokens from the response
hop secrets set gmail_refresh_token REFRESH_TOKEN
hop secrets set gmail_access_token ACCESS_TOKEN
hop secrets set gmail_token_expiry 0

# 4. Store Anthropic API key
hop secrets set ANTHROPIC_API_KEY sk-ant-...

# 5. Enable the capability
hop cap enable email-monitor

# 6. Test it
hop cap run email-monitor
```

### Token Lifecycle

The script handles token refresh automatically:
- Checks access token expiry before each run (5-minute buffer)
- Refreshes via Google's token endpoint using the stored refresh token
- Stores new access token and expiry back in secrets
- Retries on 401 (force refresh if token expired mid-run)
- Refresh tokens don't expire — runs indefinitely without re-authentication

### Retrieving Briefings

```bash
hop kv get briefings 2026-03-30   # specific date
```

*Last updated: v0.4.3*
