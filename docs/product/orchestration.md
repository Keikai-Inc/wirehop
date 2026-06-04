# Orchestration and Automation

hop's cron system, JS runtime, fleet management, and MCP integration make it a personal cloud orchestration platform. Install hop on a cloud instance, and it becomes an always-on automation backend: periodic tasks, external API integrations, AI workflows, and fleet-wide operations.

## Architecture

```
+-------------------------------------------------------------------+
|  YOUR LAPTOP (client)                                             |
|                                                                   |
|  hop myserver secrets set ANTHROPIC_API_KEY sk-ant-...            |
|  hop myserver cap enable email-monitor                            |
|  hop myserver cap status                                          |
|  hop mcp   (AI agent creates/manages jobs remotely)               |
+-------------------------------------------------------------------+
          | QUIC (P2P, encrypted)
          v
+-------------------------------------------------------------------+
|  CLOUD DAEMON (EC2, Hetzner, etc.)                                |
|                                                                   |
|  hop host (systemd/launchd daemon)                                |
|  +-- Secrets Store (encrypted KV, per-service credentials)        |
|  +-- Cron Scheduler (JS jobs with hop.* + hop.http() + secrets)   |
|  +-- Capabilities (health, security-baseline, email-monitor)      |
|  +-- MCP Server (AI agents create/manage jobs remotely)           |
|  +-- Fleet (optional: fan out to other machines)                  |
+-------------------------------------------------------------------+
```

## Remote Management

Any authenticated peer can manage secrets, capabilities, KV, and cron on remote hosts. The host name always comes first:

```bash
hop myserver secrets set API_KEY value       # store secret on myserver
hop myserver secrets list                    # list secret names on myserver
hop myserver cap enable email-monitor        # enable capability on myserver
hop myserver cap status                      # check enabled capabilities
hop myserver kv get briefings 2026-03-30     # read KV data
hop myserver cron list                       # list cron jobs
```

No Creator role required — any peer with `hop connect` access can use these. Secrets travel over the encrypted QUIC connection and never appear in shell history or process listings.

## Shipped Features

### 1. Encrypted Secrets Store (v0.4.3)

Credentials are encrypted at rest using ChaCha20-Poly1305 with a key derived from the host's Ed25519 identity. Secrets never leave the host unencrypted.

#### CLI

```bash
hop secrets set ANTHROPIC_API_KEY sk-ant-xxx123
hop secrets set GITHUB_TOKEN ghp_xxx
hop secrets set DB_PASSWORD            # reads from stdin
hop secrets get ANTHROPIC_API_KEY
hop secrets list
hop secrets delete ANTHROPIC_API_KEY

# Remote (from laptop to cloud server)
hop myserver secrets set API_KEY value
hop myserver secrets get API_KEY
```

#### JS Runtime

```javascript
var key = hop.secrets.get("ANTHROPIC_API_KEY");   // returns string or null
hop.secrets.set("token", "new-value");
hop.secrets.delete("old_token");
var names = hop.secrets.list();                    // returns string[]
```

#### MCP

Exposed via the `hop_data` tool with `secrets_set`, `secrets_get`, `secrets_delete`, and `secrets_list` actions. AI agents can store credentials on behalf of the user.

#### Design Notes

- Encryption key derived from the host's Ed25519 secret key (already in `identity.json`)
- Only decrypted in-memory during job execution
- Not included in backup/export unless explicitly requested
- Per-secret ACL possible in the future

### 2. Native HTTP (v0.4.3)

The JS runtime includes a built-in HTTP client powered by `reqwest::blocking`. No need to shell out to curl.

#### API

```javascript
// Basic request
var resp = hop.http("https://api.example.com/data", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: "test" })
});
var data = resp.json();
// resp.status  → number
// resp.headers → object
// resp.body    → string
// resp.json()  → parsed object

// Bearer auth shorthand
var resp = hop.http.get("https://api.example.com", {
    bearer: hop.secrets.get("API_KEY")
});

// Convenience methods
hop.http.get(url, opts)
hop.http.post(url, opts)
hop.http.put(url, opts)
hop.http.delete(url, opts)

// JSON body shorthand (auto-sets Content-Type)
hop.http.post("https://api.example.com", {
    json: { key: "value" }
});
```

#### Options Object

| Field | Type | Description |
|---|---|---|
| `method` | string | HTTP method (default: `GET`) |
| `headers` | object | Request headers |
| `bearer` | string | Sets `Authorization: Bearer <value>` header |
| `body` | string | Raw request body |
| `json` | any | JSON body (auto-serialized, sets Content-Type) |

#### Security

- Respects sandbox policy: if `no_network` is set, `hop.http()` throws an error
- 30-second timeout per request
- Supported methods: GET, POST, PUT, DELETE, PATCH, HEAD
- DNS resolution happens on the daemon (daemon's network is the egress point)

### 3. Email Monitor Capability (v0.4.4)

A built-in capability that performs daily AI-powered email triage. See [capabilities.md](capabilities.md) for the full setup guide.

#### What It Does

Every morning at 7 AM (configurable):

1. **Refreshes Gmail token** — inline OAuth refresh using stored refresh_token
2. **Fetches unread emails** — up to 50 messages via Gmail API
3. **Claude triage** — classifies each email as:
   - **URGENT** — time-sensitive, needs immediate response (stays unread)
   - **ACTION** — needs a response but not urgent (stays unread)
   - **FYI** — informational, newsletters, notifications (marked as read)
4. **Sends briefing email** — structured summary grouped by priority, delivered to your inbox
5. **Marks FYI as read** — only routine messages. Urgent and action-required stay unread in your inbox
6. **Archives briefing** — stored in KV datastore for later retrieval

#### Enable It

```bash
# From your laptop
hop myserver secrets set google_client_id YOUR_CLIENT_ID
hop myserver secrets set google_client_secret YOUR_CLIENT_SECRET
hop myserver secrets set gmail_refresh_token YOUR_REFRESH_TOKEN
hop myserver secrets set ANTHROPIC_API_KEY sk-ant-...
hop myserver cap enable email-monitor

# Test immediately
hop myserver cap run email-monitor

# Check status
hop myserver cap status

# Retrieve past briefings
hop myserver kv get briefings 2026-03-30
```

#### Token Lifecycle

The script handles token refresh automatically:
- Checks access token expiry before each run (5-minute buffer)
- Refreshes via Google's token endpoint using the stored refresh token
- Stores new access token and expiry back in secrets
- Retries on 401 (force refresh if token expired mid-run)
- Refresh tokens don't expire — runs indefinitely without re-authentication

### 4. Remote Peer Operations (v0.4.4)

Any authenticated peer can manage secrets, KV, cron, and capabilities on remote hosts over the encrypted QUIC connection. Uses the `PeerRequest`/`PeerResponse` protocol — no Creator role required.

```bash
hop myserver secrets set/get/list/delete    # manage secrets
hop myserver cap list/enable/disable/status  # manage capabilities
hop myserver kv get/set/list                 # read/write KV
hop myserver cron list/get                   # inspect cron jobs
```

## OAuth Proxy Flow (`hop auth`) — Shipped

Initiates OAuth on the client machine (where there is a browser) and stores resulting tokens on the remote daemon.

```bash
hop myserver auth gmail
# → Opens browser locally for OAuth consent
# → Tokens sent to myserver via QUIC
# → Stored encrypted in daemon's secrets store
# → "Authenticated with Gmail on myserver."
```

## Planned Features

### 6. `hop.ai()` Convenience Binding (Planned)

Syntactic sugar over `hop.http()` + `hop.secrets.get()` for LLM calls.

```javascript
var result = hop.ai({
    provider: "anthropic",
    model: "claude-sonnet-4-20250514",
    prompt: "Summarize these emails: " + JSON.stringify(emails),
    max_tokens: 1024,
});
```

### 7. Interactive Setup Wizard (Planned)

```bash
hop myserver cap setup email-monitor
# → Opens browser for Gmail auth (via hop auth)
# → Prompts for Anthropic API key
# → Enables the capability
# → "Email monitor active on myserver. Next briefing: 7:00 AM UTC"
```

## Implementation Status

| Phase | Feature | Status | Notes |
|---|---|---|---|
| 1 | Encrypted secrets store | **Shipped** (v0.4.3) | ChaCha20-Poly1305, CLI + JS + MCP |
| 2 | Native `hop.http()` in JS | **Shipped** (v0.4.3) | reqwest::blocking, sandbox-aware |
| 3 | Email monitor capability | **Shipped** (v0.4.4) | AI triage, briefing, selective mark-as-read |
| 4 | Remote peer operations | **Shipped** (v0.4.4) | `hop myhost secrets/cap/kv/cron` over QUIC |
| 5 | OAuth proxy (`hop auth`) | **Shipped** | Browser flow on the client, tokens stored on the daemon |
| 6 | `hop.ai()` convenience | Planned | Sugar over hop.http + hop.secrets |
| 7 | Interactive setup wizard | Planned | `hop myhost cap setup email-monitor` |

*Last updated: v0.6.33*
