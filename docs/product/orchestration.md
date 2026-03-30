# Orchestration and Automation

hop's cron system, JS runtime, fleet management, and MCP integration make it a personal cloud orchestration platform. Install hop on a cloud instance, and it becomes an always-on automation backend: periodic tasks, external API integrations, AI workflows, and fleet-wide operations.

## Architecture

```
+-------------------------------------------------------------------+
|  YOUR LAPTOP (client)                                             |
|                                                                   |
|  hop secrets set ANTHROPIC_API_KEY sk-ant-...                     |
|  hop cron create --name "Morning Briefing" --file briefing.js     |
|  hop mcp   (AI agent creates/manages cron jobs)                   |
+-------------------------------------------------------------------+
          | QUIC (P2P, encrypted)
          v
+-------------------------------------------------------------------+
|  CLOUD DAEMON (EC2, Hetzner, etc.)                                |
|                                                                   |
|  hop host (systemd/launchd daemon)                                |
|  +-- Secrets Store (encrypted KV, per-service credentials)        |
|  +-- Cron Scheduler (JS jobs with hop.* + hop.http() + secrets)   |
|  +-- MCP Server (AI agents create/manage jobs remotely)           |
|  +-- Fleet (optional: fan out to other machines)                  |
+-------------------------------------------------------------------+
```

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

## Planned Features

### 3. OAuth Proxy Flow (`hop auth`) (Planned)

Initiates OAuth on the client machine (where there is a browser) and stores resulting tokens on the remote daemon.

```bash
hop auth gmail --host MyCloud
# -> Opens browser locally for OAuth consent
# -> Tokens sent to cloud daemon via QUIC
# -> Stored encrypted in daemon's secrets store

hop auth github --host MyCloud
hop auth slack --host MyCloud --scopes channels:read,chat:write
hop auth custom --auth-url ... --token-url ... --client-id ...
hop auth revoke gmail --host MyCloud
```

**Planned service registry:** Gmail/Google, GitHub, Slack, custom OAuth providers.

**Token lifecycle:** Automatic refresh, expiry alerts, revocation.

### 4. `hop.ai()` Convenience Binding (Planned)

Syntactic sugar over `hop.http()` + `hop.secrets.get()` for LLM calls.

```javascript
var result = hop.ai({
    provider: "anthropic",
    model: "claude-sonnet-4-20250514",
    prompt: "Summarize these emails: " + JSON.stringify(emails),
    max_tokens: 1024,
});
```

### 5. Token Auto-Refresh Daemon (Planned)

Background refresh of OAuth tokens. Today, token refresh is handled inline by cron jobs (see email monitoring example below).

## Email Monitoring Example

This is a complete, working example using shipped features (secrets + hop.http). No planned features required.

### Setup

```bash
# 1. Connect to your cloud daemon
hop connect <creator-invite>

# 2. Store Google OAuth credentials (from Google Cloud Console)
hop secrets set google_client_id YOUR_CLIENT_ID
hop secrets set google_client_secret YOUR_CLIENT_SECRET

# 3. Perform OAuth manually, then store tokens
#    (Phase 3 will automate this with: hop auth gmail --host cloud)
hop secrets set gmail_refresh_token REFRESH_TOKEN
hop secrets set gmail_access_token ACCESS_TOKEN
hop secrets set gmail_token_expiry 0

# 4. Store Anthropic API key
hop secrets set ANTHROPIC_API_KEY sk-ant-your-key-here

# 5. Install the cron job
hop cron create \
  --name "Gmail Morning Briefing" \
  --schedule "0 0 7 * * *" \
  --file gmail-briefing.js
```

### Cron Job Script (gmail-briefing.js)

The script performs these steps every morning:

1. **Token refresh** -- checks expiry, refreshes via Google OAuth if needed, stores new token back in secrets
2. **Fetch unread emails** -- Gmail API list + metadata fetch (up to 30 messages)
3. **Summarize with Claude** -- sends email summaries to Anthropic API
4. **Send briefing email** -- composes and sends via Gmail API
5. **Mark as read** -- batch-modifies all fetched messages
6. **Store briefing** -- saves to KV datastore for later retrieval

Key patterns used:

```javascript
// Token refresh (inline, no separate daemon needed)
var resp = hop.http.post("https://oauth2.googleapis.com/token", {
    json: {
        client_id: hop.secrets.get("google_client_id"),
        client_secret: hop.secrets.get("google_client_secret"),
        refresh_token: hop.secrets.get("gmail_refresh_token"),
        grant_type: "refresh_token"
    }
});
hop.secrets.set("gmail_access_token", resp.json().access_token);

// Bearer auth for API calls
var messages = hop.http.get(
    "https://gmail.googleapis.com/gmail/v1/users/me/messages?q=is:unread",
    { bearer: token }
);

// LLM call via hop.http
var summary = hop.http.post("https://api.anthropic.com/v1/messages", {
    headers: {
        "x-api-key": hop.secrets.get("ANTHROPIC_API_KEY"),
        "anthropic-version": "2023-06-01"
    },
    json: { model: "claude-sonnet-4-20250514", max_tokens: 2048, messages: [...] }
});

// Persist results
hop.kv.set("briefings", today, { date: today, summary: summary });
```

## Implementation Status

| Phase | Feature | Status | Notes |
|---|---|---|---|
| 1 | Encrypted secrets store | **Shipped** (v0.4.3) | ChaCha20-Poly1305, CLI + JS + MCP |
| 2 | Native `hop.http()` in JS | **Shipped** (v0.4.3) | reqwest::blocking, sandbox-aware |
| 3 | OAuth proxy flow (`hop auth`) | Planned | Browser-based OAuth from client to remote daemon |
| 4 | `hop.ai()` convenience binding | Planned | Sugar over hop.http + hop.secrets for LLM calls |
| 5 | Token auto-refresh daemon | Planned | Background refresh; today handled inline by cron jobs |

*Last updated: v0.4.3*
