// Email Monitor — Daily Gmail triage and morning briefing
//
// Requires secrets: google_client_id, google_client_secret,
//   gmail_refresh_token, gmail_access_token, gmail_token_expiry,
//   ANTHROPIC_API_KEY

// ── Token Management ──────────────────────────────────────────────

function getGmailToken() {
    var accessToken = hop.secrets.get("gmail_access_token");
    var expiry = parseInt(hop.secrets.get("gmail_token_expiry") || "0");

    if (!accessToken || Date.now() > expiry - 300000) {
        hop.log("Refreshing Gmail access token...");
        var refreshToken = hop.secrets.get("gmail_refresh_token");
        if (!refreshToken) {
            throw new Error("gmail_refresh_token not set. Run: hop secrets set gmail_refresh_token <token>");
        }
        var resp = hop.http.post("https://oauth2.googleapis.com/token", {
            json: {
                client_id: hop.secrets.get("google_client_id"),
                client_secret: hop.secrets.get("google_client_secret"),
                refresh_token: refreshToken,
                grant_type: "refresh_token"
            }
        });
        if (resp.status !== 200) {
            throw new Error("Token refresh failed (" + resp.status + "): " + resp.body);
        }
        var data = resp.json();
        hop.secrets.set("gmail_access_token", data.access_token);
        hop.secrets.set("gmail_token_expiry", String(Date.now() + data.expires_in * 1000));
        accessToken = data.access_token;
        hop.log("Token refreshed, expires in " + data.expires_in + "s");
    }
    return accessToken;
}

// ── Gmail API Helpers ─────────────────────────────────────────────

function gmailGet(path) {
    var token = getGmailToken();
    var resp = hop.http.get(
        "https://gmail.googleapis.com/gmail/v1/users/me" + path,
        { bearer: token }
    );
    if (resp.status === 401) {
        hop.secrets.set("gmail_token_expiry", "0");
        token = getGmailToken();
        resp = hop.http.get(
            "https://gmail.googleapis.com/gmail/v1/users/me" + path,
            { bearer: token }
        );
    }
    if (resp.status !== 200) {
        throw new Error("Gmail GET " + path + " failed (" + resp.status + "): " + resp.body);
    }
    return resp.json();
}

function gmailPost(path, body) {
    var token = getGmailToken();
    var resp = hop.http.post(
        "https://gmail.googleapis.com/gmail/v1/users/me" + path,
        { bearer: token, json: body }
    );
    if (resp.status !== 200) {
        throw new Error("Gmail POST " + path + " failed (" + resp.status + "): " + resp.body);
    }
    return resp.json();
}

// ── Base64url Encoding ────────────────────────────────────────────

function base64url(str) {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        if (c < 128) bytes.push(c);
        else if (c < 2048) { bytes.push(192 | (c >> 6)); bytes.push(128 | (c & 63)); }
        else { bytes.push(224 | (c >> 12)); bytes.push(128 | ((c >> 6) & 63)); bytes.push(128 | (c & 63)); }
    }
    var b64 = "";
    for (var i = 0; i < bytes.length; i += 3) {
        var b0 = bytes[i], b1 = bytes[i + 1] || 0, b2 = bytes[i + 2] || 0;
        var n = (b0 << 16) | (b1 << 8) | b2;
        b64 += chars[(n >> 18) & 63];
        b64 += chars[(n >> 12) & 63];
        b64 += (i + 1 < bytes.length) ? chars[(n >> 6) & 63] : "";
        b64 += (i + 2 < bytes.length) ? chars[n & 63] : "";
    }
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── Fetch Unread Emails ───────────────────────────────────────────

var listResp = gmailGet("/messages?q=is:unread&maxResults=50");
var messageIds = listResp.messages || [];

if (messageIds.length === 0) {
    hop.log("No unread emails.");
    return "No unread emails";
}

hop.log("Found " + messageIds.length + " unread messages. Fetching...");

var emails = [];
for (var i = 0; i < messageIds.length && i < 30; i++) {
    var msg = gmailGet("/messages/" + messageIds[i].id
        + "?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date");
    var headers = {};
    for (var j = 0; j < (msg.payload.headers || []).length; j++) {
        var h = msg.payload.headers[j];
        headers[h.name] = h.value;
    }
    emails.push({
        id: msg.id,
        from: headers["From"] || "(unknown)",
        subject: headers["Subject"] || "(no subject)",
        date: headers["Date"] || "",
        snippet: msg.snippet || ""
    });
}

// ── Triage with Claude ────────────────────────────────────────────

var triageInput = "";
for (var i = 0; i < emails.length; i++) {
    triageInput += "[" + i + "] From: " + emails[i].from + "\n"
        + "Subject: " + emails[i].subject + "\n"
        + "Preview: " + emails[i].snippet + "\n---\n";
}

// ── Claude Inference ──────────────────────────────────────────────
// Two methods, both with automatic token refresh:
//   api_key:      direct HTTP with x-api-key header
//   claude_oauth: OAuth token via ANTHROPIC_API_KEY env + claude CLI

var anthropicMethod = hop.secrets.get("anthropic_method") || "api_key";

function getAnthropicToken() {
    var token = hop.secrets.get("ANTHROPIC_API_KEY");
    if (!token) {
        throw new Error("ANTHROPIC_API_KEY not set. Run: hop cap setup email-monitor");
    }

    // API keys (sk-ant-api...) don't expire
    if (anthropicMethod === "api_key") {
        return token;
    }

    // OAuth tokens (sk-ant-oat...) expire — check and refresh
    var expiry = parseInt(hop.secrets.get("anthropic_token_expiry") || "0");
    if (Date.now() > expiry - 300000) {
        hop.log("Refreshing Anthropic OAuth token...");
        var refreshToken = hop.secrets.get("anthropic_refresh_token");
        if (!refreshToken) {
            throw new Error("anthropic_refresh_token not set. Run: hop cap setup email-monitor");
        }

        var resp = hop.http.post("https://console.anthropic.com/v1/oauth/token", {
            json: {
                grant_type: "refresh_token",
                refresh_token: refreshToken,
                client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
            }
        });

        if (resp.status !== 200) {
            throw new Error("Anthropic token refresh failed (" + resp.status + "): " + resp.body);
        }

        var data = resp.json();
        token = data.access_token;
        hop.secrets.set("ANTHROPIC_API_KEY", token);
        if (data.expires_in) {
            hop.secrets.set("anthropic_token_expiry", String(Date.now() + data.expires_in * 1000));
        }
        hop.log("Anthropic token refreshed.");
    }

    return token;
}

function callClaude(prompt) {
    var token = getAnthropicToken();

    if (anthropicMethod === "api_key") {
        // Direct API call with x-api-key
        var resp = hop.http.post("https://api.anthropic.com/v1/messages", {
            headers: {
                "x-api-key": token,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            },
            json: {
                model: "claude-sonnet-4-20250514",
                max_tokens: 2048,
                messages: [{ role: "user", content: prompt }]
            }
        });

        if (resp.status === 200) {
            return resp.json().content[0].text;
        }
        throw new Error("Anthropic API error (" + resp.status + "): " + resp.body);
    }

    // Claude CLI with OAuth token passed via env var.
    // Prompt must be in single quotes so sandbox validator treats < > as literal.
    var tokenEscaped = token.replace(/'/g, "'\\''");
    var promptEscaped = prompt.replace(/'/g, "'\\''");
    // Daemon runs as root, so ~/.local won't find the user's claude install.
    // Search common install locations.
    var claudeBin = hop.local("which claude").stdout.trim();
    if (!claudeBin) {
        claudeBin = hop.local("ls /Users/*/.local/bin/claude /home/*/.local/bin/claude").stdout.trim().split("\n")[0] || "claude";
    }
    var cliResult = hop.local("ANTHROPIC_API_KEY='" + tokenEscaped + "' '" + claudeBin + "' -p '" + promptEscaped + "' --bare --output-format text");
    if (cliResult.exitCode === 0 && cliResult.stdout.trim()) {
        return cliResult.stdout.trim();
    }
    throw new Error("Claude CLI failed (exit " + cliResult.exitCode + "): " + cliResult.stderr);
}

var triageText = callClaude(
    "Classify each email as URGENT, ACTION, or FYI.\n\n"
    + "URGENT = time-sensitive, needs immediate response (e.g., outage, deadline today, direct request from boss)\n"
    + "ACTION = needs a response but not urgent (e.g., review request, question, meeting follow-up)\n"
    + "FYI = informational only (e.g., newsletter, notification, automated alert, marketing)\n\n"
    + "Return ONLY a JSON array like: [{\"index\": 0, \"class\": \"FYI\"}, ...]\n"
    + "No other text. One entry per email.\n\n" + triageInput
);

// Extract JSON array from response (handle markdown code fences)
var jsonMatch = triageText.match(/\[[\s\S]*\]/);
var triage = jsonMatch ? JSON.parse(jsonMatch[0]) : [];

// Build classification map
var classMap = {};
for (var i = 0; i < triage.length; i++) {
    classMap[triage[i].index] = triage[i]["class"];
}

var urgent = [], action = [], fyi = [];
for (var i = 0; i < emails.length; i++) {
    var cls = classMap[i] || "FYI";
    emails[i].classification = cls;
    if (cls === "URGENT") urgent.push(emails[i]);
    else if (cls === "ACTION") action.push(emails[i]);
    else fyi.push(emails[i]);
}

hop.log("Triage: " + urgent.length + " urgent, " + action.length + " action, " + fyi.length + " FYI");

// ── Summarize with Claude ─────────────────────────────────────────

var summaryInput = "";
if (urgent.length > 0) {
    summaryInput += "URGENT (" + urgent.length + "):\n";
    for (var i = 0; i < urgent.length; i++) {
        summaryInput += "- From: " + urgent[i].from + " | Subject: " + urgent[i].subject + " | " + urgent[i].snippet + "\n";
    }
    summaryInput += "\n";
}
if (action.length > 0) {
    summaryInput += "ACTION NEEDED (" + action.length + "):\n";
    for (var i = 0; i < action.length; i++) {
        summaryInput += "- From: " + action[i].from + " | Subject: " + action[i].subject + " | " + action[i].snippet + "\n";
    }
    summaryInput += "\n";
}
if (fyi.length > 0) {
    summaryInput += "FYI / READ (" + fyi.length + "):\n";
    for (var i = 0; i < fyi.length; i++) {
        summaryInput += "- From: " + fyi[i].from + " | Subject: " + fyi[i].subject + "\n";
    }
}

var summary = callClaude(
    "Write a concise morning email briefing from this classified inbox.\n"
    + "Group by priority (URGENT first, then ACTION, then FYI).\n"
    + "For URGENT/ACTION: include sender, subject, and why it matters.\n"
    + "For FYI: just list briefly (these will be marked as read).\n"
    + "Keep it scannable — bullet points, no fluff.\n\n" + summaryInput
);

// ── Send Briefing Email ───────────────────────────────────────────

var today = new Date().toISOString().split("T")[0];
var subject = "Morning Briefing -- " + today
    + " (" + urgent.length + " urgent, " + action.length + " action, " + fyi.length + " FYI)";

var emailContent = "From: me\r\nTo: me\r\nSubject: " + subject
    + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + summary;

gmailPost("/messages/send", { raw: base64url(emailContent) });
hop.log("Briefing email sent: " + subject);

// ── Mark FYI as Read ──────────────────────────────────────────────

if (fyi.length > 0) {
    var fyiIds = [];
    for (var i = 0; i < fyi.length; i++) {
        fyiIds.push(fyi[i].id);
    }
    gmailPost("/messages/batchModify", {
        ids: fyiIds,
        removeLabelIds: ["UNREAD"]
    });
    hop.log("Marked " + fyiIds.length + " FYI messages as read.");
}

// ── Archive Briefing ──────────────────────────────────────────────

hop.kv.set("briefings", today, {
    date: today,
    email_count: emails.length,
    urgent: urgent.length,
    action: action.length,
    fyi: fyi.length,
    summary: summary,
    classifications: emails.map(function(e) {
        return { from: e.from, subject: e.subject, classification: e.classification };
    })
});

return "Briefing sent. " + emails.length + " emails: "
    + urgent.length + " urgent, " + action.length + " action, "
    + fyi.length + " marked as read.";
