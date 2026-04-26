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
    if (resp.status >= 300) {
        throw new Error("Gmail POST " + path + " failed (" + resp.status + "): " + resp.body);
    }
    // 204 No Content (e.g. batchModify) has no body
    return resp.status === 204 ? {} : resp.json();
}

// ── Base64url Encoding ────────────────────────────────────────────

function base64url(str) {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        // Handle surrogate pairs (emoji and other 4-byte UTF-8)
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < str.length) {
            var lo = str.charCodeAt(i + 1);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                c = ((c - 0xD800) << 10) + (lo - 0xDC00) + 0x10000;
                i++;
            }
        }
        if (c < 128) bytes.push(c);
        else if (c < 2048) { bytes.push(192 | (c >> 6)); bytes.push(128 | (c & 63)); }
        else if (c < 65536) { bytes.push(224 | (c >> 12)); bytes.push(128 | ((c >> 6) & 63)); bytes.push(128 | (c & 63)); }
        else { bytes.push(240 | (c >> 18)); bytes.push(128 | ((c >> 12) & 63)); bytes.push(128 | ((c >> 6) & 63)); bytes.push(128 | (c & 63)); }
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

var listResp = gmailGet("/messages?q=is:unread+newer_than:2d&maxResults=50");
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

// ── Claude Inference via hop.claude() ─────────────────────────────
// hop.claude() handles everything: credential management, token refresh,
// binary resolution, and direct subprocess invocation. Zero config needed.

var triageText = hop.claude(
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
hop.log("Building summary...");

// ── Summarize with Claude ─────────────────────────────────────────

// Get user email for links (fetch early so it's available for summary)
var profile = gmailGet("/profile");
var userEmail = profile.emailAddress;
var GMAIL_BASE = "https://mail.google.com/mail/u/?authuser=" + userEmail.replace("@", "%40") + "#inbox/";

var summaryInput = "";
if (urgent.length > 0) {
    summaryInput += "URGENT (" + urgent.length + "):\n";
    for (var i = 0; i < urgent.length; i++) {
        summaryInput += "- From: " + urgent[i].from + " | Subject: " + urgent[i].subject + " | " + urgent[i].snippet + " | Link: " + GMAIL_BASE + urgent[i].id + "\n";
    }
    summaryInput += "\n";
}
if (action.length > 0) {
    summaryInput += "ACTION NEEDED (" + action.length + "):\n";
    for (var i = 0; i < action.length; i++) {
        summaryInput += "- From: " + action[i].from + " | Subject: " + action[i].subject + " | " + action[i].snippet + " | Link: " + GMAIL_BASE + action[i].id + "\n";
    }
    summaryInput += "\n";
}
if (fyi.length > 0) {
    summaryInput += "FYI / READ (" + fyi.length + "):\n";
    for (var i = 0; i < fyi.length; i++) {
        summaryInput += "- From: " + fyi[i].from + " | Subject: " + fyi[i].subject + " | Link: " + GMAIL_BASE + fyi[i].id + "\n";
    }
}

hop.log("Calling Claude for summary (" + summaryInput.length + " chars)...");
var summary;
try {
    summary = hop.claude(
        "Write a concise morning email briefing as clean HTML (for Gmail rendering).\n"
        + "Group by priority: URGENT first (red), then ACTION (orange), then FYI (gray).\n"
        + "For URGENT/ACTION: include sender, subject as a clickable link to the email, and a brief note on why it matters.\n"
        + "For FYI: list briefly with clickable subject links (these will be marked as read).\n"
        + "Use a clean, minimal style with inline CSS. No markdown. No emoji. Keep it scannable.\n"
        + "Use text labels like [URGENT], [ACTION], [FYI] instead of emoji.\n"
        + "Each email has a Link: URL — use it as the href for the subject.\n"
        + "Output ONLY the HTML. No explanation, no markdown, no commentary before or after.\n\n"
        + summaryInput
    );
    hop.log("Summary received (" + summary.length + " chars)");
} catch (e) {
    hop.log("ERROR: Summary call failed: " + e.message);
    throw e;
}

// ── Send Briefing Email ───────────────────────────────────────────

var today = new Date().toISOString().split("T")[0];
var subject = "Morning Briefing -- " + today
    + " (" + urgent.length + " urgent, " + action.length + " action, " + fyi.length + " FYI)";

// userEmail already fetched earlier for links

// Strip markdown code fences and any trailing commentary
var htmlBody = summary.replace(/^```html?\n?/i, "").replace(/\n?```[\s\S]*$/i, "").trim();
// If Claude added text after the closing </html> tag, strip it
var htmlEnd = htmlBody.lastIndexOf("</html>");
if (htmlEnd === -1) htmlEnd = htmlBody.lastIndexOf("</body>");
if (htmlEnd === -1) htmlEnd = htmlBody.lastIndexOf("</div>");
if (htmlEnd !== -1) {
    // Keep the closing tag + a few chars for the tag itself
    var tagEnd = htmlBody.indexOf(">", htmlEnd);
    if (tagEnd !== -1) htmlBody = htmlBody.substring(0, tagEnd + 1);
}

var emailContent = "To: " + userEmail + "\r\nSubject: " + subject
    + "\r\nContent-Type: text/html; charset=utf-8\r\nMIME-Version: 1.0\r\n\r\n" + htmlBody;

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
