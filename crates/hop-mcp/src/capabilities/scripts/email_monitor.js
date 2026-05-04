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

// ── Calendar API Helper ──────────────────────────────────────────

function calendarGet(path) {
    var token = getGmailToken(); // same OAuth token covers Gmail + Calendar
    var resp = hop.http.get(
        "https://www.googleapis.com/calendar/v3" + path,
        { bearer: token }
    );
    if (resp.status === 401) {
        hop.secrets.set("gmail_token_expiry", "0");
        token = getGmailToken();
        resp = hop.http.get(
            "https://www.googleapis.com/calendar/v3" + path,
            { bearer: token }
        );
    }
    if (resp.status !== 200) {
        hop.log("Calendar API warning (" + resp.status + "): " + resp.body);
        return { items: [] }; // graceful fallback — don't fail the whole briefing
    }
    return resp.json();
}

function makeCalendarLink(title, date, time, durationMin, location) {
    var start = date.replace(/-/g, "") + "T" + (time || "0900").replace(/:/g, "") + "00";
    var d = new Date(date + "T" + (time || "09:00") + ":00");
    d.setMinutes(d.getMinutes() + (durationMin || 60));
    var pad = function(n) { return n < 10 ? "0" + n : "" + n; };
    var end = d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate())
        + "T" + pad(d.getHours()) + pad(d.getMinutes()) + "00";

    var url = "https://calendar.google.com/calendar/render?action=TEMPLATE"
        + "&text=" + encodeURIComponent(title)
        + "&dates=" + start + "/" + end
        + "&ctz=America/Denver";
    if (location) url += "&location=" + encodeURIComponent(location);
    return url;
}

// ── Fetch Calendar Events ────────────────────────────────────────

var now = new Date();
var todayStr = now.toISOString().split("T")[0];
var weekEnd = new Date(now.getTime() + 7 * 86400000).toISOString();

var calResp = calendarGet(
    "/calendars/primary/events"
    + "?timeMin=" + encodeURIComponent(todayStr + "T00:00:00Z")
    + "&timeMax=" + encodeURIComponent(weekEnd)
    + "&singleEvents=true&orderBy=startTime&maxResults=100"
);

var calEvents = (calResp.items || []).map(function(ev) {
    var start = ev.start.dateTime || ev.start.date || "";
    var end = ev.end.dateTime || ev.end.date || "";
    var isAllDay = !ev.start.dateTime;
    return {
        title: ev.summary || "(no title)",
        start: start,
        end: end,
        allDay: isAllDay,
        location: ev.location || "",
        meetLink: (ev.conferenceData && ev.conferenceData.entryPoints
            ? ev.conferenceData.entryPoints.filter(function(e) { return e.entryPointType === "video"; })[0]
            : null),
        hangoutLink: ev.hangoutLink || "",
        htmlLink: ev.htmlLink || "",
        attendees: (ev.attendees || []).map(function(a) { return a.displayName || a.email; }).join(", ")
    };
});

hop.log("Calendar: " + calEvents.length + " events in next 7 days");

// Build calendar input for Claude
var calendarInput = "";
if (calEvents.length > 0) {
    calendarInput += "CALENDAR EVENTS (next 7 days):\n";
    for (var i = 0; i < calEvents.length; i++) {
        var ev = calEvents[i];
        calendarInput += "- " + ev.start + " | " + ev.title;
        if (ev.location) calendarInput += " | Location: " + ev.location;
        if (ev.meetLink) calendarInput += " | Meet: " + ev.meetLink.uri;
        else if (ev.hangoutLink) calendarInput += " | Meet: " + ev.hangoutLink;
        if (ev.attendees) calendarInput += " | With: " + ev.attendees;
        calendarInput += "\n";
    }
} else {
    calendarInput = "CALENDAR: No events in the next 7 days.\n";
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
    "Classify each email as URGENT, ACTION, FYI, or JUNK.\n"
    + "Also extract any calendar-worthy events (meetings, appointments, flights, deadlines).\n\n"
    + "URGENT = time-sensitive, needs immediate response (e.g., outage, deadline today, direct request from boss, 2FA codes)\n"
    + "ACTION = needs a response but not urgent (e.g., review request, question, meeting follow-up)\n"
    + "FYI = informational but worth knowing about (e.g., useful newsletters, project updates, shipping notifications)\n"
    + "JUNK = marketing, spam, promotions, cold outreach, automated notifications with no value, unsubscribe-worthy\n\n"
    + "Return ONLY a JSON array. For each email:\n"
    + "  {\"index\": 0, \"class\": \"FYI\", \"event\": null}\n"
    + "  or with an event:\n"
    + "  {\"index\": 1, \"class\": \"ACTION\", \"event\": {\"title\": \"Project Review\", \"date\": \"2026-05-07\", \"time\": \"14:00\", \"duration_min\": 60, \"location\": \"Room 5\"}}\n"
    + "Set event to null if no calendar event is mentioned. No other text.\n\n" + triageInput
);

// Extract JSON array from response (handle markdown code fences)
var jsonMatch = triageText.match(/\[[\s\S]*\]/);
var triage = jsonMatch ? JSON.parse(jsonMatch[0]) : [];

// Build classification map
var classMap = {};
var eventMap = {};
for (var i = 0; i < triage.length; i++) {
    classMap[triage[i].index] = triage[i]["class"];
    if (triage[i].event) eventMap[triage[i].index] = triage[i].event;
}

var urgent = [], action = [], fyi = [], junk = [];
for (var i = 0; i < emails.length; i++) {
    var cls = classMap[i] || "FYI";
    emails[i].classification = cls;
    // Attach calendar link if Claude extracted an event
    if (eventMap[i]) {
        var ev = eventMap[i];
        emails[i].calendarLink = makeCalendarLink(ev.title, ev.date, ev.time, ev.duration_min, ev.location);
        emails[i].eventTitle = ev.title;
    }
    if (cls === "URGENT") urgent.push(emails[i]);
    else if (cls === "ACTION") action.push(emails[i]);
    else if (cls === "JUNK") junk.push(emails[i]);
    else fyi.push(emails[i]);
}

hop.log("Triage: " + urgent.length + " urgent, " + action.length + " action, " + fyi.length + " FYI, " + junk.length + " junk");
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
        var line = "- From: " + urgent[i].from + " | Subject: " + urgent[i].subject + " | " + urgent[i].snippet + " | Link: " + GMAIL_BASE + urgent[i].id;
        if (urgent[i].calendarLink) line += " | AddToCal: " + urgent[i].calendarLink;
        summaryInput += line + "\n";
    }
    summaryInput += "\n";
}
if (action.length > 0) {
    summaryInput += "ACTION NEEDED (" + action.length + "):\n";
    for (var i = 0; i < action.length; i++) {
        var line = "- From: " + action[i].from + " | Subject: " + action[i].subject + " | " + action[i].snippet + " | Link: " + GMAIL_BASE + action[i].id;
        if (action[i].calendarLink) line += " | AddToCal: " + action[i].calendarLink;
        summaryInput += line + "\n";
    }
    summaryInput += "\n";
}
if (fyi.length > 0) {
    summaryInput += "FYI / MARKED READ (" + fyi.length + "):\n";
    for (var i = 0; i < fyi.length; i++) {
        summaryInput += "- From: " + fyi[i].from + " | Subject: " + fyi[i].subject + " | Link: " + GMAIL_BASE + fyi[i].id + "\n";
    }
    summaryInput += "\n";
}
if (junk.length > 0) {
    summaryInput += "JUNK / ARCHIVED (" + junk.length + "):\n";
    for (var i = 0; i < junk.length; i++) {
        summaryInput += "- From: " + junk[i].from + " | Subject: " + junk[i].subject + "\n";
    }
}

hop.log("Calling Claude for summary (" + summaryInput.length + " chars)...");
var summary;
try {
    summary = hop.claude(
        "Write a morning briefing as clean HTML (for Gmail rendering). Three sections:\n\n"
        + "SECTION 1 — TODAY'S SCHEDULE + WEEK AHEAD:\n"
        + "Show today's calendar events with times, locations, and meet links.\n"
        + "Add brief prep notes (what to review, what to bring, travel time).\n"
        + "Then show a day-by-day summary of the rest of the week.\n"
        + "If no events, say 'No events scheduled.'\n\n"
        + "SECTION 2 — EMAIL TRIAGE:\n"
        + "Group by priority: URGENT (red), ACTION (orange), FYI (gray), JUNK (strikethrough).\n"
        + "For URGENT/ACTION: include sender, subject as clickable link, and why it matters.\n"
        + "If an email has an AddToCal: URL, show a clickable 'Add to calendar' link.\n"
        + "For FYI: list briefly with clickable links (marked as read).\n"
        + "For JUNK: just show count (archived).\n\n"
        + "RULES:\n"
        + "Use clean minimal style with inline CSS. No markdown. No emoji.\n"
        + "Use text labels [URGENT], [ACTION], [FYI] instead of emoji.\n"
        + "Each email has a Link: URL — use as href for the subject.\n"
        + "Output ONLY the HTML. No commentary.\n\n"
        + calendarInput + "\n"
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
    + " (" + urgent.length + " urgent, " + action.length + " action, " + fyi.length + " FYI, " + junk.length + " archived)";

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

// ── Archive Junk (remove from inbox) ─────────────────────────────

if (junk.length > 0) {
    var junkIds = [];
    for (var i = 0; i < junk.length; i++) {
        junkIds.push(junk[i].id);
    }
    gmailPost("/messages/batchModify", {
        ids: junkIds,
        removeLabelIds: ["UNREAD", "INBOX"]
    });
    hop.log("Archived " + junkIds.length + " junk messages.");
}

// ── Store Briefing ───────────────────────────────────────────────

hop.kv.set("briefings", today, {
    date: today,
    email_count: emails.length,
    urgent: urgent.length,
    action: action.length,
    fyi: fyi.length,
    junk: junk.length,
    summary: summary,
    classifications: emails.map(function(e) {
        return { from: e.from, subject: e.subject, classification: e.classification };
    })
});

return "Briefing sent. " + emails.length + " emails: "
    + urgent.length + " urgent, " + action.length + " action, "
    + fyi.length + " read, " + junk.length + " archived.";
