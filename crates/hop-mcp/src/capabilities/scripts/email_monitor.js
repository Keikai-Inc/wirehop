// Email Monitor — Time-aware daily planner with SMS notifications
//
// Runs every hour. At the configured briefing hour: full email+calendar
// briefing via email + SMS summary. Other hours: checks for new URGENT
// emails and upcoming calendar events, sends SMS alerts only if needed.
//
// Requires secrets: google_client_id, google_client_secret,
//   gmail_refresh_token, gmail_access_token, gmail_token_expiry,
//   ANTHROPIC_API_KEY
// Optional secrets: sms_phone, sms_carrier, briefing_hour_utc,
//   quiet_hours_start, quiet_hours_end

// ── Configuration ────────────────────────────────────────────────

var BRIEFING_HOUR = parseInt(hop.secrets.get("briefing_hour_utc") || "14"); // 14 UTC = 7 AM MST
var QUIET_START = parseInt(hop.secrets.get("quiet_hours_start") || "4");    // 4 UTC = 10 PM MST
var QUIET_END = parseInt(hop.secrets.get("quiet_hours_end") || "12");       // 12 UTC = 6 AM MST

var GATEWAYS = {
    "tmobile": "@tmomail.net",
    "att": "@txt.att.net",
    "verizon": "@vtext.com",
    "sprint": "@messaging.sprintpcs.com",
    "googlefi": "@msg.fi.google.com",
    "mint": "@tmomail.net",
    "visible": "@vtext.com",
    "uscellular": "@email.uscc.net"
};

// ── Token Management ──────────────────────────────────────────────

function getGmailToken() {
    var accessToken = hop.secrets.get("gmail_access_token");
    var expiry = parseInt(hop.secrets.get("gmail_token_expiry") || "0");

    if (!accessToken || Date.now() > expiry - 300000) {
        hop.log("Refreshing Gmail access token...");
        var refreshToken = hop.secrets.get("gmail_refresh_token");
        if (!refreshToken) {
            throw new Error("gmail_refresh_token not set. Run: hop cap setup email-monitor");
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
    }
    return accessToken;
}

// ── API Helpers ──────────────────────────────────────────────────

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
    return resp.status === 204 ? {} : resp.json();
}

function calendarGet(path) {
    var token = getGmailToken();
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
        hop.log("Calendar API warning (" + resp.status + ")");
        return { items: [] };
    }
    return resp.json();
}

// ── Base64url Encoding ──────────────────────────────────────────

function base64url(str) {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
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

// ── SMS ─────────────────────────────────────────────────────────

function sendSMS(message) {
    var phone = hop.secrets.get("sms_phone");
    var carrier = hop.secrets.get("sms_carrier");
    if (!phone || !carrier) return false;

    var gateway = GATEWAYS[carrier.toLowerCase()];
    if (!gateway) {
        // Treat carrier as a custom gateway (e.g., "@custom.gateway.com")
        gateway = carrier.indexOf("@") === 0 ? carrier : "@" + carrier;
    }

    var smsAddr = phone + gateway;
    // Email-to-SMS gateways split long messages into multiple texts.
    // Keep under 300 chars for readability (2 texts max).
    if (message.length > 300) message = message.substring(0, 297) + "...";

    var content = "To: " + smsAddr
        + "\r\nSubject: hop\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + message;

    try {
        gmailPost("/messages/send", { raw: base64url(content) });
        hop.log("SMS sent to " + smsAddr);
        return true;
    } catch (e) {
        hop.log("SMS failed: " + e.message);
        return false;
    }
}

function isQuietHours() {
    var hour = new Date().getUTCHours();
    if (QUIET_START < QUIET_END) {
        return hour >= QUIET_START && hour < QUIET_END;
    }
    // Wraps midnight (e.g., 22-6 = 4 UTC to 12 UTC)
    return hour >= QUIET_START || hour < QUIET_END;
}

// ── Calendar Link Builder ───────────────────────────────────────

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

// ── Email Fetching + Triage ─────────────────────────────────────

function fetchAndTriageEmails(query, maxFetch) {
    var listResp = gmailGet("/messages?q=" + encodeURIComponent(query) + "&maxResults=50");
    var messageIds = listResp.messages || [];
    if (messageIds.length === 0) return { emails: [], urgent: [], action: [], fyi: [], junk: [] };

    hop.log("Found " + messageIds.length + " messages. Fetching...");
    var emails = [];
    for (var i = 0; i < messageIds.length && i < (maxFetch || 30); i++) {
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

    // Triage with Claude
    var triageInput = "";
    for (var i = 0; i < emails.length; i++) {
        triageInput += "[" + i + "] From: " + emails[i].from + "\n"
            + "Subject: " + emails[i].subject + "\n"
            + "Preview: " + emails[i].snippet + "\n---\n";
    }

    var triage = [];
    var triageFailed = false;
    try {
        var triageText = hop.claude(
            "Classify each email as URGENT, ACTION, FYI, or JUNK.\n"
            + "Also extract any calendar-worthy events.\n\n"
            + "URGENT = time-sensitive, needs immediate response\n"
            + "ACTION = needs a response but not urgent\n"
            + "FYI = informational but worth knowing about\n"
            + "JUNK = marketing, spam, promotions, no value\n\n"
            + "Return ONLY a JSON array:\n"
            + "[{\"index\": 0, \"class\": \"FYI\", \"event\": null}, ...]\n"
            + "event can be: {\"title\": \"...\", \"date\": \"YYYY-MM-DD\", \"time\": \"HH:MM\", \"duration_min\": 60, \"location\": \"...\"} or null.\n"
            + "No other text.\n\n" + triageInput
        );
        var jsonMatch = triageText.match(/\[[\s\S]*\]/);
        triage = jsonMatch ? JSON.parse(jsonMatch[0]) : [];
    } catch(e) {
        hop.log("WARNING: Claude triage failed (" + e.message + "), classifying all as FYI");
        triageFailed = true;
        triage = emails.map(function(_, i) { return { index: i, "class": "FYI", event: null }; });
    }

    var classMap = {}, eventMap = {};
    for (var i = 0; i < triage.length; i++) {
        classMap[triage[i].index] = triage[i]["class"];
        if (triage[i].event) eventMap[triage[i].index] = triage[i].event;
    }

    var urgent = [], action = [], fyi = [], junk = [];
    for (var i = 0; i < emails.length; i++) {
        var cls = classMap[i] || "FYI";
        emails[i].classification = cls;
        if (eventMap[i]) {
            var ev = eventMap[i];
            emails[i].calendarLink = makeCalendarLink(ev.title, ev.date, ev.time, ev.duration_min, ev.location);
        }
        if (cls === "URGENT") urgent.push(emails[i]);
        else if (cls === "ACTION") action.push(emails[i]);
        else if (cls === "JUNK") junk.push(emails[i]);
        else fyi.push(emails[i]);
    }

    return { emails: emails, urgent: urgent, action: action, fyi: fyi, junk: junk, triageFailed: triageFailed };
}

// ── Fetch Calendar Events ───────────────────────────────────────

function fetchCalendarEvents(hoursAhead) {
    var now = new Date();
    var end = new Date(now.getTime() + hoursAhead * 3600000);
    var calResp = calendarGet(
        "/calendars/primary/events"
        + "?timeMin=" + encodeURIComponent(now.toISOString())
        + "&timeMax=" + encodeURIComponent(end.toISOString())
        + "&singleEvents=true&orderBy=startTime&maxResults=100"
    );
    return (calResp.items || []).map(function(ev) {
        return {
            id: ev.id,
            title: ev.summary || "(no title)",
            start: ev.start.dateTime || ev.start.date || "",
            end: ev.end.dateTime || ev.end.date || "",
            allDay: !ev.start.dateTime,
            location: ev.location || "",
            meetLink: (ev.conferenceData && ev.conferenceData.entryPoints
                ? (ev.conferenceData.entryPoints.filter(function(e) { return e.entryPointType === "video"; })[0] || {}).uri
                : null) || ev.hangoutLink || "",
            htmlLink: ev.htmlLink || "",
            attendees: (ev.attendees || []).map(function(a) { return a.displayName || a.email; }).join(", ")
        };
    });
}

// ═══════════════════════════════════════════════════════════════
// MAIN: Time-aware dispatch
// ═══════════════════════════════════════════════════════════════

var currentHour = new Date().getUTCHours();
var isBriefingTime = (currentHour === BRIEFING_HOUR);

if (isBriefingTime) {
    // ── FULL MORNING BRIEFING ──────────────────────────────────

    var calEvents = fetchCalendarEvents(168); // 7 days
    hop.log("Calendar: " + calEvents.length + " events in next 7 days");

    var result = fetchAndTriageEmails("is:unread newer_than:2d", 30);
    if (result.emails.length === 0 && calEvents.length === 0) {
        hop.log("No emails or calendar events.");
        return "No emails or events";
    }

    hop.log("Triage: " + result.urgent.length + " urgent, " + result.action.length + " action, "
        + result.fyi.length + " FYI, " + result.junk.length + " junk");

    // Build calendar input for Claude
    var calendarInput = "";
    if (calEvents.length > 0) {
        calendarInput += "CALENDAR EVENTS (next 7 days):\n";
        for (var i = 0; i < calEvents.length; i++) {
            var ev = calEvents[i];
            calendarInput += "- " + ev.start + " | " + ev.title;
            if (ev.location) calendarInput += " | Location: " + ev.location;
            if (ev.meetLink) calendarInput += " | Meet: " + ev.meetLink;
            if (ev.attendees) calendarInput += " | With: " + ev.attendees;
            calendarInput += "\n";
        }
    } else {
        calendarInput = "CALENDAR: No events in the next 7 days.\n";
    }

    // Build email summary input
    var profile = gmailGet("/profile");
    var userEmail = profile.emailAddress;
    var GMAIL_BASE = "https://mail.google.com/mail/u/?authuser=" + userEmail.replace("@", "%40") + "#inbox/";

    var summaryInput = "";
    if (result.urgent.length > 0) {
        summaryInput += "URGENT (" + result.urgent.length + "):\n";
        for (var i = 0; i < result.urgent.length; i++) {
            var e = result.urgent[i];
            var line = "- From: " + e.from + " | Subject: " + e.subject + " | " + e.snippet + " | Link: " + GMAIL_BASE + e.id;
            if (e.calendarLink) line += " | AddToCal: " + e.calendarLink;
            summaryInput += line + "\n";
        }
        summaryInput += "\n";
    }
    if (result.action.length > 0) {
        summaryInput += "ACTION (" + result.action.length + "):\n";
        for (var i = 0; i < result.action.length; i++) {
            var e = result.action[i];
            var line = "- From: " + e.from + " | Subject: " + e.subject + " | " + e.snippet + " | Link: " + GMAIL_BASE + e.id;
            if (e.calendarLink) line += " | AddToCal: " + e.calendarLink;
            summaryInput += line + "\n";
        }
        summaryInput += "\n";
    }
    if (result.fyi.length > 0) {
        summaryInput += "FYI / MARKED READ (" + result.fyi.length + "):\n";
        for (var i = 0; i < result.fyi.length; i++) {
            summaryInput += "- " + result.fyi[i].from + " | " + result.fyi[i].subject + " | Link: " + GMAIL_BASE + result.fyi[i].id + "\n";
        }
        summaryInput += "\n";
    }
    if (result.junk.length > 0) {
        summaryInput += "JUNK / ARCHIVED (" + result.junk.length + "):\n";
        for (var i = 0; i < result.junk.length; i++) {
            summaryInput += "- " + result.junk[i].from + " | " + result.junk[i].subject + "\n";
        }
    }

    // Claude generates HTML briefing (with fallback if AI unavailable)
    var htmlBody;
    hop.log("Calling Claude for summary...");
    try {
        var summary = hop.claude(
            "Write a morning briefing as clean HTML (for Gmail).\n\n"
            + "SECTION 1 — TODAY'S SCHEDULE + WEEK AHEAD:\n"
            + "Show today's events with times, locations, meet links, prep notes.\n"
            + "Then day-by-day summary of rest of week.\n\n"
            + "SECTION 2 — EMAIL TRIAGE:\n"
            + "URGENT (red), ACTION (orange), FYI (gray). Clickable subject links.\n"
            + "If AddToCal URL exists, show 'Add to calendar' link.\n"
            + "JUNK: just count.\n\n"
            + "RULES: Clean inline CSS. No markdown. No emoji. Text labels only.\n"
            + "Output ONLY HTML. No commentary.\n\n"
            + calendarInput + "\n" + summaryInput
        );
        hop.log("Summary received (" + summary.length + " chars)");

        // Clean HTML
        htmlBody = summary.replace(/^```html?\n?/i, "").replace(/\n?```[\s\S]*$/i, "").trim();
        var htmlEnd = htmlBody.lastIndexOf("</html>");
        if (htmlEnd === -1) htmlEnd = htmlBody.lastIndexOf("</body>");
        if (htmlEnd === -1) htmlEnd = htmlBody.lastIndexOf("</div>");
        if (htmlEnd !== -1) {
            var tagEnd = htmlBody.indexOf(">", htmlEnd);
            if (tagEnd !== -1) htmlBody = htmlBody.substring(0, tagEnd + 1);
        }
    } catch(e) {
        hop.log("WARNING: Claude HTML generation failed (" + e.message + "), using plain fallback");
        var escHtml = function(s) { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); };
        htmlBody = "<html><body style='font-family: -apple-system, sans-serif; max-width: 600px; margin: 0 auto;'>"
            + "<h2 style='color: #333;'>Morning Briefing</h2>"
            + "<p style='color: #c00; font-size: 13px;'>AI summarization unavailable: " + escHtml(e.message) + "</p>"
            + (result.triageFailed ? "<p style='color: #c00; font-size: 13px;'>Email classification also failed -- all shown as FYI.</p>" : "")
            + "<h3>Calendar</h3><pre style='white-space: pre-wrap; font-size: 13px;'>" + escHtml(calendarInput) + "</pre>"
            + "<h3>Emails</h3><pre style='white-space: pre-wrap; font-size: 13px;'>" + escHtml(summaryInput) + "</pre>"
            + "</body></html>";
    }

    // Send email
    var today = new Date().toISOString().split("T")[0];
    var subject = "Morning Briefing -- " + today
        + " (" + result.urgent.length + " urgent, " + result.action.length + " action, "
        + result.fyi.length + " FYI, " + result.junk.length + " archived)";

    var emailContent = "To: " + userEmail + "\r\nSubject: " + subject
        + "\r\nContent-Type: text/html; charset=utf-8\r\nMIME-Version: 1.0\r\n\r\n" + htmlBody;

    gmailPost("/messages/send", { raw: base64url(emailContent) });
    hop.log("Briefing email sent: " + subject);

    // Send SMS summary
    if (!isQuietHours()) {
        var smsLines = [];
        smsLines.push("Morning Briefing: " + result.urgent.length + " urgent, " + result.action.length + " action, " + result.fyi.length + " FYI, " + result.junk.length + " archived");
        // Today's events
        var todayEvents = calEvents.filter(function(e) {
            return e.start.indexOf(today) === 0 || e.start.indexOf(today) >= 0;
        });
        for (var i = 0; i < todayEvents.length && i < 3; i++) {
            var t = todayEvents[i].start.match(/T(\d{2}):(\d{2})/);
            var timeStr = t ? (parseInt(t[1]) % 12 || 12) + (parseInt(t[1]) >= 12 ? "PM" : "AM") : "all day";
            smsLines.push(timeStr + " " + todayEvents[i].title.substring(0, 30));
        }
        // Top urgent
        for (var i = 0; i < result.urgent.length && i < 2; i++) {
            smsLines.push("[URGENT] " + result.urgent[i].subject.substring(0, 30));
        }
        sendSMS(smsLines.join("\n"));
    }

    // Mark FYI as read
    if (result.fyi.length > 0) {
        var fyiIds = result.fyi.map(function(e) { return e.id; });
        gmailPost("/messages/batchModify", { ids: fyiIds, removeLabelIds: ["UNREAD"] });
        hop.log("Marked " + fyiIds.length + " FYI as read.");
    }

    // Archive junk
    if (result.junk.length > 0) {
        var junkIds = result.junk.map(function(e) { return e.id; });
        gmailPost("/messages/batchModify", { ids: junkIds, removeLabelIds: ["UNREAD", "INBOX"] });
        hop.log("Archived " + junkIds.length + " junk.");
    }

    // Save state
    hop.kv.set("email-monitor", "last_check_time", String(Date.now()));
    hop.kv.set("email-monitor", "notified_ids", JSON.stringify(
        result.emails.map(function(e) { return e.id; })
    ));

    hop.kv.set("briefings", today, {
        date: today, email_count: result.emails.length,
        urgent: result.urgent.length, action: result.action.length,
        fyi: result.fyi.length, junk: result.junk.length
    });

    return "Briefing sent. " + result.emails.length + " emails: "
        + result.urgent.length + " urgent, " + result.action.length + " action, "
        + result.fyi.length + " read, " + result.junk.length + " archived.";

} else {
    // ── HOURLY WATCHDOG ───────────────────────────────────────────

    if (isQuietHours()) {
        return "Quiet hours — skipping";
    }

    var alerts = [];

    // Load previously notified IDs
    var prevIds = [];
    try {
        var stored = hop.kv.get("email-monitor", "notified_ids");
        if (stored) prevIds = JSON.parse(stored);
    } catch(e) {}

    // Quick check: any new unread emails at all?
    var listResp = gmailGet("/messages?q=" + encodeURIComponent("is:unread newer_than:1d") + "&maxResults=50");
    var messageIds = (listResp.messages || []).map(function(m) { return m.id; });
    var newMessageIds = messageIds.filter(function(id) { return prevIds.indexOf(id) === -1; });

    // Only run Claude triage if there are NEW emails we haven't seen
    if (newMessageIds.length > 0) {
        hop.log("Watchdog: " + newMessageIds.length + " new emails, triaging...");
        try {
            var result = fetchAndTriageEmails("is:unread newer_than:1d", 15);

            var newUrgent = result.urgent.filter(function(e) {
                return prevIds.indexOf(e.id) === -1;
            });

            // Only alert for URGENT emails
            for (var i = 0; i < newUrgent.length; i++) {
                alerts.push("[URGENT] " + newUrgent[i].from.split("<")[0].trim()
                    + ": " + newUrgent[i].subject.substring(0, 40));
            }

            // Archive junk continuously (not just at briefing time)
            if (result.junk.length > 0) {
                var junkIds = result.junk.map(function(e) { return e.id; });
                gmailPost("/messages/batchModify", { ids: junkIds, removeLabelIds: ["UNREAD", "INBOX"] });
                hop.log("Watchdog: archived " + junkIds.length + " junk");
            }

            // Mark FYI as read continuously
            if (result.fyi.length > 0) {
                var fyiIds = result.fyi.map(function(e) { return e.id; });
                gmailPost("/messages/batchModify", { ids: fyiIds, removeLabelIds: ["UNREAD"] });
                hop.log("Watchdog: marked " + fyiIds.length + " FYI as read");
            }
        } catch(e) {
            hop.log("Watchdog: email triage failed: " + e.message);
            // Continue to calendar check below
        }

        // Update notified email IDs (only if triage succeeded)
        if (typeof result !== "undefined" && result.emails) {
            var allIds = prevIds.concat(result.emails.map(function(e) { return e.id; }));
            hop.kv.set("email-monitor", "notified_ids", JSON.stringify(allIds));
        } else {
            // Mark new IDs as seen even if triage failed, to prevent re-processing
            var allIds = prevIds.concat(newMessageIds);
            hop.kv.set("email-monitor", "notified_ids", JSON.stringify(allIds));
        }
    }

    // Check calendar events in next 60 minutes (always, no Claude needed)
    var upcomingEvents = fetchCalendarEvents(1);
    var notifiedEvents = [];
    try {
        var stored = hop.kv.get("email-monitor", "notified_event_ids");
        if (stored) notifiedEvents = JSON.parse(stored);
    } catch(e) {}

    var newEvents = upcomingEvents.filter(function(ev) {
        return !ev.allDay && notifiedEvents.indexOf(ev.id) === -1;
    });

    for (var i = 0; i < newEvents.length; i++) {
        var ev = newEvents[i];
        var t = ev.start.match(/T(\d{2}):(\d{2})/);
        var timeStr = t ? (parseInt(t[1]) % 12 || 12) + ":" + t[2] + (parseInt(t[1]) >= 12 ? "PM" : "AM") : "";
        var line = timeStr + " " + ev.title;
        if (ev.location) line += " @ " + ev.location.substring(0, 25);
        alerts.push(line);
    }

    if (newEvents.length > 0) {
        var allEventIds = notifiedEvents.concat(newEvents.map(function(e) { return e.id; }));
        hop.kv.set("email-monitor", "notified_event_ids", JSON.stringify(allEventIds));
    }

    if (alerts.length > 0) {
        sendSMS(alerts.join("\n"));
        hop.log("Watchdog: " + alerts.length + " alerts sent via SMS");
        return "Watchdog: " + alerts.length + " alerts";
    }

    return "Watchdog: all clear";
}
