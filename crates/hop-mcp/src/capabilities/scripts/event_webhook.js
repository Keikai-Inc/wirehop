// event-webhook capability — fire a local HTTP POST on warren events.
//
// Polls THIS node's per-node audit log (G4) and POSTs a JSON payload to a
// secret-stored URL when:
//   - a new member joins            (audit category "membership", e.g. member.join)
//   - this node's posture fails      (audit action "posture.fail")
//   - rejected/denied activity spikes (>= deny_threshold deny/failure events
//                                       since the last run — a brute-force signal)
//
// No central collector: each node runs this locally and reports its OWN events.
// Configure: `hop secrets set webhook_url https://hooks.example.com/...`
// (must be a PUBLIC https URL — the cap runs under the restricted `connect`
// sandbox, whose SSRF guard blocks loopback/private/CGNAT targets).
//
// State (watermark) is kept in KV namespace "event-webhook"/"last_ts" so each run
// only acts on events newer than the last.

var NS = "event-webhook";
var FIRST_RUN_LOOKBACK_MS = 10 * 60 * 1000; // first run: only the last 10 minutes

function nodeId() {
    try { return hop.id ? hop.id() : ""; } catch (e) { return ""; }
}

function post(url, payload) {
    payload.node = nodeId();
    try {
        var resp = hop.http.post(url, { json: payload });
        if (resp.status >= 200 && resp.status < 300) {
            hop.log("event-webhook: delivered " + payload.hop_event + " (HTTP " + resp.status + ")");
            return true;
        }
        hop.log("event-webhook: webhook returned HTTP " + resp.status + " for " + payload.hop_event);
    } catch (e) {
        hop.log("event-webhook: POST failed for " + payload.hop_event + ": " + e);
    }
    return false;
}

function main() {
    var url = hop.secrets.get("webhook_url");
    if (!url) {
        hop.log("event-webhook: no webhook_url secret set — nothing to do. " +
                "Run: hop secrets set webhook_url <https-url>");
        return { fired: 0, reason: "no webhook_url" };
    }

    var threshold = 5;
    try {
        if (hop.params && hop.params.deny_threshold) {
            threshold = parseInt(hop.params.deny_threshold, 10) || 5;
        }
    } catch (e) {}

    var now = Date.now();
    var lastTs = 0;
    try {
        var stored = hop.kv.get(NS, "last_ts");
        if (stored) lastTs = parseInt(stored, 10) || 0;
    } catch (e) {}
    // First run (no watermark): only look at the recent past, don't replay history.
    var since = lastTs > 0 ? lastTs : (now - FIRST_RUN_LOOKBACK_MS);

    var events = [];
    try {
        events = hop.audit.query({ since: since, limit: 500 }) || [];
    } catch (e) {
        hop.log("event-webhook: audit query failed: " + e);
        return { fired: 0, reason: "audit query failed" };
    }

    // Strictly newer than the watermark (since_ms is inclusive).
    var fresh = [];
    var maxTs = lastTs;
    for (var i = 0; i < events.length; i++) {
        var ev = events[i];
        if (ev.ts_ms > lastTs) fresh.push(ev);
        if (ev.ts_ms > maxTs) maxTs = ev.ts_ms;
    }

    var fired = 0;
    var denials = [];

    for (var j = 0; j < fresh.length; j++) {
        var e = fresh[j];
        if (e.category === "membership") {
            if (post(url, {
                hop_event: "membership",
                action: e.action, member: e.actor, user: e.actor_user,
                detail: e.detail, ts_ms: e.ts_ms
            })) fired++;
        } else if (e.action === "posture.fail") {
            if (post(url, {
                hop_event: "posture_fail",
                detail: e.detail, ts_ms: e.ts_ms
            })) fired++;
        } else if (e.outcome === "deny" || e.outcome === "failure") {
            denials.push(e);
        }
    }

    // Aggregate rejected/denied activity into one alert when it crosses the threshold.
    if (denials.length >= threshold) {
        var samples = [];
        for (var k = 0; k < denials.length && k < 10; k++) {
            samples.push({
                action: denials[k].action, outcome: denials[k].outcome,
                actor: denials[k].actor, detail: denials[k].detail, ts_ms: denials[k].ts_ms
            });
        }
        if (post(url, {
            hop_event: "denial_threshold",
            count: denials.length, threshold: threshold,
            window_start_ms: since, window_end_ms: now, samples: samples
        })) fired++;
    }

    // Advance the watermark (best-effort delivery; failures are logged above).
    try { hop.kv.set(NS, "last_ts", String(maxTs > 0 ? maxTs : now)); } catch (e) {}

    var summary = {
        fired: fired,
        scanned: fresh.length,
        denials: denials.length,
        threshold: threshold
    };
    hop.log("event-webhook: " + JSON.stringify(summary));
    return summary;
}

// Top-level return hands the summary back to the cron runner (logged per run).
return main();
