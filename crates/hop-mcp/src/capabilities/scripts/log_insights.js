// log-insights capability — AI-aggregated federated log search.
//
// Fans a READ-ONLY search across the target nodes (each greps its OWN logs locally,
// no central collector), collects the matches, and asks Claude to reduce them into
// ONE aggregated answer: patterns, anomalies, and the most important findings.
//
//   hop cap run log-insights --targets web --param query="failed password"
//   hop cap run log-insights --targets prod --param query=OOM --param source=system
//
// Tier: Connect (network) — required because hop.claude() needs network + an
// Anthropic credential (`hop auth anthropic`). The per-node search itself is
// read-only (grep/journalctl/cat only).

function searchCommand(query, source) {
    // Single-quote the query so it's inert data, never shell code.
    var pat = "'" + String(query).split("'").join("'\\''") + "'";
    if (source === "audit") {
        return "hop audit --json --since 24h --limit 2000 | grep -iF -- " + pat;
    }
    if (source && source.indexOf("/") === 0) {
        return "grep -iF -- " + pat + " '" + source.split("'").join("'\\''") + "' 2>/dev/null | head -n 100";
    }
    // Default "system": resolve the native log source per-OS, at the node.
    return "PAT=" + pat + "; " +
        "if command -v journalctl >/dev/null 2>&1; then journalctl --no-pager -n 5000 2>/dev/null | grep -iF -- \"$PAT\"; " +
        "elif [ -r /var/log/syslog ]; then grep -iF -- \"$PAT\" /var/log/syslog /var/log/auth.log 2>/dev/null; " +
        "elif [ -r /var/log/system.log ]; then grep -iF -- \"$PAT\" /var/log/system.log 2>/dev/null; " +
        "elif [ -r /var/log/messages ]; then grep -iF -- \"$PAT\" /var/log/messages /var/log/secure 2>/dev/null; " +
        "fi | head -n 100";
}

function main() {
    var query = hop.params && hop.params.query;
    if (!query) {
        return { error: "query parameter required (--param query=<pattern>)" };
    }
    var source = (hop.params && hop.params.source) || "system";
    var targets = hop.targets || [];
    if (targets.length === 0) {
        return { error: "no targets — run with --targets <group>" };
    }

    var cmd = searchCommand(query, source);
    var results = [];
    var matched = 0;
    for (var i = 0; i < targets.length; i++) {
        var name = targets[i].name;
        try {
            var r = hop.exec(name, cmd); // runs under this cap's read-only sandbox
            var out = (r && r.stdout ? r.stdout : "").trim();
            if (out) {
                matched++;
                results.push({ host: name, matches: out.split("\n").slice(0, 50) });
            }
        } catch (e) {
            results.push({ host: name, error: String(e) });
        }
    }

    if (results.length === 0 || matched === 0) {
        return {
            query: query, source: source,
            hosts_searched: targets.length, hosts_matched: 0,
            summary: "No matches for '" + query + "' across " + targets.length + " host(s)."
        };
    }

    // Reduce to one aggregated answer with Claude.
    var prompt = "You are an SRE analyzing federated log-search results. The search " +
        "pattern was: \"" + query + "\". Below are matching log lines grouped by host " +
        "(JSON). Summarize in a few sentences: what is happening, any anomalies or " +
        "patterns across hosts, and the single most important finding. Be concise.\n\n" +
        JSON.stringify(results).slice(0, 12000);

    var summary;
    try {
        summary = hop.claude(prompt);
    } catch (e) {
        // No Anthropic credential / no network — still return the raw aggregation.
        summary = "(AI summary unavailable: " + String(e) + ") — " + matched +
            " host(s) matched '" + query + "'.";
    }

    var out = {
        query: query, source: source,
        hosts_searched: targets.length, hosts_matched: matched,
        summary: summary, results: results
    };
    hop.log("log-insights: " + matched + "/" + targets.length + " host(s) matched '" + query + "'");
    return out;
}

return main();
