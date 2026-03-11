// Log search capability — fan-out dispatch.
//
// Searches system logs across fleet nodes. Each node greps locally
// and returns only matching lines (filter at source, not ship all logs).

var query = (hop.params && hop.params.query) || '';
if (!query) {
    throw new Error('query parameter is required for log-search');
}

var targets = hop.targets || [];
if (targets.length === 0) {
    throw new Error('log-search requires targets (use --targets to specify fleet group)');
}

var safeQuery = query.replace(/"/g, '\\"').replace(/'/g, "'\\''");
var searchCmd = [
    'for f in /var/log/syslog /var/log/system.log /var/log/messages /var/log/auth.log; do',
    '  [ -f "$f" ] && grep -i "' + safeQuery + '" "$f" 2>/dev/null | tail -20',
    'done'
].join('\n');

var results = [];
for (var i = 0; i < targets.length; i++) {
    var r = hop.exec(targets[i].name, searchCmd);
    if (r.stdout.trim()) {
        results.push({ host: targets[i].name, matches: r.stdout.trim() });
        hop.log('=== ' + targets[i].name + ' ===');
        hop.log(r.stdout.trim());
    }
}

return JSON.stringify({
    query: query,
    hosts_searched: targets.length,
    hosts_matched: results.length,
    results: results
});
