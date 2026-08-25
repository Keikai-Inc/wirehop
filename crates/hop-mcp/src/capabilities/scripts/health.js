// Health monitoring capability — dual mode (orchestrator + node-local).
//
// Collects: hostname, OS, load average, memory (total/free), disk usage, uptime.
// Stores metrics in time-series (health.load, health.mem_pct, health.disk_pct)
// and latest snapshot in KV (cap:health:<hostname>:latest).

var targets = hop.targets || [];
var isLocal = targets.length === 0;

var healthCmd = [
    'os=$(uname -s); hostname=$(hostname)',
    'if [ "$os" = "Darwin" ]; then',
    '  load=$(sysctl -n vm.loadavg 2>/dev/null | awk "{print \\$2}")',
    '  mem_total=$(($(sysctl -n hw.memsize 2>/dev/null)/1048576))',
    '  mem_free=$(vm_stat 2>/dev/null | awk "/Pages free/{gsub(/\\./,\\"\\",\\$3);p=\\$3}END{print int(p*4096/1048576)}")',
    '  disk_pct=$(df -h / | awk "NR==2{print \\$5}" | tr -d "%")',
    '  up=$(( $(date +%s) - $(sysctl -n kern.boottime 2>/dev/null | awk "{print \\$4}" | tr -d ",") ))',
    'else',
    '  load=$(cat /proc/loadavg 2>/dev/null | awk "{print \\$1}")',
    '  mem_total=$(free -m 2>/dev/null | awk "/Mem/{print \\$2}")',
    '  mem_free=$(free -m 2>/dev/null | awk "/Mem/{print \\$7}")',
    '  disk_pct=$(df / 2>/dev/null | awk "NR==2{print \\$5}" | tr -d "%")',
    '  up=$(awk "{print int(\\$1)}" /proc/uptime 2>/dev/null)',
    'fi',
    'echo "$hostname|$os|$load|$mem_total|$mem_free|$disk_pct|$up"'
].join('\n');

function storeMetrics(hostname, parts) {
    var tags = { host: hostname };
    var memTotal = parseInt(parts[3]) || 1;
    var memFree = parseInt(parts[4]) || 0;
    var memPct = Math.round((1 - memFree / memTotal) * 100);
    var diskPct = parseInt(parts[5]) || 0;
    var load = parseFloat(parts[2]) || 0;

    hop.ts.insert('health.load', load, tags);
    hop.ts.insert('health.mem_pct', memPct, tags);
    hop.ts.insert('health.disk_pct', diskPct, tags);

    hop.kv.set('default', 'cap:health:' + hostname + ':latest',
        JSON.stringify({
            host: hostname,
            os: parts[1],
            load: parts[2],
            mem_pct: memPct,
            disk_pct: diskPct,
            uptime_s: parts[6],
            ts: Date.now()
        })
    );

    hop.log(hostname + ': load=' + parts[2] + ' mem=' + memFree + '/' + memTotal + 'MB disk=' + diskPct + '%');
}

if (isLocal) {
    var r = hop.local(healthCmd);
    if (r.exit_code === 0 && r.stdout.trim()) {
        var parts = r.stdout.trim().split('|');
        storeMetrics(parts[0], parts);
    }
} else {
    for (var i = 0; i < targets.length; i++) {
        var r = hop.exec(targets[i].name, healthCmd);
        if (r.exit_code === 0 && r.stdout.trim()) {
            var parts = r.stdout.trim().split('|');
            storeMetrics(targets[i].name, parts);
        }
    }
}
