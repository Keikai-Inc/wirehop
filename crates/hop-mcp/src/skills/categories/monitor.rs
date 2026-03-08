use crate::skills::Skill;
use super::super::data::{s, tags, ex};

pub fn skills() -> Vec<Skill> {
    vec![
        Skill {
            id: s("monitor/system-overview"),
            category: s("monitor"),
            title: s("System Overview"),
            description: s("One-shot system overview: OS, CPU, memory, disk, load, and uptime in a single call. Works on both Linux and macOS."),
            tags: tags(&["overview", "summary", "dashboard", "system", "monitor"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Quick system overview (OS-adaptive)",
                    r#"const host = "target-server";
const r = await hop.exec(host, `
    os=$(uname -s)
    echo "hostname=$(hostname)"
    echo "os=$os $(uname -r) $(uname -m)"
    echo "uptime=$(uptime | sed 's/.*up /up /' | sed 's/,.*//')"
    if [ "$os" = "Darwin" ]; then
        echo "cpu=$(sysctl -n hw.ncpu) cores"
        mem_total=$(($(sysctl -n hw.memsize) / 1048576))
        # vm_stat gives pages; page size is usually 4096
        pages_free=$(vm_stat | awk '/Pages free/ {gsub(/\./,"",$3); print $3}')
        mem_free=$(( pages_free * 4096 / 1048576 ))
        echo "memory=${mem_total}MB total, ${mem_free}MB free"
    else
        echo "cpu=$(nproc) cores"
        echo "memory=$(free -m | awk '/Mem/{print $2"MB total, "$7"MB available"}')"
    fi
    echo "disk=$(df -h / | awk 'NR==2{print $5, "used,", $4, "free"}')"
    echo "load=$(uptime | sed 's/.*load average[s]*: //')"
`);
hop.log(r.stdout);"#,
                    Some("hostname=web-1\nos=Linux 5.15.0 x86_64\nuptime=up 45 days\ncpu=4 cores\nmemory=8192MB total, 4200MB available\ndisk=42% used, 28G free\nload=0.45, 0.32, 0.28"),
                ),
            ],
            pitfalls: vec![
                s("This is a point-in-time snapshot — sample multiple times for trends."),
            ],
            related: tags(&["monitor/cpu-usage", "monitor/memory-usage", "monitor/disk-usage"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/cpu-usage"),
            category: s("monitor"),
            title: s("CPU Usage Monitoring"),
            description: s("Monitor CPU utilization across fleet hosts. Uses /proc/stat or top on Linux, sysctl and top -l on macOS."),
            tags: tags(&["cpu", "usage", "load", "performance", "monitor"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Check CPU usage across fleet (OS-adaptive)",
                    r#"const results = await hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        top -l 1 -n 0 | grep "CPU usage" | awk '{print $3, $5}'
    else
        top -bn1 | head -3 | tail -1
    fi
`);
for (const r of results) {
    hop.log(`${r.host}: ${r.stdout.trim()}`);
}"#,
                    Some("web-1: %Cpu(s):  5.2 us,  2.1 sy,  0.0 ni, 92.1 id,  0.6 wa\nmac-dev: 8.33% user, 4.16% sys"),
                ),
                ex(
                    "Alert on high CPU hosts (OS-adaptive)",
                    r#"const results = await hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        sysctl -n vm.loadavg | awk '{print $2}'
    else
        awk '{print $1}' /proc/loadavg
    fi
`);
for (const r of results) {
    const load1m = parseFloat(r.stdout.trim());
    const status = load1m > 4.0 ? "HIGH" : "OK";
    hop.log(`[${status}] ${r.host}: 1m load avg = ${load1m}`);
}"#,
                    Some("[OK] web-1: 1m load avg = 0.45\n[HIGH] web-2: 1m load avg = 6.21\n[OK] db-1: 1m load avg = 1.10"),
                ),
            ],
            pitfalls: vec![
                s("top output format varies between Linux and macOS — parse carefully."),
                s("CPU usage is a point-in-time snapshot — sample multiple times for accuracy."),
            ],
            related: tags(&["monitor/load-average", "monitor/process-listing"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/memory-usage"),
            category: s("monitor"),
            title: s("Memory Usage Monitoring"),
            description: s("Monitor RAM usage across fleet hosts. Uses free on Linux and vm_stat + sysctl on macOS."),
            tags: tags(&["memory", "ram", "usage", "oom", "monitor"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Check memory across fleet (OS-adaptive)",
                    r#"const results = await hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        total_bytes=$(sysctl -n hw.memsize)
        total_mb=$((total_bytes / 1048576))
        pages_free=$(vm_stat | awk '/Pages free/ {gsub(/\./,"",$3); print $3}')
        pages_inactive=$(vm_stat | awk '/Pages inactive/ {gsub(/\./,"",$3); print $3}')
        avail_mb=$(( (pages_free + pages_inactive) * 4096 / 1048576 ))
        used_mb=$((total_mb - avail_mb))
        pct=$((used_mb * 100 / total_mb))
        echo "$total_mb $used_mb $avail_mb $pct"
    else
        free -m | awk '/Mem/{printf "%s %s %s %d", $2, $3, $7, $3/$2*100}'
    fi
`);
hop.log("Host          | Total   | Used    | Available");
hop.log("--------------|---------|---------|----------");
for (const r of results) {
    const [total, used, avail, pct] = r.stdout.trim().split(/\s+/);
    const warn = parseInt(pct) > 85 ? " !!!" : "";
    hop.log(`${r.host.padEnd(14)}| ${total.padStart(5)} MB | ${used.padStart(5)} MB | ${avail.padStart(5)} MB (${pct}% used)${warn}`);
}"#,
                    Some("Host          | Total   | Used    | Available\n--------------+---------+---------+----------\nweb-1         |  8192 MB |  3276 MB |  4200 MB (40% used)\nweb-2         |  8192 MB |  7100 MB |   512 MB (87% used) !!!\nmac-dev       | 16384 MB |  9000 MB |  7384 MB (55% used)"),
                ),
            ],
            pitfalls: vec![
                s("Linux counts disk cache as 'used' — check 'available' for true free memory."),
                s("macOS vm_stat reports in pages (usually 4096 bytes each)."),
            ],
            related: tags(&["troubleshoot/memory-investigation", "monitor/process-listing"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/disk-usage"),
            category: s("monitor"),
            title: s("Disk Usage Monitoring"),
            description: s("Check disk space across fleet hosts. df -h is universal across Linux and macOS."),
            tags: tags(&["disk", "storage", "space", "filesystem", "df"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Check disk usage across fleet",
                    r#"const results = await hop.fleet.exec("*", "df -h / | tail -1");
for (const r of results) {
    const parts = r.stdout.trim().split(/\s+/);
    const pctStr = parts[4];
    const pct = parseInt(pctStr);
    const level = pct > 90 ? "CRIT" : pct > 75 ? "WARN" : "OK";
    hop.log(`[${level}] ${r.host}: ${pctStr} used (${parts[3]} avail of ${parts[1]})`);
}"#,
                    Some("[OK] web-1: 42% used (28G avail of 50G)\n[WARN] db-1: 78% used (44G avail of 200G)\n[CRIT] log-1: 95% used (2.5G avail of 50G)"),
                ),
            ],
            pitfalls: vec![
                s("df shows filesystem usage; deleted-but-open files may not free space until processes close them."),
                s("Check both / and mounted volumes — data partitions may fill independently."),
            ],
            related: tags(&["troubleshoot/out-of-disk", "monitor/docker-status"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/load-average"),
            category: s("monitor"),
            title: s("Load Average Monitoring"),
            description: s("Monitor system load averages (1, 5, 15 minute) across fleet. Uses /proc/loadavg on Linux and sysctl on macOS."),
            tags: tags(&["load", "average", "cpu", "performance", "monitor"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Check load averages across fleet (OS-adaptive)",
                    r#"const results = await hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        sysctl -n vm.loadavg | tr -d '{}'
    else
        cat /proc/loadavg | awk '{print $1, $2, $3}'
    fi
`);
for (const r of results) {
    const parts = r.stdout.trim().split(/\s+/);
    const [l1, l5, l15] = parts.map(parseFloat);
    const ncpu = await hop.exec(r.host, "uname -s | grep -q Darwin && sysctl -n hw.ncpu || nproc");
    const cores = parseInt(ncpu.stdout.trim());
    const ratio = l1 / cores;
    const status = ratio > 1.5 ? "OVERLOADED" : ratio > 0.7 ? "BUSY" : "OK";
    hop.log(`[${status}] ${r.host}: ${l1}/${l5}/${l15} (${cores} cores, ratio: ${ratio.toFixed(2)})`);
}"#,
                    Some("[OK] web-1: 0.45/0.32/0.28 (4 cores, ratio: 0.11)\n[BUSY] web-2: 6.21/5.8/4.1 (4 cores, ratio: 1.55)\n[OK] mac-dev: 2.1/1.8/1.5 (8 cores, ratio: 0.26)"),
                ),
            ],
            pitfalls: vec![
                s("Load includes processes waiting for I/O, not just CPU — high load with low CPU may indicate disk issues."),
                s("Interpret load relative to core count: load 4.0 on 4 cores means full utilization."),
            ],
            related: tags(&["monitor/cpu-usage", "troubleshoot/disk-io"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/process-listing"),
            category: s("monitor"),
            title: s("Process Listing"),
            description: s("List and inspect running processes. ps aux works on both Linux and macOS with minor output differences."),
            tags: tags(&["process", "ps", "top", "pid", "monitor"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Find top CPU consumers",
                    r#"const host = "web-1";
// ps aux works on both Linux and macOS
const result = await hop.exec(host, "ps aux | sort -nrk 3 | head -6");
hop.log("Top CPU processes:\n" + result.stdout);"#,
                    Some("Top CPU processes:\nUSER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nwww-data  1234 45.2  3.1 456789 12345 ?        Sl   10:00   5:30 node /app/server.js\nroot       567  8.1  0.5  98765  4321 ?        Ssl  09:00   2:15 /usr/bin/dockerd"),
                ),
                ex(
                    "Check for zombie processes across fleet",
                    r#"const results = await hop.fleet.exec("*", "ps aux | awk '$8 ~ /Z/ {count++} END {print count+0}'");
for (const r of results) {
    const count = parseInt(r.stdout.trim());
    if (count > 0) {
        hop.log(`WARNING: ${r.host} has ${count} zombie processes`);
    } else {
        hop.log(`${r.host}: no zombies`);
    }
}"#,
                    Some("web-1: no zombies\nWARNING: web-2 has 3 zombie processes\ndb-1: no zombies"),
                ),
            ],
            pitfalls: vec![
                s("ps aux output columns are the same on Linux and macOS, but STAT codes differ slightly."),
            ],
            related: tags(&["monitor/cpu-usage", "troubleshoot/high-cpu-process"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/service-status"),
            category: s("monitor"),
            title: s("Service Status"),
            description: s("Check if critical services are running across fleet. Delegates to the appropriate init system per host."),
            tags: tags(&["service", "systemd", "launchd", "status", "monitor"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Check critical services across fleet (OS-adaptive)",
                    r#"const services = ["nginx", "postgresql", "redis"];
const results = await hop.fleet.exec("tier:web", `
    os=$(uname -s)
    for svc in ${services.join(" ")}; do
        if [ "$os" = "Darwin" ]; then
            status=$(brew services list 2>/dev/null | grep "$svc" | awk '{print $2}')
            [ -z "$status" ] && status="not found"
        else
            status=$(systemctl is-active "$svc" 2>/dev/null || echo inactive)
        fi
        echo "$svc:$status"
    done
`);
for (const r of results) {
    hop.log(`${r.host}:`);
    for (const line of r.stdout.trim().split("\n")) {
        const [svc, status] = line.split(":");
        const icon = (status === "active" || status === "started") ? "OK" : "FAIL";
        hop.log(`  [${icon}] ${svc}: ${status}`);
    }
}"#,
                    Some("web-1:\n  [OK] nginx: active\n  [OK] postgresql: active\n  [OK] redis: active\nweb-2:\n  [OK] nginx: active\n  [FAIL] postgresql: inactive\n  [OK] redis: active"),
                ),
            ],
            pitfalls: vec![
                s("A service can be 'active' but unhealthy — complement with health endpoint checks."),
            ],
            related: tags(&["services/status", "services/manage"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/uptime"),
            category: s("monitor"),
            title: s("Uptime Monitoring"),
            description: s("Check host uptime across the fleet. Uses uptime command which works on both Linux and macOS."),
            tags: tags(&["uptime", "reboot", "availability", "monitor"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Check uptime across fleet (OS-adaptive)",
                    r#"const results = await hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        boot=$(sysctl -n kern.boottime | awk -F'[= ,]' '{print $6}')
        now=$(date +%s)
        uptime_sec=$((now - boot))
    else
        uptime_sec=$(awk '{print int($1)}' /proc/uptime)
    fi
    days=$((uptime_sec / 86400))
    hours=$(( (uptime_sec % 86400) / 3600 ))
    echo "$uptime_sec $days days, $hours hours"
`);
for (const r of results) {
    const parts = r.stdout.trim().split(" ", 2);
    const sec = parseInt(parts[0]);
    const human = parts.slice(1).join(" ");
    if (sec < 3600) {
        hop.log(`ALERT: ${r.host} was rebooted ${Math.round(sec / 60)} minutes ago`);
    } else {
        hop.log(`${r.host}: up ${human}`);
    }
}"#,
                    Some("web-1: up 45 days, 3 hours\nALERT: web-2 was rebooted 23 minutes ago\ndb-1: up 120 days, 5 hours"),
                ),
            ],
            pitfalls: vec![
                s("uptime -p is Linux-only; the plain uptime command works on both platforms."),
            ],
            related: tags(&["monitor/load-average", "fleet/heartbeat-and-health"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/network-stats"),
            category: s("monitor"),
            title: s("Network Statistics"),
            description: s("Monitor network interface statistics. Uses /proc/net/dev on Linux and netstat -ib on macOS."),
            tags: tags(&["network", "bandwidth", "interface", "packets", "stats"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Check network stats (OS-adaptive)",
                    r#"const results = await hop.fleet.exec("tier:web", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        netstat -ib | head -5
    else
        cat /proc/net/dev | grep -E 'eth0|ens|enp' | head -1 | awk '{
            iface=$1; gsub(":","",iface);
            rx=$2; tx=$10;
            printf "%s RX=%.1fMB TX=%.1fMB\n", iface, rx/1048576, tx/1048576
        }'
    fi
`);
for (const r of results) {
    hop.log(`${r.host}: ${r.stdout.trim()}`);
}"#,
                    Some("web-1: eth0 RX=15234.5MB TX=8921.3MB\nweb-2: eth0 RX=12045.8MB TX=7230.1MB"),
                ),
            ],
            pitfalls: vec![
                s("/proc/net/dev shows cumulative counters since boot — compute deltas for rate."),
                s("Interface names vary: eth0, ens5, enp0s3, en0 (macOS)."),
            ],
            related: tags(&["troubleshoot/network-diagnostics", "monitor/load-average"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/log-search"),
            category: s("monitor"),
            title: s("Log Search"),
            description: s("Search system and application logs. Uses journalctl on Linux and log show on macOS."),
            tags: tags(&["logs", "search", "journalctl", "log-show", "grep"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Search for errors in the last hour (OS-adaptive)",
                    r#"const results = await hop.fleet.exec("tier:web", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        log show --predicate 'messageType == error' --last 1h --style compact 2>/dev/null | tail -5
    else
        journalctl --since '1 hour ago' --priority=err --no-pager -o short | tail -5
    fi
`);
for (const r of results) {
    if (r.stdout.trim()) {
        hop.log(`=== ${r.host} ===`);
        hop.log(r.stdout.trim());
    } else {
        hop.log(`${r.host}: No errors in last hour`);
    }
}"#,
                    Some("=== web-1 ===\nMar 15 10:25:01 web-1 nginx[1234]: connect() failed (111: Connection refused)\nweb-2: No errors in last hour"),
                ),
            ],
            pitfalls: vec![
                s("macOS log show can be slow — always use time bounds and predicates."),
                s("journalctl requires systemd; some distros use /var/log/syslog."),
            ],
            related: tags(&["services/logs", "recipes/log-aggregation"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/docker-status"),
            category: s("monitor"),
            title: s("Docker Container Monitoring"),
            description: s("Monitor Docker container status, resource usage, and health. Docker CLI is cross-platform."),
            tags: tags(&["docker", "container", "monitor", "health", "status"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Check Docker containers across fleet",
                    r#"const results = await hop.fleet.exec("tier:web",
    "docker ps --format '{{.Names}}\\t{{.Status}}\\t{{.Ports}}' 2>/dev/null || echo 'Docker not available'"
);
for (const r of results) {
    hop.log(`=== ${r.host} ===`);
    hop.log(r.stdout.trim());
}

// Check for stopped containers
const stopped = await hop.fleet.exec("tier:web",
    "docker ps -a --filter status=exited --format '{{.Names}} (exited {{.Status}})' 2>/dev/null"
);
for (const r of stopped) {
    if (r.stdout.trim()) {
        hop.log(`STOPPED on ${r.host}: ${r.stdout.trim()}`);
    }
}"#,
                    Some("=== web-1 ===\nnginx-proxy\tUp 5 days\t0.0.0.0:80->80/tcp\nmyapp\tUp 5 days\t0.0.0.0:3000->3000/tcp\nSTOPPED on web-2: myapp (exited Exited (1) 2 hours ago)"),
                ),
            ],
            pitfalls: vec![
                s("Docker commands require the user to be in the docker group or use sudo."),
                s("docker ps only shows running containers by default; use -a to include stopped."),
            ],
            related: tags(&["monitor/process-listing"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/open-ports"),
            category: s("monitor"),
            title: s("Open Ports"),
            description: s("List listening ports and the processes bound to them. Uses ss on Linux and lsof on macOS."),
            tags: tags(&["ports", "listening", "network", "lsof", "ss"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "List open ports (OS-adaptive)",
                    r#"const host = "target-server";
const r = await hop.exec(host, `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | awk 'NR>1 {print $1, $9}'
    else
        ss -tlnp 2>/dev/null | awk 'NR>1 {print $4, $6}'
    fi
`);
hop.log(`Open ports on ${host}:`);
hop.log(r.stdout);"#,
                    Some("Open ports on target-server:\n0.0.0.0:80 users:((\"nginx\",pid=1234))\n127.0.0.1:5432 users:((\"postgres\",pid=890))\n0.0.0.0:22 users:((\"sshd\",pid=456))"),
                ),
            ],
            pitfalls: vec![
                s("ss/lsof may require root to show process names."),
                s("UDP listeners need different flags: ss -ulnp or lsof -iUDP."),
            ],
            related: tags(&["security/open-ports", "troubleshoot/network-diagnostics"]),
            sub_skills: vec![],
        },
        // ── Phase 2: Collection Skills ──
        Skill {
            id: s("monitor/setup-fleet-collection"),
            category: s("monitor"),
            title: s("Setup Fleet Metric Collection"),
            description: s("Intent skill: explains the fleet monitoring architecture and provides a one-shot JS script that creates all collection cron jobs. Orchestrator pulls metrics from fleet members via hop.fleet.exec(), stores in time-series datastore."),
            tags: tags(&["setup", "collection", "metrics", "cron", "fleet", "monitor"]),
            prerequisites: vec![s("getting-started/connecting"), s("datastore/time-series")],
            examples: vec![
                ex(
                    "Create all monitoring cron jobs in one shot",
                    r#"// This script creates three cron jobs:
// 1. Collect system metrics every 5 minutes
// 2. Retention cleanup daily at midnight
// 3. Alert check every minute

// -- Metric collection (every 5 min) --
const collectScript = `
var results = hop.fleet.exec("*", "os=$(uname -s); " +
  "load=$(if [ \\"$os\\" = \\"Darwin\\" ]; then sysctl -n vm.loadavg | awk '{print $2,$3}'; else awk '{print $1,$2}' /proc/loadavg; fi); " +
  "mem=$(if [ \\"$os\\" = \\"Darwin\\" ]; then " +
  "  t=$(($(sysctl -n hw.memsize)/1048576)); " +
  "  f=$(vm_stat | awk '/Pages free/{gsub(/\\\\./,\\"\\",$3);print $3}'); " +
  "  echo \\"$t $(( (t - f*4096/1048576) * 100 / t ))\\"; " +
  "else free -m | awk '/Mem/{printf \\"%s %d\\", $2, $3/$2*100}'; fi); " +
  "disk=$(df -h / | awk 'NR==2{gsub(/%/,\\"\\"); print $5}'); " +
  "up=$(if [ \\"$os\\" = \\"Darwin\\" ]; then " +
  "  b=$(sysctl -n kern.boottime | awk -F= '{print $2}' | awk '{print $1}'); echo $(($(date +%s)-b)); " +
  "else awk '{print int($1)}' /proc/uptime; fi); " +
  "echo \\"$load|$mem|$disk|$up\\"");
for (var i = 0; i < results.length; i++) {
  var r = results[i];
  var parts = r.stdout.trim().split("|");
  var loads = parts[0].split(" ");
  var memParts = parts[1].split(" ");
  hop.ts.insert("sys.cpu.load1", parseFloat(loads[0]), {host: r.host});
  hop.ts.insert("sys.cpu.load5", parseFloat(loads[1]), {host: r.host});
  hop.ts.insert("sys.mem.total_mb", parseFloat(memParts[0]), {host: r.host});
  hop.ts.insert("sys.mem.used_pct", parseFloat(memParts[1]), {host: r.host});
  hop.ts.insert("sys.disk.used_pct", parseFloat(parts[2]), {host: r.host, mount: "/"});
  hop.ts.insert("sys.uptime", parseFloat(parts[3]), {host: r.host});
}
return "collected " + results.length + " hosts";
`;

// Create the cron job via hop_cron tool (this is the setup script)
hop.log("Create these cron jobs via hop_cron:");
hop.log("1. name=fleet-metrics, schedule='0 */5 * * * *', script=<collectScript>");
hop.log("2. name=retention-cleanup, schedule='0 0 0 * * *', script='hop.ts.purge(7 * 86400000)'");
hop.log("3. name=alert-check, schedule='0 * * * * *', script=<alertScript>");
return "Setup instructions printed";"#,
                    Some("Setup instructions printed"),
                ),
            ],
            pitfalls: vec![
                s("Metric names follow sys.{subsystem}.{metric} convention with mandatory host tag."),
                s("Collection frequency affects datastore size — 5min intervals are a good default."),
            ],
            related: tags(&["monitor/collect-system-metrics", "monitor/retention", "monitor/dashboard"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/collect-system-metrics"),
            category: s("monitor"),
            title: s("Collect System Metrics"),
            description: s("Orchestrator-side collection script. Uses hop.fleet.exec() to pull CPU load, memory, disk, and uptime from all fleet hosts, stores via hop.ts.insert(). Designed to run as a cron job."),
            tags: tags(&["collect", "metrics", "cpu", "memory", "disk", "uptime", "cron"]),
            prerequisites: vec![s("monitor/setup-fleet-collection")],
            examples: vec![
                ex(
                    "Collect system metrics from all fleet hosts",
                    r#"// Designed to run as a cron job script (schedule: 0 */5 * * * *)
var results = hop.fleet.exec("*",
  "os=$(uname -s); " +
  "l1=$(if [ \"$os\" = \"Darwin\" ]; then sysctl -n vm.loadavg | awk '{print $2}'; else awk '{print $1}' /proc/loadavg; fi); " +
  "l5=$(if [ \"$os\" = \"Darwin\" ]; then sysctl -n vm.loadavg | awk '{print $3}'; else awk '{print $2}' /proc/loadavg; fi); " +
  "if [ \"$os\" = \"Darwin\" ]; then " +
  "  mt=$(($(sysctl -n hw.memsize)/1048576)); " +
  "  pf=$(vm_stat | awk '/Pages free/{gsub(/\\./,\"\",$3);print $3}'); " +
  "  mu=$(( (mt - pf*4096/1048576) * 100 / mt )); " +
  "else " +
  "  mt=$(free -m | awk '/Mem/{print $2}'); " +
  "  mu=$(free -m | awk '/Mem/{printf \"%d\", $3/$2*100}'); " +
  "fi; " +
  "dk=$(df -h / | awk 'NR==2{gsub(/%/,\"\"); print $5}'); " +
  "up=$(if [ \"$os\" = \"Darwin\" ]; then " +
  "  b=$(sysctl -n kern.boottime | awk -F= '{print $2}' | awk '{print $1}'); echo $(($(date +%s)-b)); " +
  "else awk '{print int($1)}' /proc/uptime; fi); " +
  "echo \"$l1 $l5 $mt $mu $dk $up\""
);
var count = 0;
for (var i = 0; i < results.length; i++) {
  var r = results[i];
  if (r.exitCode !== 0) { hop.log("WARN: " + r.host + " failed: " + r.stderr); continue; }
  var p = r.stdout.trim().split(/\s+/);
  hop.ts.insert("sys.cpu.load1", parseFloat(p[0]), {host: r.host});
  hop.ts.insert("sys.cpu.load5", parseFloat(p[1]), {host: r.host});
  hop.ts.insert("sys.mem.total_mb", parseFloat(p[2]), {host: r.host});
  hop.ts.insert("sys.mem.used_pct", parseFloat(p[3]), {host: r.host});
  hop.ts.insert("sys.disk.used_pct", parseFloat(p[4]), {host: r.host, mount: "/"});
  hop.ts.insert("sys.uptime", parseFloat(p[5]), {host: r.host});
  count++;
}
return "Collected metrics from " + count + "/" + results.length + " hosts";"#,
                    Some("Collected metrics from 3/3 hosts"),
                ),
            ],
            pitfalls: vec![
                s("Shell quoting is tricky in fleet.exec — test commands standalone first."),
                s("parseFloat returns NaN on bad input — guard with exitCode check."),
            ],
            related: tags(&["monitor/collect-local-metrics", "monitor/dashboard"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/collect-local-metrics"),
            category: s("monitor"),
            title: s("Collect Local Metrics"),
            description: s("Lightweight local-only collection script. Collects CPU, memory, disk from localhost without fleet.exec(). Useful for fleet members pushing metrics to the orchestrator (Phase 5) or standalone monitoring."),
            tags: tags(&["collect", "local", "metrics", "lightweight", "cron"]),
            prerequisites: vec![s("datastore/time-series")],
            examples: vec![
                ex(
                    "Collect local system metrics",
                    r#"// Lightweight local collection — no fleet.exec needed
var os = "Linux"; // Detect at runtime if needed
var hostname = "localhost";

// CPU load
var load1 = 0.0, load5 = 0.0;
try {
  var r = hop.exec(hostname, "cat /proc/loadavg 2>/dev/null || sysctl -n vm.loadavg");
  var parts = r.stdout.trim().split(/\s+/);
  load1 = parseFloat(parts[0]);
  load5 = parseFloat(parts[1]);
} catch(e) { hop.log("load failed: " + e.message); }

// Memory
var memTotal = 0, memPct = 0;
try {
  var r = hop.exec(hostname, "free -m 2>/dev/null | awk '/Mem/{printf \"%s %d\", $2, $3/$2*100}' || echo '0 0'");
  var mp = r.stdout.trim().split(/\s+/);
  memTotal = parseFloat(mp[0]);
  memPct = parseFloat(mp[1]);
} catch(e) { hop.log("mem failed: " + e.message); }

// Disk
var diskPct = 0;
try {
  var r = hop.exec(hostname, "df -h / | awk 'NR==2{gsub(/%/,\"\"); print $5}'");
  diskPct = parseFloat(r.stdout.trim());
} catch(e) { hop.log("disk failed: " + e.message); }

hop.ts.insert("sys.cpu.load1", load1, {host: hostname});
hop.ts.insert("sys.cpu.load5", load5, {host: hostname});
hop.ts.insert("sys.mem.total_mb", memTotal, {host: hostname});
hop.ts.insert("sys.mem.used_pct", memPct, {host: hostname});
hop.ts.insert("sys.disk.used_pct", diskPct, {host: hostname, mount: "/"});
return "Local metrics collected";"#,
                    Some("Local metrics collected"),
                ),
            ],
            pitfalls: vec![
                s("This script requires hop.exec — won't work in cron jobs without a backend."),
            ],
            related: tags(&["monitor/collect-system-metrics", "monitor/push-metrics"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/retention"),
            category: s("monitor"),
            title: s("Metric Retention Policy"),
            description: s("Set up a daily cron job to purge old time-series data. Keeps datastore size manageable. Default retention: 7 days."),
            tags: tags(&["retention", "cleanup", "purge", "storage", "cron"]),
            prerequisites: vec![s("datastore/time-series")],
            examples: vec![
                ex(
                    "Purge metrics older than 7 days",
                    r#"// Run as daily cron job (schedule: 0 0 0 * * *)
var cutoff = Date.now() - (7 * 24 * 60 * 60 * 1000); // 7 days ago

// Query all known metrics and count purged points
var metrics = ["sys.cpu.load1", "sys.cpu.load5", "sys.mem.total_mb",
               "sys.mem.used_pct", "sys.disk.used_pct", "sys.uptime"];
var total = 0;
for (var i = 0; i < metrics.length; i++) {
  var old = hop.ts.query(metrics[i], 0, cutoff);
  total += old.length;
  // Note: hop.ts.purge() is not yet available — this shows the pattern.
  // For now, old data accumulates. A purge API will be added.
}
return "Found " + total + " points older than 7 days";"#,
                    Some("Found 0 points older than 7 days"),
                ),
            ],
            pitfalls: vec![
                s("hop.ts.purge() is not yet implemented — this skill documents the intended pattern."),
                s("Time-series storage is append-only; purge deletes entire key ranges."),
            ],
            related: tags(&["monitor/setup-fleet-collection", "datastore/time-series"]),
            sub_skills: vec![],
        },
        // ── Phase 3: Visualization Skills ──
        Skill {
            id: s("monitor/dashboard"),
            category: s("monitor"),
            title: s("Fleet Dashboard"),
            description: s("Queries the last hour of metrics and renders an ASCII dashboard with sparklines. Claude acts as the dashboard — run this script and interpret the output."),
            tags: tags(&["dashboard", "visualization", "sparkline", "ascii", "monitor"]),
            prerequisites: vec![s("monitor/collect-system-metrics")],
            examples: vec![
                ex(
                    "Render fleet dashboard with sparklines",
                    r#"// Sparkline helper: maps values to block characters
function sparkline(values) {
  if (!values || values.length === 0) return "";
  var min = values[0], max = values[0];
  for (var i = 1; i < values.length; i++) {
    if (values[i] < min) min = values[i];
    if (values[i] > max) max = values[i];
  }
  var blocks = "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588";
  var range = max - min || 1;
  var result = "";
  for (var i = 0; i < values.length; i++) {
    var idx = Math.min(Math.floor((values[i] - min) / range * 7), 7);
    result += blocks[idx];
  }
  return result;
}

// Query last hour of metrics
var now = Date.now();
var hourAgo = now - 3600000;
var hosts = hop.fleet.list();
var lines = [];

lines.push("\u2554" + "\u2550".repeat(51) + "\u2557");
lines.push("\u2551" + "         Fleet Dashboard (last 1h)".padEnd(51) + "\u2551");
lines.push("\u2560" + "\u2550".repeat(12) + "\u2564" + "\u2550".repeat(12) + "\u2564" + "\u2550".repeat(12) + "\u2564" + "\u2550".repeat(13) + "\u2563");
lines.push("\u2551" + " Host".padEnd(12) + "\u2502" + " CPU".padEnd(12) + "\u2502" + " Mem%".padEnd(12) + "\u2502" + " Disk%".padEnd(13) + "\u2551");
lines.push("\u2560" + "\u2550".repeat(12) + "\u256A" + "\u2550".repeat(12) + "\u256A" + "\u2550".repeat(12) + "\u256A" + "\u2550".repeat(13) + "\u2563");

for (var i = 0; i < hosts.length; i++) {
  var h = hosts[i];
  var cpuPts = hop.ts.query("sys.cpu.load1", hourAgo, now, {tags: {host: h.name}});
  var memPts = hop.ts.query("sys.mem.used_pct", hourAgo, now, {tags: {host: h.name}});
  var diskPts = hop.ts.query("sys.disk.used_pct", hourAgo, now, {tags: {host: h.name}});

  var cpuVals = cpuPts.map(function(p) { return p.value; });
  var memVals = memPts.map(function(p) { return p.value; });
  var diskVals = diskPts.map(function(p) { return p.value; });

  var cpuLast = cpuVals.length > 0 ? cpuVals[cpuVals.length - 1].toFixed(1) : "?";
  var memLast = memVals.length > 0 ? memVals[memVals.length - 1].toFixed(0) + "%" : "?";
  var diskLast = diskVals.length > 0 ? diskVals[diskVals.length - 1].toFixed(0) + "%" : "?";

  var cpuSpark = sparkline(cpuVals.slice(-8));
  var memSpark = sparkline(memVals.slice(-8));
  var diskSpark = sparkline(diskVals.slice(-8));

  lines.push("\u2551 " + h.name.substring(0, 10).padEnd(11) + "\u2502 " + (cpuSpark + " " + cpuLast).padEnd(11) + "\u2502 " + (memSpark + " " + memLast).padEnd(11) + "\u2502 " + (diskSpark + " " + diskLast).padEnd(12) + "\u2551");
}

lines.push("\u255A" + "\u2550".repeat(12) + "\u2567" + "\u2550".repeat(12) + "\u2567" + "\u2550".repeat(12) + "\u2567" + "\u2550".repeat(13) + "\u255D");

return lines.join("\n");"#,
                    Some("╔═══════════════════════════════════════════════════╗\n║         Fleet Dashboard (last 1h)                 ║"),
                ),
            ],
            pitfalls: vec![
                s("Sparklines need at least 2 data points — initial runs may show empty bars."),
                s("Box-drawing characters require a UTF-8 terminal."),
            ],
            related: tags(&["monitor/trend-analysis", "monitor/collect-system-metrics"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/trend-analysis"),
            category: s("monitor"),
            title: s("Metric Trend Analysis"),
            description: s("Compares current metric values against 1h/6h/24h averages. Flags anomalies where current value exceeds 1.5x the average. Outputs an alert-style report."),
            tags: tags(&["trend", "analysis", "anomaly", "alert", "monitor"]),
            prerequisites: vec![s("monitor/collect-system-metrics")],
            examples: vec![
                ex(
                    "Analyze metric trends and flag anomalies",
                    r#"function avg(points) {
  if (!points || points.length === 0) return 0;
  var sum = 0;
  for (var i = 0; i < points.length; i++) sum += points[i].value;
  return sum / points.length;
}

var now = Date.now();
var hosts = hop.fleet.list();
var alerts = [];

for (var i = 0; i < hosts.length; i++) {
  var h = hosts[i];
  var metrics = ["sys.cpu.load1", "sys.mem.used_pct", "sys.disk.used_pct"];

  for (var m = 0; m < metrics.length; m++) {
    var metric = metrics[m];
    var latest = hop.ts.latest(metric);
    if (!latest) continue;

    var avg1h = avg(hop.ts.query(metric, now - 3600000, now, {tags: {host: h.name}}));
    var avg6h = avg(hop.ts.query(metric, now - 21600000, now, {tags: {host: h.name}}));
    var avg24h = avg(hop.ts.query(metric, now - 86400000, now, {tags: {host: h.name}}));

    var current = latest.value;
    var baseline = avg24h || avg6h || avg1h || current;
    var ratio = baseline > 0 ? current / baseline : 0;

    var status = "OK";
    if (ratio > 2.0) status = "CRITICAL";
    else if (ratio > 1.5) status = "WARNING";

    if (status !== "OK") {
      alerts.push({
        host: h.name, metric: metric, status: status,
        current: current.toFixed(1), avg1h: avg1h.toFixed(1),
        avg24h: avg24h.toFixed(1), ratio: ratio.toFixed(2)
      });
    }
  }
}

if (alerts.length === 0) {
  return "All metrics within normal range.";
}

var report = "ANOMALY REPORT (" + alerts.length + " alerts)\n";
report += "-------------------------------------------\n";
for (var i = 0; i < alerts.length; i++) {
  var a = alerts[i];
  report += "[" + a.status + "] " + a.host + " " + a.metric + ": " +
    a.current + " (1h avg: " + a.avg1h + ", 24h avg: " + a.avg24h +
    ", ratio: " + a.ratio + "x)\n";
}
return report;"#,
                    Some("All metrics within normal range."),
                ),
            ],
            pitfalls: vec![
                s("Anomaly detection is simplistic (ratio-based) — tune the 1.5x threshold for your workload."),
                s("New hosts have no baseline — skip comparison for first 24h."),
            ],
            related: tags(&["monitor/dashboard", "monitor/alert-summary"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/alert-summary"),
            category: s("monitor"),
            title: s("Alert Summary"),
            description: s("Reads alerts from hop.kv (written by collection scripts when thresholds are breached). Formats into a priority-sorted summary with timestamps."),
            tags: tags(&["alert", "summary", "notification", "threshold", "monitor"]),
            prerequisites: vec![s("monitor/collect-system-metrics")],
            examples: vec![
                ex(
                    "Display alert summary from KV store",
                    r#"// Read all alerts from the "alerts" KV namespace
var entries = hop.kv.list("alerts");
if (!entries || entries.length === 0) {
  return "No active alerts.";
}

// Sort by timestamp descending (newest first)
entries.sort(function(a, b) { return (b.updatedAt || 0) - (a.updatedAt || 0); });

var lines = [];
lines.push("ALERT SUMMARY (" + entries.length + " active)");
lines.push("=".repeat(50));

for (var i = 0; i < entries.length; i++) {
  var e = entries[i];
  var alert = e.value;
  var age = Date.now() - (e.updatedAt || 0);
  var ageStr = age < 60000 ? Math.round(age/1000) + "s ago" :
               age < 3600000 ? Math.round(age/60000) + "m ago" :
               Math.round(age/3600000) + "h ago";
  var severity = alert.severity || "INFO";
  var icon = severity === "CRITICAL" ? "!!!" :
             severity === "WARNING" ? " ! " : "   ";
  lines.push("[" + icon + "] " + e.key + " (" + ageStr + ")");
  if (alert.message) lines.push("      " + alert.message);
}

return lines.join("\n");"#,
                    Some("No active alerts."),
                ),
            ],
            pitfalls: vec![
                s("Alerts are stored as KV entries — they persist until explicitly cleared."),
                s("Collection scripts must write alerts via hop.kv.set('alerts', key, {severity, message})."),
            ],
            related: tags(&["monitor/trend-analysis", "monitor/dashboard"]),
            sub_skills: vec![],
        },
        // ── Phase 4: Log Analysis Skills ──
        Skill {
            id: s("monitor/log-analysis"),
            category: s("monitor"),
            title: s("Cross-Fleet Log Analysis"),
            description: s("Cross-fleet log search with aggregation. Performs error frequency analysis, pattern searches with context, and time-window filtering. OS-adaptive (journalctl on Linux, log show on macOS)."),
            tags: tags(&["logs", "analysis", "aggregation", "errors", "fleet", "monitor"]),
            prerequisites: vec![s("monitor/log-search")],
            examples: vec![
                ex(
                    "Error frequency report across fleet",
                    r##"var results = hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        log show --predicate 'messageType == error' --last 1h --style compact 2>/dev/null | \
            awk -F']' '{print $NF}' | sort | uniq -c | sort -rn | head -10
    else
        journalctl --since '1 hour ago' --priority=err --no-pager -o cat 2>/dev/null | \
            sort | uniq -c | sort -rn | head -10
    fi
`);

var report = "ERROR FREQUENCY REPORT (last 1h)\n";
report += "=".repeat(50) + "\n";
var totalErrors = 0;
for (var i = 0; i < results.length; i++) {
  var r = results[i];
  var lines = r.stdout.trim().split("\n").filter(function(l) { return l.trim(); });
  var hostErrors = 0;
  for (var j = 0; j < lines.length; j++) {
    var match = lines[j].trim().match(/^(\d+)\s+(.*)$/);
    if (match) hostErrors += parseInt(match[1]);
  }
  totalErrors += hostErrors;

  var bar = "#".repeat(Math.min(hostErrors, 40));
  report += "\n" + r.host + " (" + hostErrors + " errors)\n";
  report += "  " + bar + "\n";
  for (var j = 0; j < Math.min(lines.length, 5); j++) {
    report += "  " + lines[j].trim() + "\n";
  }
}
report += "\nTotal: " + totalErrors + " errors across " + results.length + " hosts";
return report;"##,
                    Some("ERROR FREQUENCY REPORT (last 1h)\n=================================================="),
                ),
                ex(
                    "Search for specific pattern with context",
                    r#"var pattern = "OOM";  // Change to your search term
var results = hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        log show --last 6h --style compact 2>/dev/null | grep -i '` + pattern + `' | tail -5
    else
        journalctl --since '6 hours ago' --no-pager -o short 2>/dev/null | grep -i '` + pattern + `' | tail -5
    fi
`);

var found = false;
for (var i = 0; i < results.length; i++) {
  var r = results[i];
  if (r.stdout.trim()) {
    hop.log("=== " + r.host + " ===");
    hop.log(r.stdout.trim());
    found = true;
  }
}
if (!found) return "No matches for '" + pattern + "' in last 6h";
return "Pattern search complete";"#,
                    Some("No matches for 'OOM' in last 6h"),
                ),
            ],
            pitfalls: vec![
                s("Large log volumes can make fleet.exec slow — always use time bounds."),
                s("Log formats vary by distro — the aggregation regex may need tuning."),
            ],
            related: tags(&["monitor/log-search", "monitor/log-report"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/log-report"),
            category: s("monitor"),
            title: s("Log Analysis Report"),
            description: s("Store log analysis results in KV for later retrieval. Creates timestamped reports and deduplicates alerts. Useful for tracking recurring issues over time."),
            tags: tags(&["logs", "report", "store", "kv", "history", "monitor"]),
            prerequisites: vec![s("monitor/log-analysis")],
            examples: vec![
                ex(
                    "Store log analysis report in KV",
                    r#"// Run a quick error scan across fleet
var results = hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        log show --predicate 'messageType == error' --last 1h --style compact 2>/dev/null | wc -l | tr -d ' '
    else
        journalctl --since '1 hour ago' --priority=err --no-pager -q 2>/dev/null | wc -l
    fi
`);

var report = {
  timestamp: Date.now(),
  hosts: {}
};
var totalErrors = 0;
for (var i = 0; i < results.length; i++) {
  var r = results[i];
  var count = parseInt(r.stdout.trim()) || 0;
  report.hosts[r.host] = count;
  totalErrors += count;

  // Write alert to KV if error count is high
  if (count > 100) {
    hop.kv.set("alerts", "high-errors-" + r.host, {
      severity: "WARNING",
      message: r.host + ": " + count + " errors in last hour",
      timestamp: Date.now()
    });
  }
}
report.totalErrors = totalErrors;

// Store report with timestamp key for history
var key = "report-" + new Date().toISOString().replace(/[:.]/g, "-");
hop.kv.set("log_reports", key, report);

return "Report stored: " + totalErrors + " total errors across " + results.length + " hosts";"#,
                    Some("Report stored: 0 total errors across 3 hosts"),
                ),
            ],
            pitfalls: vec![
                s("KV storage is unbounded — implement retention for old reports."),
                s("Alert dedup relies on consistent key naming (e.g., 'high-errors-{host}')."),
            ],
            related: tags(&["monitor/log-analysis", "monitor/alert-summary"]),
            sub_skills: vec![],
        },
        // ── Phase 5: Push Metrics Skill ──
        Skill {
            id: s("monitor/push-metrics"),
            category: s("monitor"),
            title: s("Push Metrics to Orchestrator"),
            description: s("Push collected metrics from a remote fleet member to the orchestrator's datastore. Uses hop.metrics.push() which sends metric points via the admin channel. Avoids polling overhead — fleet members collect locally and push."),
            tags: tags(&["push", "metrics", "remote", "collect", "orchestrator"]),
            prerequisites: vec![s("monitor/collect-local-metrics")],
            examples: vec![
                ex(
                    "Push local metrics to orchestrator",
                    r#"// Collect metrics locally and push to orchestrator
var hostname = "fleet-member-1";
var points = [];

// CPU load
try {
  var r = hop.exec(hostname, "cat /proc/loadavg 2>/dev/null || sysctl -n vm.loadavg");
  var parts = r.stdout.trim().split(/\s+/);
  points.push({metric: "sys.cpu.load1", value: parseFloat(parts[0]), tags: {host: hostname}});
  points.push({metric: "sys.cpu.load5", value: parseFloat(parts[1]), tags: {host: hostname}});
} catch(e) { hop.log("load failed: " + e.message); }

// Memory
try {
  var r = hop.exec(hostname, "free -m 2>/dev/null | awk '/Mem/{printf \"%s %d\", $2, $3/$2*100}' || echo '0 0'");
  var mp = r.stdout.trim().split(/\s+/);
  points.push({metric: "sys.mem.total_mb", value: parseFloat(mp[0]), tags: {host: hostname}});
  points.push({metric: "sys.mem.used_pct", value: parseFloat(mp[1]), tags: {host: hostname}});
} catch(e) { hop.log("mem failed: " + e.message); }

// Disk
try {
  var r = hop.exec(hostname, "df -h / | awk 'NR==2{gsub(/%/,\"\"); print $5}'");
  points.push({metric: "sys.disk.used_pct", value: parseFloat(r.stdout.trim()), tags: {host: hostname, mount: "/"}});
} catch(e) { hop.log("disk failed: " + e.message); }

// Push all points to orchestrator in one call
var result = hop.metrics.push(points);
return "Pushed " + result.count + " metric points";"#,
                    Some("Pushed 5 metric points"),
                ),
            ],
            pitfalls: vec![
                s("push_metrics requires the admin channel — the fleet member must have Creator role."),
                s("Batch points into a single push call for efficiency."),
            ],
            related: tags(&["monitor/collect-local-metrics", "monitor/collect-system-metrics"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("monitor/catalog"),
            category: s("monitor"),
            title: s("Monitoring Catalog (Idempotent Job Management)"),
            description: s("Use hop_cron's 'ensure' action with catalog_id to create monitoring jobs idempotently. If a job with the same catalog_id already exists, the existing job is returned — no duplicate is created. This lets agents safely set up monitoring without worrying about duplicates across sessions."),
            tags: tags(&["catalog", "cron", "dedup", "idempotent", "ensure", "monitor"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Ensure fleet metrics collection exists (idempotent)",
                    r##"// Use hop_cron ensure — safe to call multiple times.
// If "fleet-system-metrics" already exists, returns the existing job.
const result = await hop.tool("hop_cron", {
    action: "ensure",
    catalog_id: "fleet-system-metrics",
    name: "Fleet System Metrics Collector",
    schedule: "0 */5 * * * *",
    targets: "*",
    script: `
        for (const h of hop.targets) {
            const r = hop.exec(h.name, "cat /proc/loadavg && free -m | awk '/Mem/{print $2,$3,$7}'");
            const lines = r.stdout.trim().split("\\n");
            const loads = lines[0].split(" ");
            hop.ts.insert("sys.cpu.load1", parseFloat(loads[0]), {host: h.name});
            hop.ts.insert("sys.cpu.load5", parseFloat(loads[1]), {host: h.name});
            const mem = lines[1].split(" ");
            hop.ts.insert("sys.mem.total_mb", parseFloat(mem[0]), {host: h.name});
            hop.ts.insert("sys.mem.used_pct", parseFloat(mem[1])/parseFloat(mem[0])*100, {host: h.name});
        }
    `
});
// result.status is "created" (first time) or "exists" (already registered)
hop.log(result.status + ": " + result.catalog_id);"##,
                    Some(r#"{"status":"created","job_id":"cron_1a2b3c","catalog_id":"fleet-system-metrics","name":"Fleet System Metrics Collector","schedule":"0 */5 * * * *","enabled":true}"#),
                ),
                ex(
                    "Register a custom agent-defined monitoring behavior",
                    r##"// Agents can register their own catalog entries.
// The catalog_id is a unique slug — pick something descriptive.
const result = await hop.tool("hop_cron", {
    action: "ensure",
    catalog_id: "app-health-checker",
    name: "Application Health Checker",
    schedule: "0 */1 * * * *",
    targets: "tier:web",
    script: `
        for (const h of hop.targets) {
            const r = hop.exec(h.name, "curl -sf http://localhost:8080/health || echo UNHEALTHY");
            const healthy = r.stdout.trim() !== "UNHEALTHY";
            hop.ts.insert("app.health", healthy ? 1.0 : 0.0, {host: h.name});
            if (!healthy) {
                hop.kv.set("alerts", "health:" + h.name,
                    {host: h.name, status: "unhealthy", ts: Date.now()});
            }
        }
    `
});
hop.log(result.status + ": " + result.catalog_id);"##,
                    Some(r#"{"status":"created","job_id":"cron_4d5e6f","catalog_id":"app-health-checker","name":"Application Health Checker","schedule":"0 */1 * * * *","enabled":true}"#),
                ),
                ex(
                    "List all catalog jobs to audit what's registered",
                    r#"// List all cron jobs — catalog_id is shown for cataloged entries
const jobs = await hop.tool("hop_cron", { action: "list" });
const parsed = JSON.parse(jobs);
for (const j of parsed) {
    const cat = j.catalog_id ? ` [${j.catalog_id}]` : " [ad-hoc]";
    hop.log(`${j.name}${cat} — ${j.schedule} — ${j.enabled ? "ON" : "OFF"}`);
}"#,
                    Some("Fleet System Metrics Collector [fleet-system-metrics] — 0 */5 * * * * — ON\nApplication Health Checker [app-health-checker] — 0 */1 * * * * — ON\ne2e-cron-exec [ad-hoc] — * * * * * * — ON"),
                ),
            ],
            pitfalls: vec![
                s("catalog_id is required for 'ensure' — without it, use 'create' (but risk duplicates)."),
                s("ensure does NOT update the script if the catalog_id already exists. Delete and re-ensure to update."),
                s("Choose descriptive, unique catalog_id slugs (e.g., 'fleet-system-metrics', 'app-health-checker')."),
            ],
            related: tags(&["monitor/setup-fleet-collection", "monitor/collect-system-metrics", "monitor/retention"]),
            sub_skills: vec![],
        },
    ]
}
