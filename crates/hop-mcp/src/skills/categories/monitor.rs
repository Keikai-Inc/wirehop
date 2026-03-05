use crate::skills::{Skill, SkillExample};
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
    ]
}
