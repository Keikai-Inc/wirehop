use crate::skills::{Skill, SkillExample};
use super::super::data::{s, tags, ex};

pub fn skills() -> Vec<Skill> {
    vec![
        Skill {
            id: s("troubleshoot/high-cpu-process"),
            category: s("troubleshoot"),
            title: s("High CPU Process"),
            description: s("Find and diagnose the process consuming the most CPU. Works on both Linux and macOS."),
            tags: tags(&["cpu", "high", "process", "diagnose", "top"]),
            prerequisites: vec![s("monitor/process-listing")],
            examples: vec![
                ex(
                    "Find the top CPU consumer (OS-adaptive)",
                    r#"const host = "app-server-01";
const r = await hop.exec(host, `
    os=$(uname -s)
    echo "=== Top CPU consumers ==="
    ps aux | sort -nrk 3 | head -6
    echo ""
    echo "=== Load average ==="
    if [ "$os" = "Darwin" ]; then
        sysctl -n vm.loadavg
    else
        cat /proc/loadavg
    fi
`);
hop.log(r.stdout);"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("ps shows instantaneous CPU — a process may spike and drop before sampling."),
            ],
            related: tags(&["monitor/cpu-usage", "troubleshoot/process-debugging"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("troubleshoot/out-of-disk"),
            category: s("troubleshoot"),
            title: s("Out of Disk Space"),
            description: s("Find what is consuming disk space. du and find work on both Linux and macOS."),
            tags: tags(&["disk", "full", "space", "du", "cleanup"]),
            prerequisites: vec![s("monitor/disk-usage")],
            examples: vec![
                ex(
                    "Find what is consuming disk space",
                    r#"const host = "full-disk-host";
const r = await hop.exec(host, `
    echo "=== Filesystem usage ==="
    df -h /
    echo ""
    echo "=== Largest directories under / ==="
    du -xh --max-depth=1 / 2>/dev/null | sort -rh | head -10 || \
        du -xd 1 / 2>/dev/null | sort -rn | head -10
    echo ""
    echo "=== Large files modified in last 7 days ==="
    find / -xdev -type f -size +100M -mtime -7 2>/dev/null | head -10
    echo ""
    echo "=== Log file sizes ==="
    du -sh /var/log/* 2>/dev/null | sort -rh | head -5
`);
hop.log(r.stdout);"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("du --max-depth is GNU; macOS uses -d. The example tries both."),
                s("Deleted files held open by processes still consume space — use lsof to find them."),
            ],
            related: tags(&["monitor/disk-usage", "monitor/docker-status"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("troubleshoot/process-debugging"),
            category: s("troubleshoot"),
            title: s("Process Debugging"),
            description: s("Debug hung or misbehaving processes. Uses strace on Linux and dtruss/sample on macOS."),
            tags: tags(&["process", "debug", "strace", "dtruss", "sample", "hang"]),
            prerequisites: vec![s("monitor/process-listing")],
            examples: vec![
                ex(
                    "Debug a process (OS-adaptive)",
                    r#"const host = "app-server-01";
const pid = "12345";

const os = (await hop.exec(host, "uname -s")).stdout.trim();

if (os === "Darwin") {
    // macOS: use sample for CPU profiling
    const sample = await hop.exec(host, `sample ${pid} 3 2>&1 | tail -20`);
    hop.log("Sample output:\n" + sample.stdout);

    // Check open files
    const fds = await hop.exec(host, `lsof -p ${pid} | wc -l`);
    hop.log(`Open file descriptors: ${fds.stdout.trim()}`);
} else {
    // Linux: use strace for syscall tracing
    const strace = await hop.exec(host, `timeout 5 strace -p ${pid} -c 2>&1 || true`);
    hop.log("System call profile:\n" + strace.stdout);

    // Check open files and memory
    const fds = await hop.exec(host, `ls /proc/${pid}/fd 2>/dev/null | wc -l`);
    hop.log(`Open file descriptors: ${fds.stdout.trim()}`);

    const mem = await hop.exec(host, `cat /proc/${pid}/status 2>/dev/null | grep -E 'VmRSS|VmSize|Threads'`);
    hop.log(mem.stdout);
}"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("strace/dtruss add overhead — use briefly on production."),
                s("Some debug tools require root or CAP_SYS_PTRACE."),
            ],
            related: tags(&["monitor/cpu-usage", "monitor/process-listing"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("troubleshoot/network-diagnostics"),
            category: s("troubleshoot"),
            title: s("Network Diagnostics"),
            description: s("Diagnose network issues: routing, DNS, packet loss, latency. Uses ip/ss on Linux, ifconfig/netstat on macOS."),
            tags: tags(&["network", "ping", "traceroute", "connectivity", "latency"]),
            prerequisites: vec![],
            examples: vec![
                ex(
                    "Full network diagnostic (OS-adaptive)",
                    r#"const host = "web-01";
const os = (await hop.exec(host, "uname -s")).stdout.trim();

// Connectivity check (universal)
const ping = await hop.exec(host, "ping -c 5 8.8.8.8");
hop.log("Ping:\n" + ping.stdout);

// DNS resolution (universal)
const dns = await hop.exec(host, "dig +short example.com 2>/dev/null || nslookup example.com 2>/dev/null | tail -2");
hop.log("DNS:\n" + dns.stdout);

// Listening ports
if (os === "Darwin") {
    const ports = await hop.exec(host, "lsof -iTCP -sTCP:LISTEN -P -n");
    hop.log("Listening ports:\n" + ports.stdout);
} else {
    const ports = await hop.exec(host, "ss -tlnp");
    hop.log("Listening ports:\n" + ports.stdout);
}

// Default gateway
if (os === "Darwin") {
    const gw = await hop.exec(host, "route -n get default 2>/dev/null | grep gateway");
    hop.log("Gateway: " + gw.stdout.trim());
} else {
    const gw = await hop.exec(host, "ip route | grep default | awk '{print $3}'");
    hop.log("Gateway: " + gw.stdout.trim());
}"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("ICMP (ping) may be blocked by firewalls — doesn't always mean host is down."),
                s("DNS issues are a common root cause for 'connectivity' problems."),
            ],
            related: tags(&["troubleshoot/dns-resolution", "troubleshoot/connectivity-test"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("troubleshoot/disk-io"),
            category: s("troubleshoot"),
            title: s("Disk I/O Investigation"),
            description: s("Investigate disk I/O bottlenecks. iostat flags differ between Linux and macOS."),
            tags: tags(&["disk", "io", "iowait", "iostat", "latency"]),
            prerequisites: vec![s("monitor/disk-usage")],
            examples: vec![
                ex(
                    "Investigate disk I/O (OS-adaptive)",
                    r#"const host = "db-server-01";
const os = (await hop.exec(host, "uname -s")).stdout.trim();

if (os === "Darwin") {
    const io = await hop.exec(host, "iostat -d -c 3 -w 1");
    hop.log("Disk I/O:\n" + io.stdout);
} else {
    const cpu = await hop.exec(host, "iostat -c 1 3 | tail -1");
    hop.log("CPU stats (check %iowait):\n" + cpu.stdout);

    const io = await hop.exec(host, "iostat -dx 1 3 2>/dev/null | tail -20");
    hop.log("Device I/O:\n" + io.stdout);
}

// Write latency test (universal)
const dd = await hop.exec(host, "dd if=/dev/zero of=/tmp/iotest bs=512 count=1000 oflag=dsync 2>&1 | tail -1");
hop.log("Write latency test:\n" + dd.stdout);
await hop.exec(host, "rm -f /tmp/iotest");"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("High iowait doesn't always mean disk is the bottleneck — could be network I/O."),
                s("The dd test creates actual I/O load — use cautiously on production."),
            ],
            related: tags(&["monitor/disk-usage", "troubleshoot/performance-profiling"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("troubleshoot/memory-investigation"),
            category: s("troubleshoot"),
            title: s("Memory Investigation"),
            description: s("Debug memory issues: OOM kills, leaks, swap. Uses free and /proc on Linux, vm_stat on macOS."),
            tags: tags(&["memory", "oom", "leak", "swap", "debug"]),
            prerequisites: vec![s("monitor/memory-usage")],
            examples: vec![
                ex(
                    "Investigate memory issues (OS-adaptive)",
                    r#"const host = "app-server-01";
const os = (await hop.exec(host, "uname -s")).stdout.trim();

// Memory overview
if (os === "Darwin") {
    const vm = await hop.exec(host, "vm_stat");
    hop.log("Memory (vm_stat):\n" + vm.stdout);
    const top = await hop.exec(host, "top -l 1 -n 10 -o MEM -stats pid,command,mem | tail -11");
    hop.log("Top memory consumers:\n" + top.stdout);
} else {
    const free = await hop.exec(host, "free -h");
    hop.log("Memory:\n" + free.stdout);
    const topMem = await hop.exec(host, "ps aux --sort=-%mem | head -11");
    hop.log("Top memory consumers:\n" + topMem.stdout);

    // Check for OOM kills
    const oom = await hop.exec(host, "dmesg | grep -i 'oom\\|out of memory' | tail -10");
    if (oom.stdout.trim()) {
        hop.log("OOM events found:\n" + oom.stdout);
    } else {
        hop.log("No OOM events detected");
    }
}"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("Linux 'free' shows buffers/cache as used — look at 'available' column."),
                s("macOS vm_stat reports in pages (usually 4096 bytes)."),
            ],
            related: tags(&["monitor/memory-usage", "troubleshoot/process-debugging"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("troubleshoot/service-crash"),
            category: s("troubleshoot"),
            title: s("Service Crash Debugging"),
            description: s("Debug service crashes. Uses journalctl/systemctl on Linux, log show/launchctl on macOS."),
            tags: tags(&["service", "crash", "restart", "log", "debug"]),
            prerequisites: vec![s("services/manage")],
            examples: vec![
                ex(
                    "Debug a crashed service (OS-adaptive)",
                    r#"const host = "app-01";
const service = "myapp";
const os = (await hop.exec(host, "uname -s")).stdout.trim();

if (os === "Darwin") {
    const status = await hop.exec(host, `launchctl print system/com.${service} 2>&1 | head -10`);
    hop.log("Service info:\n" + status.stdout);
    const logs = await hop.exec(host, `log show --predicate 'process == "${service}"' --last 1h --style compact 2>/dev/null | tail -20`);
    hop.log("Recent logs:\n" + logs.stdout);
} else {
    const status = await hop.exec(host, `systemctl status ${service} 2>&1`);
    hop.log("Service status:\n" + status.stdout);
    const logs = await hop.exec(host, `journalctl -u ${service} --no-pager -n 50 --since '1 hour ago'`);
    hop.log("Recent logs:\n" + logs.stdout);
    const restarts = await hop.exec(host, `systemctl show ${service} -p NRestarts`);
    hop.log(restarts.stdout.trim());
}"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("Services with Restart=always may hide crashes — check restart counters."),
                s("On macOS, check /var/log/system.log and Console.app for additional crash info."),
            ],
            related: tags(&["services/manage", "troubleshoot/process-debugging"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("troubleshoot/connectivity-test"),
            category: s("troubleshoot"),
            title: s("Connectivity Testing"),
            description: s("Test network connectivity between fleet hosts. nc and curl are available on both platforms."),
            tags: tags(&["connectivity", "port", "reachable", "test", "nc", "curl"]),
            prerequisites: vec![s("fleet/fleet-exec")],
            examples: vec![
                ex(
                    "Test port connectivity between hosts",
                    r#"const hosts = await hop.fleet.list();
const onlineHosts = hosts.filter(h => h.online);
const testPort = 443;

hop.log("Connectivity matrix (port " + testPort + "):");
for (const src of onlineHosts) {
    const results = [];
    for (const dst of onlineHosts) {
        if (src.name === dst.name) { results.push("self"); continue; }
        const r = await hop.exec(src.name, `nc -z -w3 ${dst.name} ${testPort} 2>&1 && echo OK || echo FAIL`);
        results.push(r.stdout.trim());
    }
    hop.log(`  ${src.name} -> ${results.join(', ')}`);
}"#,
                    Some("Connectivity matrix (port 443):\n  web-1 -> self, OK, OK\n  db-1 -> OK, self, OK"),
                ),
            ],
            pitfalls: vec![
                s("nc -z may not be available everywhere — use bash /dev/tcp as fallback."),
                s("Firewall rules may be directional — test both directions."),
            ],
            related: tags(&["troubleshoot/network-diagnostics", "security/open-ports"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("troubleshoot/dns-resolution"),
            category: s("troubleshoot"),
            title: s("DNS Resolution"),
            description: s("Debug DNS resolution issues. Uses /etc/resolv.conf on Linux and scutil --dns on macOS."),
            tags: tags(&["dns", "resolve", "dig", "nameserver"]),
            prerequisites: vec![],
            examples: vec![
                ex(
                    "Check DNS across fleet (OS-adaptive)",
                    r#"const domain = "api.example.com";
const results = await hop.fleet.exec("*", `
    os=$(uname -s)
    resolved=$(dig +short ${domain} 2>/dev/null || nslookup ${domain} 2>/dev/null | grep Address | tail -1)
    if [ "$os" = "Darwin" ]; then
        nameservers=$(scutil --dns 2>/dev/null | grep "nameserver" | head -3 | awk '{print $3}' | tr '\n' ', ')
    else
        nameservers=$(grep nameserver /etc/resolv.conf | awk '{print $2}' | tr '\n' ', ')
    fi
    echo "resolved=$resolved nameservers=$nameservers"
`);
for (const r of results) {
    hop.log(`${r.host}: ${r.stdout.trim()}`);
}"#,
                    Some("web-1: resolved=10.0.1.5 nameservers=10.0.0.2,\nmac-dev: resolved=10.0.1.5 nameservers=192.168.1.1,8.8.8.8,"),
                ),
            ],
            pitfalls: vec![
                s("DNS caching (nscd, systemd-resolved, mDNSResponder) can mask stale records."),
                s("macOS does not use /etc/resolv.conf — DNS is configured via scutil or System Preferences."),
            ],
            related: tags(&["troubleshoot/network-diagnostics", "troubleshoot/connectivity-test"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("troubleshoot/performance-profiling"),
            category: s("troubleshoot"),
            title: s("Performance Profiling"),
            description: s("Profile system performance. Uses perf/vmstat on Linux, instruments/sample on macOS."),
            tags: tags(&["performance", "profile", "perf", "vmstat", "bottleneck"]),
            prerequisites: vec![s("monitor/cpu-usage"), s("monitor/load-average")],
            examples: vec![
                ex(
                    "Performance snapshot (OS-adaptive)",
                    r#"const host = "app-server-01";
const os = (await hop.exec(host, "uname -s")).stdout.trim();

if (os === "Darwin") {
    const vm = await hop.exec(host, "vm_stat");
    hop.log("VM stats:\n" + vm.stdout);
    const top = await hop.exec(host, "top -l 2 -n 0 -s 1 | grep -E 'CPU|PhysMem|Processes'");
    hop.log("System snapshot:\n" + top.stdout);
} else {
    const vmstat = await hop.exec(host, "vmstat 1 5");
    hop.log("vmstat (1s intervals):\n" + vmstat.stdout);
    const perf = await hop.exec(host, "perf stat -a sleep 3 2>&1 || echo 'perf not available'");
    hop.log("Perf counters:\n" + perf.stdout);
}

hop.log("Profile complete for " + host);"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("perf requires kernel support; instruments requires Xcode."),
                s("Profiling tools add overhead — keep sampling intervals reasonable."),
            ],
            related: tags(&["troubleshoot/disk-io", "troubleshoot/memory-investigation"]),
            sub_skills: vec![],
        },
    ]
}
