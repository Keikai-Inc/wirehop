use crate::skills::{Skill, SkillExample};
use super::super::data::{s, tags, ex};

pub fn skills() -> Vec<Skill> {
    vec![
        Skill {
            id: s("recipes/investigate-unknown-host"),
            category: s("recipes"),
            title: s("Investigate Unknown Host"),
            description: s("Full system investigation workflow for a host you know nothing about. Discovers OS, capabilities, services, and health in one go."),
            tags: tags(&["investigate", "unknown", "discover", "fingerprint", "new"]),
            prerequisites: vec![s("discover/system-fingerprint")],
            examples: vec![
                ex(
                    "Full investigation of an unknown host",
                    r#"const host = "mystery-box";
hop.log(`=== Investigating ${host} ===\n`);

// Step 1: OS fingerprint
const fp = await hop.exec(host, `
    echo "os=$(uname -s) $(uname -r) $(uname -m)"
    [ -f /etc/os-release ] && . /etc/os-release && echo "distro=$PRETTY_NAME" || \
        (command -v sw_vers >/dev/null && echo "distro=macOS $(sw_vers -productVersion)" || echo "distro=unknown")
    for pm in apt-get dnf yum brew apk; do command -v $pm >/dev/null 2>&1 && echo "pkg=$pm" && break; done
    command -v systemctl >/dev/null 2>&1 && echo "init=systemd" || \
        (command -v launchctl >/dev/null 2>&1 && echo "init=launchd" || echo "init=unknown")
`);
hop.log("1. System:\n" + fp.stdout);

// Step 2: Resources
const res = await hop.exec(host, `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        cores=$(sysctl -n hw.ncpu)
        mem=$(($(sysctl -n hw.memsize) / 1048576))
    else
        cores=$(nproc)
        mem=$(free -m 2>/dev/null | awk '/Mem/{print $2}' || echo unknown)
    fi
    echo "cpu=$cores cores"
    echo "memory=${mem}MB"
    echo "disk=$(df -h / | awk 'NR==2{print $5, "of", $2}')"
    echo "uptime=$(uptime | sed 's/.*up //' | sed 's/,.*//')"
`);
hop.log("2. Resources:\n" + res.stdout);

// Step 3: Running services
const svc = await hop.exec(host, `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        brew services list 2>/dev/null | grep started || echo "(no brew services)"
    else
        systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -15
    fi
`);
hop.log("3. Running services:\n" + svc.stdout);

// Step 4: Listening ports
const ports = await hop.exec(host, `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | awk 'NR>1 {print $1, $9}' | sort -u
    else
        ss -tlnp 2>/dev/null | awk 'NR>1 {print $4, $6}'
    fi
`);
hop.log("4. Listening ports:\n" + ports.stdout);

hop.log("=== Investigation complete ===");"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("Run this before any platform-specific commands to avoid errors."),
                s("The investigation is read-only — it does not modify the host."),
            ],
            related: tags(&["discover/system-fingerprint", "discover/detect-capabilities"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("recipes/rolling-update"),
            category: s("recipes"),
            title: s("Rolling Update"),
            description: s("Perform rolling updates across fleet hosts one at a time, with health checks. Detects package manager per host."),
            tags: tags(&["rolling", "update", "zero-downtime", "deploy", "upgrade"]),
            prerequisites: vec![s("install/package"), s("services/manage"), s("fleet/fleet-exec")],
            examples: vec![
                ex(
                    "Rolling update with OS detection",
                    r#"const hosts = await hop.fleet.list("tier:web");
const onlineHosts = hosts.filter(h => h.online);

for (let i = 0; i < onlineHosts.length; i++) {
    const h = onlineHosts[i];
    hop.log(`[${i + 1}/${onlineHosts.length}] Updating ${h.name}...`);

    // Drain
    await hop.exec(h.name, "touch /tmp/maintenance.flag");
    await hop.sleep(5000);

    // Detect package manager and update
    const pm = (await hop.exec(h.name, `
        command -v apt-get >/dev/null 2>&1 && echo apt && exit 0
        command -v dnf >/dev/null 2>&1 && echo dnf && exit 0
        command -v brew >/dev/null 2>&1 && echo brew && exit 0
        echo unknown
    `)).stdout.trim();

    if (pm === "apt") {
        await hop.exec(h.name, "apt-get update -qq && apt-get install -y myapp");
    } else if (pm === "dnf") {
        await hop.exec(h.name, "dnf update -y myapp");
    } else if (pm === "brew") {
        await hop.exec(h.name, "brew upgrade myapp");
    }

    // Restart service (OS-adaptive)
    const os = (await hop.exec(h.name, "uname -s")).stdout.trim();
    if (os === "Darwin") {
        await hop.exec(h.name, "brew services restart myapp 2>/dev/null || launchctl kickstart -k system/com.myapp");
    } else {
        await hop.exec(h.name, "systemctl restart myapp");
    }

    // Health check
    await hop.sleep(3000);
    const check = await hop.exec(h.name, "curl -sf http://localhost:8080/health || echo UNHEALTHY");
    if (check.stdout.trim() === "UNHEALTHY") {
        hop.log(`ABORT: ${h.name} failed health check!`);
        return { error: `Rolling update aborted at ${h.name}` };
    }

    await hop.exec(h.name, "rm -f /tmp/maintenance.flag");
    hop.log(`${h.name}: updated and healthy`);
}"#,
                    Some("[1/3] Updating web-1...\nweb-1: updated and healthy\n[2/3] Updating web-2...\nweb-2: updated and healthy"),
                ),
            ],
            pitfalls: vec![
                s("Always include health checks between hosts."),
                s("Have a rollback plan ready if the update fails mid-fleet."),
            ],
            related: tags(&["install/package", "services/manage"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("recipes/fleet-health-report"),
            category: s("recipes"),
            title: s("Fleet Health Report"),
            description: s("Generate a comprehensive fleet health report with OS-adaptive probes for CPU, memory, disk, and load."),
            tags: tags(&["health", "report", "fleet", "overview", "dashboard"]),
            prerequisites: vec![s("monitor/cpu-usage"), s("monitor/memory-usage"), s("monitor/disk-usage")],
            examples: vec![
                ex(
                    "Generate fleet health report (OS-adaptive)",
                    r#"const hosts = await hop.fleet.list();
const report = [];

for (const h of hosts.filter(m => m.online)) {
    const r = await hop.exec(h.name, `
        os=$(uname -s)
        if [ "$os" = "Darwin" ]; then
            cores=$(sysctl -n hw.ncpu)
            load=$(sysctl -n vm.loadavg | awk '{print $2, $3, $4}')
            total_mem=$(($(sysctl -n hw.memsize) / 1048576))
            pages_free=$(vm_stat | awk '/Pages free/ {gsub(/\./,"",$3); print $3}')
            mem_free=$(( pages_free * 4096 / 1048576 ))
            mem_pct=$(( (total_mem - mem_free) * 100 / total_mem ))
        else
            cores=$(nproc)
            load=$(cat /proc/loadavg | awk '{print $1, $2, $3}')
            mem_pct=$(free | awk '/Mem/{printf "%.0f", $3/$2*100}')
        fi
        disk_pct=$(df -h / | awk 'NR==2{print $5}' | tr -d '%')
        echo "$cores $load $mem_pct $disk_pct"
    `);
    const parts = r.stdout.trim().split(/\s+/);
    report.push({
        host: h.name,
        cores: parts[0],
        load: parts.slice(1, 4).join("/"),
        memPct: parts[4] + "%",
        diskPct: parts[5] + "%",
    });
}

const critical = report.filter(r => parseInt(r.memPct) > 90 || parseInt(r.diskPct) > 90);
hop.log(`Fleet Health: ${report.length} hosts, ${critical.length} critical`);
for (const r of report) {
    const flag = critical.includes(r) ? "!!" : "OK";
    hop.log(`[${flag}] ${r.host}: MEM=${r.memPct} DISK=${r.diskPct} LOAD=${r.load}`);
}
return report;"#,
                    Some("Fleet Health: 5 hosts, 1 critical\n[OK] web-1: MEM=45% DISK=34% LOAD=0.5/0.3/0.2\n[!!] db-1: MEM=92% DISK=78% LOAD=4.2/3.8/3.5"),
                ),
            ],
            pitfalls: vec![
                s("Large fleets will be slow with sequential checks — consider batching."),
                s("Offline hosts are skipped — check for missing hosts in the report."),
            ],
            related: tags(&["monitor/system-overview", "monitor/cpu-usage", "monitor/memory-usage"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("recipes/security-baseline"),
            category: s("recipes"),
            title: s("Security Baseline Check"),
            description: s("Comprehensive security baseline with OS-adaptive checks for SSH, firewall, users, packages, and permissions."),
            tags: tags(&["security", "baseline", "audit", "compliance", "hardening"]),
            prerequisites: vec![s("security/open-ports"), s("security/user-audit")],
            examples: vec![
                ex(
                    "Run security baseline (OS-adaptive)",
                    r#"const hosts = await hop.fleet.list();
for (const h of hosts.filter(m => m.online)) {
    hop.log(`\n=== Security Baseline: ${h.name} ===`);
    const os = (await hop.exec(h.name, "uname -s")).stdout.trim();

    // SSH hardening
    const ssh = await hop.exec(h.name, "sshd -T 2>/dev/null | grep -E 'passwordauthentication|permitrootlogin' || echo 'sshd -T not available'");
    hop.log("SSH config: " + ssh.stdout.trim());

    // Firewall status
    if (os === "Darwin") {
        const fw = await hop.exec(h.name, "pfctl -sr 2>/dev/null | head -5 || echo 'pf not active'");
        hop.log("Firewall (pf): " + fw.stdout.trim());
    } else {
        const fw = await hop.exec(h.name, "ufw status 2>/dev/null || iptables -L -n 2>/dev/null | head -5 || echo 'No firewall'");
        hop.log("Firewall: " + fw.stdout.trim());
    }

    // Users with login shells
    if (os === "Darwin") {
        const users = await hop.exec(h.name, "dscl . list /Users UniqueID | awk '$2 >= 500 {print $1}' | tr '\\n' ', '");
        hop.log("Users (UID>=500): " + users.stdout.trim());
    } else {
        const users = await hop.exec(h.name, "grep -v 'nologin\\|false' /etc/passwd | cut -d: -f1 | tr '\\n' ', '");
        hop.log("Users with shells: " + users.stdout.trim());
    }

    // SUID files
    const suid = await hop.exec(h.name, "find / -perm -4000 -type f 2>/dev/null | wc -l");
    hop.log("SUID files: " + suid.stdout.trim());
}"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("Security baselines vary by compliance framework (CIS, NIST, etc.)."),
                s("Some checks require root access for accurate results."),
            ],
            related: tags(&["security/open-ports", "security/user-audit", "security/firewall-audit"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("recipes/incident-response"),
            category: s("recipes"),
            title: s("Incident Response"),
            description: s("Incident response runbook with OS-adaptive forensic data collection."),
            tags: tags(&["incident", "response", "forensic", "isolate", "investigate"]),
            prerequisites: vec![s("troubleshoot/process-debugging"), s("troubleshoot/network-diagnostics")],
            examples: vec![
                ex(
                    "Incident response data collection (OS-adaptive)",
                    r#"const host = "compromised-host";
const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
const os = (await hop.exec(host, "uname -s")).stdout.trim();

hop.log(`=== Incident Response: ${host} @ ${timestamp} ===`);

// 1. Capture running state
hop.log("Step 1: Capturing system state...");
const procs = await hop.exec(host, "ps auxwwf 2>/dev/null || ps aux");
const who = await hop.exec(host, "w");
hop.log("Active sessions:\n" + who.stdout);

// 2. Network connections
if (os === "Darwin") {
    const net = await hop.exec(host, "lsof -i -P -n | head -30");
    hop.log("Network connections:\n" + net.stdout);
} else {
    const net = await hop.exec(host, "ss -tlnpa");
    hop.log("Network connections:\n" + net.stdout);
}

// 3. Recent logins
const logins = await hop.exec(host, "last -25");
hop.log("Recent logins:\n" + logins.stdout);

// 4. Suspicious activity
const tmpFiles = await hop.exec(host, "find /tmp /var/tmp -mtime -1 -type f -ls 2>/dev/null");
hop.log("Recent /tmp files:\n" + tmpFiles.stdout);

// 5. Preserve logs
await hop.exec(host, `tar czf /root/incident-${timestamp}.tar.gz /var/log/ 2>/dev/null`);
hop.log("Incident data collected. Review before taking isolation actions.");"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("NEVER modify the system before collecting evidence."),
                s("Document every action taken with timestamps."),
                s("Isolate by network rules first, not by shutting down."),
            ],
            related: tags(&["security/failed-logins", "troubleshoot/process-debugging"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("recipes/new-server-setup"),
            category: s("recipes"),
            title: s("New Server Setup"),
            description: s("Complete new server setup recipe with package manager detection and OS-adaptive hardening."),
            tags: tags(&["new", "server", "setup", "provision", "onboard"]),
            prerequisites: vec![s("discover/system-fingerprint"), s("install/package")],
            examples: vec![
                ex(
                    "Set up a new server (OS-adaptive)",
                    r#"const host = "new-server-01";

// Phase 1: Detect OS and package manager
hop.log("Phase 1: System detection");
const detect = await hop.exec(host, `
    os=$(uname -s); echo "os=$os"
    command -v apt-get >/dev/null 2>&1 && echo "pkg=apt" && exit 0
    command -v dnf >/dev/null 2>&1 && echo "pkg=dnf" && exit 0
    command -v brew >/dev/null 2>&1 && echo "pkg=brew" && exit 0
    echo "pkg=unknown"
`);
const info = {};
for (const line of detect.stdout.trim().split("\n")) {
    const [k, v] = line.split("=");
    info[k] = v;
}
hop.log(`Detected: ${info.os}, pkg=${info.pkg}`);

// Phase 2: Install base packages
hop.log("Phase 2: Base packages");
const basePkgs = "curl wget vim htop jq";
if (info.pkg === "apt") {
    await hop.exec(host, `apt-get update -qq && apt-get install -y ${basePkgs} fail2ban ufw`);
} else if (info.pkg === "dnf") {
    await hop.exec(host, `dnf install -y ${basePkgs} fail2ban`);
} else if (info.pkg === "brew") {
    await hop.exec(host, `brew install ${basePkgs}`);
}

// Phase 3: Security hardening
hop.log("Phase 3: Security hardening");
await hop.exec(host, "sed -i.bak 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config 2>/dev/null || true");
if (info.os !== "Darwin") {
    await hop.exec(host, "systemctl reload sshd 2>/dev/null || true");
    if (info.pkg === "apt") {
        await hop.exec(host, "ufw default deny incoming && ufw default allow outgoing && ufw allow 22 && ufw --force enable");
    }
}

// Phase 4: Verify
hop.log("Phase 4: Verification");
const status = await hop.admin.status(host);
hop.log(`Version: ${status.version}, Peers: ${status.peerCount}`);

return { host, status: "setup complete" };"#,
                    Some("Phase 1: System detection\nDetected: Linux, pkg=apt\nPhase 2: Base packages\nPhase 3: Security hardening\nPhase 4: Verification"),
                ),
            ],
            pitfalls: vec![
                s("Always test the recipe on a staging server first."),
                s("Keep the recipe idempotent — safe to re-run."),
            ],
            related: tags(&["discover/system-fingerprint", "install/package", "recipes/security-baseline"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("recipes/user-onboarding"),
            category: s("recipes"),
            title: s("User Onboarding"),
            description: s("Onboard a new team member: create accounts, assign roles, distribute SSH keys, and set up access."),
            tags: tags(&["user", "onboard", "account", "invite", "team"]),
            prerequisites: vec![s("admin/creating-users"), s("roles/creating-roles")],
            examples: vec![
                ex(
                    "Onboard a new developer",
                    r#"const username = "alice";
const role = "developer";

const hosts = await hop.fleet.list("tier:dev");
hop.log(`Onboarding ${username} to ${hosts.length} dev hosts`);

for (const h of hosts.filter(m => m.online)) {
    const result = await hop.admin.createUser(h.name, username, {
        sudo: false,
        groups: ["developers", "docker"],
        shell: "/bin/bash",
    });
    hop.log(`${h.name}: user created, invite=${result}`);
}

const invite = await hop.admin.invite(hosts[0].name, { username });
hop.log(`\nInvite for ${username}: ${invite}`);
hop.log(`Share this invite securely with the new team member.`);"#,
                    Some("Onboarding alice to 3 dev hosts\ndev-1: user created\ndev-2: user created"),
                ),
            ],
            pitfalls: vec![
                s("Always use individual accounts — never share credentials."),
                s("Distribute invites through a secure channel (not email)."),
            ],
            related: tags(&["admin/creating-users", "roles/creating-roles"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("recipes/log-aggregation"),
            category: s("recipes"),
            title: s("Log Aggregation"),
            description: s("Aggregate and search logs across fleet with OS-adaptive log commands."),
            tags: tags(&["log", "aggregate", "search", "collect", "centralize"]),
            prerequisites: vec![s("monitor/log-search"), s("fleet/fleet-exec")],
            examples: vec![
                ex(
                    "Search logs across fleet (OS-adaptive)",
                    r#"const since = "1 hour ago";

const results = await hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        log show --predicate 'messageType == error' --last 1h --style compact 2>/dev/null | tail -10
    else
        journalctl --since '${since}' --no-pager -p err 2>/dev/null | tail -10
    fi
`);

let totalErrors = 0;
for (const r of results) {
    const lines = r.stdout.trim().split('\n').filter(l => l);
    totalErrors += lines.length;
    if (lines.length > 0) {
        hop.log(`\n--- ${r.host} (${lines.length} errors) ---`);
        for (const line of lines.slice(-5)) {
            hop.log("  " + line);
        }
    }
}

hop.log(`\nTotal errors across fleet: ${totalErrors}`);"#,
                    Some("--- web-1 (3 errors) ---\n  Mar 04 10:15:23 web-1 nginx[1234]: ...\n\nTotal errors across fleet: 7"),
                ),
            ],
            pitfalls: vec![
                s("Large log volumes can be slow — always use time bounds and filters."),
                s("macOS log show can be very slow without predicates."),
            ],
            related: tags(&["monitor/log-search", "services/logs"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("recipes/capacity-planning"),
            category: s("recipes"),
            title: s("Capacity Planning"),
            description: s("Analyze fleet resource utilization for capacity planning with OS-adaptive probes."),
            tags: tags(&["capacity", "planning", "growth", "trend", "forecast"]),
            prerequisites: vec![s("monitor/cpu-usage"), s("monitor/memory-usage"), s("monitor/disk-usage")],
            examples: vec![
                ex(
                    "Capacity planning analysis (OS-adaptive)",
                    r#"const hosts = await hop.fleet.list();
const analysis = { cpu: [], memory: [], disk: [] };

for (const h of hosts.filter(m => m.online)) {
    const r = await hop.exec(h.name, `
        os=$(uname -s)
        if [ "$os" = "Darwin" ]; then
            total_mem=$(($(sysctl -n hw.memsize) / 1048576))
            pages_free=$(vm_stat | awk '/Pages free/ {gsub(/\./,"",$3); print $3}')
            mem_free=$((pages_free * 4096 / 1048576))
            mem_pct=$(( (total_mem - mem_free) * 100 / total_mem ))
        else
            mem_pct=$(free | awk '/Mem/{printf "%.0f", $3/$2*100}')
        fi
        disk_pct=$(df / | awk 'NR==2{print $5}' | tr -d '%')
        echo "$mem_pct $disk_pct"
    `);
    const [memPct, diskPct] = r.stdout.trim().split(/\s+/).map(Number);
    analysis.memory.push({ host: h.name, value: memPct });
    analysis.disk.push({ host: h.name, value: diskPct });
}

const avgMem = analysis.memory.reduce((a, b) => a + b.value, 0) / analysis.memory.length;
const avgDisk = analysis.disk.reduce((a, b) => a + b.value, 0) / analysis.disk.length;

hop.log(`Fleet Capacity (${hosts.length} hosts):`);
hop.log(`  Memory: avg=${avgMem.toFixed(1)}% max=${Math.max(...analysis.memory.map(m => m.value))}%`);
hop.log(`  Disk:   avg=${avgDisk.toFixed(1)}% max=${Math.max(...analysis.disk.map(d => d.value))}%`);

const memHigh = analysis.memory.filter(m => m.value > 80);
const diskHigh = analysis.disk.filter(d => d.value > 85);
if (memHigh.length) hop.log(`\nWARN: ${memHigh.length} hosts with Memory > 80%`);
if (diskHigh.length) hop.log(`CRIT: ${diskHigh.length} hosts with Disk > 85%`);

return analysis;"#,
                    Some("Fleet Capacity (5 hosts):\n  Memory: avg=56.8% max=89%\n  Disk:   avg=45.1% max=87%"),
                ),
            ],
            pitfalls: vec![
                s("Point-in-time snapshots don't capture peaks — sample multiple times."),
            ],
            related: tags(&["monitor/memory-usage", "monitor/disk-usage"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("recipes/disaster-recovery-check"),
            category: s("recipes"),
            title: s("Disaster Recovery Check"),
            description: s("Verify disaster recovery readiness: backup status, replication health, failover configuration."),
            tags: tags(&["disaster", "recovery", "dr", "backup", "failover"]),
            prerequisites: vec![s("files/backup-and-restore"), s("fleet/fleet-exec")],
            examples: vec![
                ex(
                    "DR readiness check",
                    r#"hop.log("=== Disaster Recovery Readiness Check ===\n");

// 1. Backup verification
hop.log("1. Backup Status:");
const dbHosts = await hop.fleet.list("role:database");
for (const h of dbHosts.filter(m => m.online)) {
    const backup = await hop.exec(h.name, "ls -lt /var/backups/*.sql.gz 2>/dev/null | head -3");
    const lastBackup = await hop.exec(h.name, `
        os=$(uname -s)
        if [ "$os" = "Darwin" ]; then
            stat -f %m /var/backups/*.sql.gz 2>/dev/null | sort -rn | head -1
        else
            stat -c %Y /var/backups/*.sql.gz 2>/dev/null | sort -rn | head -1
        fi
    `);
    const ageHours = lastBackup.stdout.trim() ? Math.round((Date.now()/1000 - parseInt(lastBackup.stdout)) / 3600) : -1;
    const status = ageHours >= 0 && ageHours < 24 ? "OK" : "STALE";
    hop.log(`  [${status}] ${h.name}: last backup ${ageHours >= 0 ? ageHours + 'h ago' : 'NONE FOUND'}`);
}

// 2. Service redundancy
hop.log("\n2. Service Redundancy:");
const webHosts = await hop.fleet.list("tier:web");
const onlineWeb = webHosts.filter(h => h.online);
hop.log(`  Web tier: ${onlineWeb.length}/${webHosts.length} online (need >= 2)`);

// 3. Disk space for recovery
hop.log("\n3. Disk Space:");
const allHosts = await hop.fleet.list();
for (const h of allHosts.filter(m => m.online)) {
    const disk = await hop.exec(h.name, "df -h / | awk 'NR==2{print $4}'");
    hop.log(`  ${h.name}: ${disk.stdout.trim()} available`);
}

hop.log("\n=== DR Check Complete ===");"#,
                    Some("=== Disaster Recovery Readiness Check ===\n\n1. Backup Status:\n  [OK] db-1: last backup 6h ago\n  [STALE] db-2: last backup 48h ago"),
                ),
            ],
            pitfalls: vec![
                s("Backup existence doesn't mean backup integrity — test restores regularly."),
                s("DR plans should be tested, not just documented."),
            ],
            related: tags(&["files/backup-and-restore", "recipes/fleet-health-report"]),
            sub_skills: vec![],
        },
    ]
}
