use crate::skills::{Skill, SkillExample};
use super::super::data::{s, tags, ex};

pub fn skills() -> Vec<Skill> {
    vec![
        Skill {
            id: s("security/package-vulnerabilities"),
            category: s("security"),
            title: s("Package Vulnerability Scan"),
            description: s("Scan for known package vulnerabilities. Uses apt on Debian, dnf on RHEL, brew on macOS."),
            tags: tags(&["cve", "vulnerability", "scan", "security", "patch"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Check for security updates (OS-adaptive)",
                    r#"const results = await hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        brew outdated 2>/dev/null | head -10 || echo "brew not available"
    elif command -v apt >/dev/null 2>&1; then
        apt list --upgradable 2>/dev/null | grep -i security | head -10 || echo "No security updates"
    elif command -v dnf >/dev/null 2>&1; then
        dnf updateinfo list security 2>/dev/null | head -10 || echo "No security updates"
    else
        echo "Unknown package manager"
    fi
`);
for (const r of results) {
    hop.log(`=== ${r.host} ===`);
    hop.log(r.stdout.trim());
}"#,
                    Some("=== web-1 ===\nlibssl3/jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.12]\n=== mac-dev ===\nopenssl 3.2.1 -> 3.2.2"),
                ),
            ],
            pitfalls: vec![
                s("Package-based scanning does not cover manually installed or compiled software."),
                s("Run package index updates first for accurate results."),
            ],
            related: tags(&["security/package-audit", "install/package"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("security/package-audit"),
            category: s("security"),
            title: s("Package Audit"),
            description: s("Audit installed packages across fleet hosts. Uses dpkg on Debian, rpm on RHEL, brew on macOS."),
            tags: tags(&["package", "audit", "installed", "integrity", "version"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Audit installed packages (OS-adaptive)",
                    r#"const results = await hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        count=$(brew list 2>/dev/null | wc -l | tr -d ' ')
        echo "$count packages (brew)"
        brew doctor 2>&1 | head -3
    elif command -v dpkg >/dev/null 2>&1; then
        count=$(dpkg -l | grep -c "^ii")
        echo "$count packages (dpkg)"
        dpkg --audit 2>&1 | head -3
    elif command -v rpm >/dev/null 2>&1; then
        count=$(rpm -qa | wc -l)
        echo "$count packages (rpm)"
    fi
`);
for (const r of results) {
    hop.log(`${r.host}: ${r.stdout.trim()}`);
}"#,
                    Some("web-1: 342 packages (dpkg)\nweb-2: 387 packages (dpkg)\nmac-dev: 85 packages (brew)\nYour system is ready to brew."),
                ),
            ],
            pitfalls: vec![
                s("Package count differences between similar hosts may indicate config drift."),
            ],
            related: tags(&["security/package-vulnerabilities", "install/list-installed"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("security/open-ports"),
            category: s("security"),
            title: s("Open Port Auditing"),
            description: s("Audit listening ports for unexpected services. Uses ss on Linux and lsof on macOS."),
            tags: tags(&["ports", "listening", "network", "firewall", "audit"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Audit open ports across fleet (OS-adaptive)",
                    r#"const results = await hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | awk 'NR>1 {print $1, $9}' | sort -u
    else
        ss -tlnp | awk 'NR>1 {print $4, $6}'
    fi
`);
for (const r of results) {
    hop.log(`=== ${r.host} ===`);
    const lines = r.stdout.trim().split("\n");
    for (const line of lines) {
        if (!line.startsWith("127.") && !line.includes("[::1]")) {
            hop.log(`  EXTERNAL: ${line}`);
        } else {
            hop.log(`  local:    ${line}`);
        }
    }
}"#,
                    Some("=== web-1 ===\n  EXTERNAL: 0.0.0.0:80 users:((\"nginx\",pid=1234))\n  local:    127.0.0.1:3000 users:((\"node\",pid=5678))"),
                ),
            ],
            pitfalls: vec![
                s("ss/lsof may require root for process names."),
                s("UDP listeners are not shown with TCP flags — add -u for UDP."),
            ],
            related: tags(&["security/firewall-audit", "monitor/open-ports"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("security/file-permissions"),
            category: s("security"),
            title: s("File Permission Audit"),
            description: s("Audit file permissions on sensitive files. stat format strings differ between Linux and macOS."),
            tags: tags(&["permissions", "chmod", "ownership", "audit", "security"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Audit sensitive file permissions (OS-adaptive)",
                    r#"const host = "target-server";
const checks = [
    { path: "/etc/ssh/sshd_config", expected: "644" },
    { path: "/etc/passwd", expected: "644" },
];
const r = await hop.exec(host, `
    os=$(uname -s)
    for path in ${checks.map(c => c.path).join(" ")}; do
        if [ -f "$path" ]; then
            if [ "$os" = "Darwin" ]; then
                stat -f '%Lp %Su:%Sg %N' "$path"
            else
                stat -c '%a %U:%G %n' "$path"
            fi
        else
            echo "MISSING $path"
        fi
    done
`);
for (const line of r.stdout.trim().split("\n")) {
    if (line.startsWith("MISSING")) {
        hop.log(`  WARN: ${line}`);
    } else {
        const perms = line.split(" ")[0];
        hop.log(`  ${line}`);
    }
}"#,
                    Some("  644 root:root /etc/ssh/sshd_config\n  644 root:root /etc/passwd"),
                ),
            ],
            pitfalls: vec![
                s("stat format differs: Linux uses -c, macOS uses -f."),
                s("Some applications modify permissions on restart — audit after service starts."),
            ],
            related: tags(&["security/suid-files", "security/ssh-key-audit"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("security/ssh-key-audit"),
            category: s("security"),
            title: s("SSH Key Audit"),
            description: s("Audit SSH authorized keys and host keys. Works on both Linux and macOS."),
            tags: tags(&["ssh", "keys", "authorized", "audit", "security"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Audit SSH authorized keys across fleet",
                    r#"const results = await hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        home_base="/Users"
    else
        home_base="/home"
    fi
    for user_dir in $home_base/*; do
        u=$(basename "$user_dir")
        f="$user_dir/.ssh/authorized_keys"
        if [ -f "$f" ]; then
            count=$(wc -l < "$f" | tr -d ' ')
            echo "$u:$count"
        fi
    done
`);
for (const r of results) {
    hop.log(`=== ${r.host} ===`);
    if (r.stdout.trim()) {
        for (const line of r.stdout.trim().split("\n")) {
            const [user, count] = line.split(":");
            hop.log(`  ${user}: ${count} authorized key(s)`);
        }
    } else {
        hop.log("  No authorized_keys files found");
    }
}"#,
                    Some("=== web-1 ===\n  deploy: 3 authorized key(s)\n  admin: 1 authorized key(s)"),
                ),
            ],
            pitfalls: vec![
                s("Root's authorized_keys is at /root/.ssh/ (Linux) or /var/root/.ssh/ (macOS)."),
                s("Some systems use AuthorizedKeysFile in sshd_config for non-default locations."),
            ],
            related: tags(&["security/user-audit", "security/file-permissions"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("security/user-audit"),
            category: s("security"),
            title: s("User Account Audit"),
            description: s("Audit user accounts. Uses /etc/passwd on Linux and dscl on macOS."),
            tags: tags(&["users", "accounts", "audit", "passwd", "security"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Audit user accounts (OS-adaptive)",
                    r#"const results = await hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        dscl . list /Users UniqueID | awk '$2 >= 500 && $2 < 65534 {print $1}'
    else
        awk -F: '$3 >= 1000 && $3 < 65534 {print $1":"$7}' /etc/passwd
    fi
`);
for (const r of results) {
    hop.log(`=== ${r.host} ===`);
    for (const line of r.stdout.trim().split("\n")) {
        if (!line) continue;
        hop.log(`  ${line}`);
    }
}"#,
                    Some("=== web-1 ===\n  deploy:/bin/bash\n  appuser:/usr/sbin/nologin\n=== mac-dev ===\n  jason\n  admin"),
                ),
            ],
            pitfalls: vec![
                s("UID ranges differ: Linux 1000+, macOS 500+."),
                s("LDAP/AD users may not appear in local account stores."),
            ],
            related: tags(&["security/ssh-key-audit", "security/sudo-audit"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("security/certificate-expiry"),
            category: s("security"),
            title: s("TLS Certificate Expiry"),
            description: s("Check TLS certificate expiry dates. openssl is available on both Linux and macOS."),
            tags: tags(&["tls", "ssl", "certificate", "expiry", "security"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Check certificate expiry on web hosts",
                    r#"const results = await hop.fleet.exec("tier:web",
    "echo | openssl s_client -connect localhost:443 -servername localhost 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null || echo 'No cert found'"
);
for (const r of results) {
    const line = r.stdout.trim();
    if (line.startsWith("notAfter=")) {
        const expiry = new Date(line.replace("notAfter=", ""));
        const daysLeft = Math.floor((expiry - Date.now()) / 86400000);
        const level = daysLeft < 7 ? "CRITICAL" : daysLeft < 30 ? "WARNING" : "OK";
        hop.log(`[${level}] ${r.host}: expires in ${daysLeft} days`);
    } else {
        hop.log(`[INFO] ${r.host}: ${line}`);
    }
}"#,
                    Some("[OK] web-1: expires in 89 days\n[WARNING] web-2: expires in 14 days\n[CRITICAL] web-3: expires in 3 days"),
                ),
            ],
            pitfalls: vec![
                s("Self-signed certificates will show expiry but may cause TLS errors in clients."),
                s("Check nginx/apache configs for cert paths if the default check doesn't work."),
            ],
            related: tags(&["monitor/service-status", "security/open-ports"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("security/firewall-audit"),
            category: s("security"),
            title: s("Firewall Rule Audit"),
            description: s("Audit firewall rules. Uses ufw/iptables on Linux and pfctl on macOS."),
            tags: tags(&["firewall", "iptables", "ufw", "pf", "pfctl", "audit"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Audit firewall rules (OS-adaptive)",
                    r#"const results = await hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        pfctl -sr 2>/dev/null || echo "pf not active"
    else
        ufw status 2>/dev/null || iptables -L -n --line-numbers 2>/dev/null | head -20 || echo "No firewall detected"
    fi
`);
for (const r of results) {
    hop.log(`=== ${r.host} ===`);
    const output = r.stdout.trim();
    if (output.includes("inactive") || output.includes("No firewall") || output.includes("not active")) {
        hop.log("  WARNING: No active firewall!");
    } else {
        hop.log(output.split("\n").map(l => `  ${l}`).join("\n"));
    }
}"#,
                    Some("=== web-1 ===\n  Status: active\n  To                         Action      From\n  80/tcp                     ALLOW       Anywhere\n=== mac-dev ===\n  WARNING: No active firewall!"),
                ),
            ],
            pitfalls: vec![
                s("Cloud security groups provide firewall-like protection not visible on the host."),
                s("iptables requires root; pfctl requires admin."),
            ],
            related: tags(&["security/open-ports", "security/file-permissions"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("security/sudo-audit"),
            category: s("security"),
            title: s("Sudo Configuration Audit"),
            description: s("Audit sudo configuration. sudoers format is the same on both Linux and macOS."),
            tags: tags(&["sudo", "sudoers", "privilege", "escalation", "audit"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Audit sudo configuration",
                    r#"const results = await hop.fleet.exec("*",
    "cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^#' | grep -v '^$' | grep -v '^Defaults'"
);
for (const r of results) {
    hop.log(`=== ${r.host} ===`);
    for (const line of r.stdout.trim().split("\n")) {
        if (!line.trim()) continue;
        const warn = line.includes("NOPASSWD") ? " [NOPASSWD!]" : "";
        const allCmds = line.includes("ALL=(ALL)") ? " [ALL COMMANDS!]" : "";
        hop.log(`  ${line.trim()}${warn}${allCmds}`);
    }
}"#,
                    Some("=== web-1 ===\n  root ALL=(ALL:ALL) ALL [ALL COMMANDS!]\n  deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp [NOPASSWD!]"),
                ),
            ],
            pitfalls: vec![
                s("Editing sudoers directly can lock you out — always use visudo."),
                s("Files in /etc/sudoers.d/ are included by default on most distros and macOS."),
            ],
            related: tags(&["security/user-audit", "admin/audit-log"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("security/suid-files"),
            category: s("security"),
            title: s("SUID/SGID Binary Audit"),
            description: s("Find SUID and SGID binaries. find -perm works on both Linux and macOS."),
            tags: tags(&["suid", "sgid", "binary", "privilege", "audit"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Find SUID binaries across fleet",
                    r#"const results = await hop.fleet.exec("*",
    "find / -perm -4000 -type f 2>/dev/null | sort"
);
const knownSafe = ["/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/chsh",
    "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/gpasswd",
    "/usr/bin/su", "/usr/lib/openssh/ssh-keysign"];

for (const r of results) {
    const binaries = r.stdout.trim().split("\n").filter(l => l);
    const unknown = binaries.filter(b => !knownSafe.includes(b));
    hop.log(`${r.host}: ${binaries.length} SUID binaries (${unknown.length} non-standard)`);
    for (const b of unknown) {
        hop.log(`  REVIEW: ${b}`);
    }
}"#,
                    Some("web-1: 8 SUID binaries (1 non-standard)\n  REVIEW: /usr/local/bin/custom-tool\ndb-1: 7 SUID binaries (0 non-standard)"),
                ),
            ],
            pitfalls: vec![
                s("The find command can be slow on large filesystems — exclude /proc, /sys."),
                s("Some legitimate apps require SUID — verify before removing."),
            ],
            related: tags(&["security/file-permissions", "security/sudo-audit"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("security/failed-logins"),
            category: s("security"),
            title: s("Failed Login Monitoring"),
            description: s("Check failed login attempts. Uses journalctl on Linux and log show on macOS."),
            tags: tags(&["login", "failed", "brute-force", "auth", "security"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Check failed logins across fleet (OS-adaptive)",
                    r#"const results = await hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        log show --predicate 'process == "sshd" && eventMessage contains "Failed"' --last 24h 2>/dev/null | grep -c "Failed" || echo 0
    else
        journalctl _SYSTEMD_UNIT=sshd.service --since '24 hours ago' --no-pager 2>/dev/null | grep -c 'Failed password' || echo 0
    fi
`);
for (const r of results) {
    const count = parseInt(r.stdout.trim());
    const level = count > 100 ? "ALERT" : count > 10 ? "WARN" : "OK";
    hop.log(`[${level}] ${r.host}: ${count} failed SSH logins in 24h`);
}"#,
                    Some("[OK] web-1: 3 failed SSH logins in 24h\n[ALERT] web-2: 247 failed SSH logins in 24h\n[OK] db-1: 0 failed SSH logins in 24h"),
                ),
            ],
            pitfalls: vec![
                s("Log retention varies — old entries may be rotated out."),
                s("Some brute-force attacks use valid usernames from data breaches."),
            ],
            related: tags(&["security/ssh-key-audit", "security/firewall-audit"]),
            sub_skills: vec![],
        },
    ]
}
