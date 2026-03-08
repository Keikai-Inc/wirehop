use crate::skills::Skill;
use super::super::data::{s, tags, ex};

pub fn skills() -> Vec<Skill> {
    vec![
        Skill {
            id: s("services/manage"),
            category: s("services"),
            title: s("Manage Services"),
            description: s("Start, stop, restart, and enable services with init system detection. Automatically uses systemctl on Linux or launchctl on macOS."),
            tags: tags(&["service", "start", "stop", "restart", "enable", "systemctl", "launchctl"]),
            prerequisites: vec![s("discover/detect-init-system")],
            examples: vec![
                ex(
                    "Restart a service (OS-adaptive)",
                    r#"const host = "target-server";
const service = "nginx";

const init = await hop.exec(host, `
    command -v systemctl >/dev/null 2>&1 && echo systemd && exit 0
    command -v launchctl >/dev/null 2>&1 && echo launchd && exit 0
    echo unknown
`);
const initSys = init.stdout.trim();

if (initSys === "systemd") {
    await hop.exec(host, `systemctl restart ${service}`);
    const status = await hop.exec(host, `systemctl is-active ${service}`);
    hop.log(`${host}: ${service} is ${status.stdout.trim()} (systemd)`);
} else if (initSys === "launchd") {
    // macOS: brew services or launchctl
    await hop.exec(host, `brew services restart ${service} 2>/dev/null || launchctl kickstart -k system/com.${service}`);
    const status = await hop.exec(host, `brew services list 2>/dev/null | grep ${service} || launchctl print system/com.${service} 2>&1 | head -3`);
    hop.log(`${host}: ${status.stdout.trim()} (launchd)`);
} else {
    hop.log(`${host}: unknown init system, cannot manage services`);
}"#,
                    Some("target-server: nginx is active (systemd)"),
                ),
            ],
            pitfalls: vec![
                s("Service names may differ between Linux and macOS (e.g., 'nginx' vs 'homebrew.mxcl.nginx')."),
                s("systemctl restart causes brief downtime — use 'reload' when the service supports it."),
            ],
            related: tags(&["services/status", "services/logs", "services/manage-systemd", "services/manage-launchd"]),
            sub_skills: vec![
                s("services/manage-systemd"),
                s("services/manage-launchd"),
            ],
        },
        Skill {
            id: s("services/manage-systemd"),
            category: s("services"),
            title: s("Manage Services with systemd"),
            description: s("Detailed systemd service management: start, stop, restart, enable, disable, mask, and inspect units."),
            tags: tags(&["systemd", "systemctl", "unit", "linux"]),
            prerequisites: vec![],
            examples: vec![
                ex(
                    "systemd service operations",
                    r#"const host = "linux-host";
const svc = "nginx";

// Start and enable
await hop.exec(host, `systemctl enable --now ${svc}`);

// Check status
const status = await hop.exec(host, `systemctl status ${svc} --no-pager`);
hop.log(status.stdout);

// Reload (zero-downtime config update)
await hop.exec(host, `systemctl reload ${svc}`);

// Show restart count and resource limits
const props = await hop.exec(host, `systemctl show ${svc} -p NRestarts,MemoryMax,CPUQuota`);
hop.log(props.stdout);

// List failed units
const failed = await hop.exec(host, "systemctl --failed --no-pager");
hop.log(failed.stdout);"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("'enable' makes the service start on boot; 'start' only starts it now."),
                s("Use 'enable --now' to combine both actions."),
            ],
            related: tags(&["services/manage"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("services/manage-launchd"),
            category: s("services"),
            title: s("Manage Services with launchd"),
            description: s("macOS service management using launchctl and brew services. launchd is macOS's init system, managing daemons and agents."),
            tags: tags(&["launchd", "launchctl", "macos", "brew-services"]),
            prerequisites: vec![],
            examples: vec![
                ex(
                    "launchd service operations",
                    r#"const host = "mac-host";

// Using brew services (preferred for Homebrew-installed software)
await hop.exec(host, "brew services start nginx");
const list = await hop.exec(host, "brew services list");
hop.log(list.stdout);

// Using launchctl directly
await hop.exec(host, "launchctl load /Library/LaunchDaemons/com.example.myapp.plist");

// Check if a service is running
const check = await hop.exec(host, "launchctl list | grep nginx");
hop.log(check.stdout);

// Stop a service
await hop.exec(host, "brew services stop nginx");"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("LaunchDaemons run as root; LaunchAgents run as the logged-in user."),
                s("brew services manages plist files for Homebrew-installed formulas."),
            ],
            related: tags(&["services/manage"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("services/status"),
            category: s("services"),
            title: s("Check Service Status"),
            description: s("Check if a service is running, using the appropriate init system. Works across Linux (systemd) and macOS (launchd)."),
            tags: tags(&["status", "running", "check", "service", "health"]),
            prerequisites: vec![s("discover/detect-init-system")],
            examples: vec![
                ex(
                    "Check service status (OS-adaptive)",
                    r#"const host = "target-server";
const services = ["nginx", "postgresql", "redis"];

const os = (await hop.exec(host, "uname -s")).stdout.trim();

for (const svc of services) {
    let status;
    if (os === "Darwin") {
        const r = await hop.exec(host, `brew services list 2>/dev/null | grep ${svc} | awk '{print $2}' || echo unknown`);
        status = r.stdout.trim();
    } else {
        const r = await hop.exec(host, `systemctl is-active ${svc} 2>/dev/null || echo inactive`);
        status = r.stdout.trim();
    }
    const icon = (status === "active" || status === "started") ? "OK" : "FAIL";
    hop.log(`[${icon}] ${svc}: ${status}`);
}"#,
                    Some("[OK] nginx: active\n[FAIL] postgresql: inactive\n[OK] redis: active"),
                ),
            ],
            pitfalls: vec![
                s("A service can be 'active' but unhealthy — complement with application-level health checks."),
            ],
            related: tags(&["services/manage", "services/logs", "monitor/service-status"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("services/logs"),
            category: s("services"),
            title: s("View Service Logs"),
            description: s("View service logs using journalctl on Linux or log show on macOS. Supports filtering by time, priority, and pattern."),
            tags: tags(&["logs", "journalctl", "log-show", "service", "debug"]),
            prerequisites: vec![s("discover/detect-init-system")],
            examples: vec![
                ex(
                    "View service logs (OS-adaptive)",
                    r#"const host = "target-server";
const service = "nginx";

const os = (await hop.exec(host, "uname -s")).stdout.trim();

let r;
if (os === "Darwin") {
    // macOS: use log show with predicate
    r = await hop.exec(host, `log show --predicate 'process == "${service}"' --last 1h --style compact 2>/dev/null | tail -20`);
} else {
    // Linux: use journalctl
    r = await hop.exec(host, `journalctl -u ${service} --since '1 hour ago' --no-pager -n 20`);
}
hop.log(`=== ${host} ${service} logs ===`);
hop.log(r.stdout);"#,
                    Some("=== target-server nginx logs ===\nMar 15 10:25:01 web-1 nginx[1234]: 10.0.0.1 - - GET /api/health 200\n..."),
                ),
            ],
            pitfalls: vec![
                s("macOS 'log show' can be slow for large time ranges — use narrow predicates."),
                s("journalctl requires the service to log to the journal; some apps log only to files."),
            ],
            related: tags(&["services/status", "monitor/log-search"]),
            sub_skills: vec![],
        },
    ]
}
