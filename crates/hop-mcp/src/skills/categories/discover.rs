use crate::skills::{Skill, SkillExample};
use super::super::data::{s, tags, ex};

pub fn skills() -> Vec<Skill> {
    vec![
        Skill {
            id: s("discover/system-fingerprint"),
            category: s("discover"),
            title: s("System Fingerprint"),
            description: s("All-in-one system probe: detect OS, architecture, package manager, init system, firewall, and default shell in a single call. Run this first on any unknown host."),
            tags: tags(&["fingerprint", "detect", "os", "system", "probe", "discover"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Fingerprint a host",
                    r#"const host = "unknown-server";
const r = await hop.exec(host, `
  echo "os=$(uname -s)"
  echo "arch=$(uname -m)"
  echo "kernel=$(uname -r)"
  [ -f /etc/os-release ] && . /etc/os-release && echo "distro=$ID $VERSION_ID" || \
    (command -v sw_vers >/dev/null && echo "distro=macos $(sw_vers -productVersion)" || echo "distro=unknown")
  for pm in apt-get dnf yum brew apk; do command -v $pm >/dev/null 2>&1 && echo "pkg=$pm" && break; done
  command -v systemctl >/dev/null 2>&1 && echo "init=systemd" || \
    (command -v launchctl >/dev/null 2>&1 && echo "init=launchd" || \
    (command -v rc-service >/dev/null 2>&1 && echo "init=openrc" || echo "init=unknown"))
  command -v ufw >/dev/null 2>&1 && echo "fw=ufw" || \
    (command -v pfctl >/dev/null 2>&1 && echo "fw=pf" || \
    (command -v iptables >/dev/null 2>&1 && echo "fw=iptables" || echo "fw=none"))
  echo "shell=$SHELL"
`);
const info = {};
for (const line of r.stdout.trim().split("\n")) {
    const [k, v] = line.split("=", 2);
    if (k && v) info[k.trim()] = v.trim();
}
hop.log(JSON.stringify(info, null, 2));"#,
                    Some("{\n  \"os\": \"Linux\",\n  \"arch\": \"x86_64\",\n  \"kernel\": \"5.15.0\",\n  \"distro\": \"ubuntu 22.04\",\n  \"pkg\": \"apt-get\",\n  \"init\": \"systemd\",\n  \"fw\": \"ufw\",\n  \"shell\": \"/bin/bash\"\n}"),
                ),
            ],
            pitfalls: vec![
                s("Run this before any platform-specific commands to avoid errors on unknown systems."),
                s("Some minimal containers may lack /etc/os-release and common utilities."),
            ],
            related: tags(&["discover/identify-os", "discover/detect-package-manager", "discover/detect-init-system"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("discover/identify-os"),
            category: s("discover"),
            title: s("Identify OS"),
            description: s("Detect the operating system family and version. Uses uname, /etc/os-release on Linux, and sw_vers on macOS."),
            tags: tags(&["os", "detect", "linux", "macos", "version", "uname"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Detect OS across fleet",
                    r#"const hosts = await hop.fleet.list();
for (const h of hosts.filter(m => m.online)) {
    const r = await hop.exec(h.name, `
        os=$(uname -s)
        if [ "$os" = "Darwin" ]; then
            ver=$(sw_vers -productVersion)
            echo "macOS $ver ($(uname -m))"
        elif [ -f /etc/os-release ]; then
            . /etc/os-release
            echo "$PRETTY_NAME ($(uname -m))"
        else
            echo "$os $(uname -r) ($(uname -m))"
        fi
    `);
    hop.log(`${h.name}: ${r.stdout.trim()}`);
}"#,
                    Some("web-1: Ubuntu 22.04.3 LTS (x86_64)\nweb-2: Ubuntu 22.04.3 LTS (x86_64)\nmac-dev: macOS 14.2.1 (arm64)\ndb-1: Debian GNU/Linux 12 (x86_64)"),
                ),
            ],
            pitfalls: vec![
                s("Container hosts may report the host OS kernel version, not the container's base image."),
            ],
            related: tags(&["discover/system-fingerprint", "discover/detect-package-manager"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("discover/detect-package-manager"),
            category: s("discover"),
            title: s("Detect Package Manager"),
            description: s("Find which package manager is available: apt, dnf, yum, brew, or apk. Essential before running any install commands."),
            tags: tags(&["package-manager", "apt", "dnf", "brew", "apk", "detect"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Detect package manager on a host",
                    r#"const host = "target-server";
const checks = [
    ["apt-get", "apt-get"],
    ["dnf", "dnf"],
    ["yum", "yum"],
    ["brew", "brew"],
    ["apk", "apk"],
];
let pm = null;
for (const [check, cmd] of checks) {
    const r = await hop.exec(host, `command -v ${check} 2>/dev/null && echo found`);
    if (r.stdout.includes("found")) { pm = cmd; break; }
}
if (pm) {
    hop.log(`Package manager: ${pm}`);
} else {
    hop.log("No known package manager found");
}"#,
                    Some("Package manager: apt-get"),
                ),
            ],
            pitfalls: vec![
                s("Some systems have multiple package managers (e.g., both yum and dnf). Prefer the newer one."),
                s("brew typically runs as a non-root user, unlike apt/dnf."),
            ],
            related: tags(&["discover/system-fingerprint", "install/package"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("discover/detect-init-system"),
            category: s("discover"),
            title: s("Detect Init System"),
            description: s("Find which init system manages services: systemd, launchd, or OpenRC. Required before managing services."),
            tags: tags(&["init", "systemd", "launchd", "openrc", "detect", "service"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Detect init system",
                    r#"const host = "target-server";
const r = await hop.exec(host, `
    if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
        echo "systemd"
    elif command -v launchctl >/dev/null 2>&1; then
        echo "launchd"
    elif command -v rc-service >/dev/null 2>&1; then
        echo "openrc"
    else
        echo "unknown"
    fi
`);
hop.log(`Init system: ${r.stdout.trim()}`);"#,
                    Some("Init system: systemd"),
                ),
            ],
            pitfalls: vec![
                s("Containers often run without a full init system — PID 1 may be the app itself."),
            ],
            related: tags(&["discover/system-fingerprint", "services/manage"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("discover/check-command"),
            category: s("discover"),
            title: s("Check Command Availability"),
            description: s("Test if a specific binary exists in PATH. Use before invoking tools that may not be installed."),
            tags: tags(&["command", "check", "exists", "which", "path"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Check for required tools",
                    r#"const host = "target-server";
const tools = ["docker", "curl", "jq", "git", "python3", "node"];
const available = [];
const missing = [];
for (const tool of tools) {
    const r = await hop.exec(host, `command -v ${tool} >/dev/null 2>&1 && echo yes || echo no`);
    if (r.stdout.trim() === "yes") {
        available.push(tool);
    } else {
        missing.push(tool);
    }
}
hop.log(`Available: ${available.join(", ")}`);
if (missing.length) hop.log(`Missing: ${missing.join(", ")}`);"#,
                    Some("Available: curl, git, python3\nMissing: docker, jq, node"),
                ),
            ],
            pitfalls: vec![
                s("Use 'command -v' instead of 'which' — it is POSIX-portable across all shells."),
            ],
            related: tags(&["discover/detect-capabilities", "discover/system-fingerprint"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("discover/detect-capabilities"),
            category: s("discover"),
            title: s("Detect Capabilities"),
            description: s("Probe for available runtimes, tools, and capabilities: docker, python3, node, curl, jq, compilers, and more."),
            tags: tags(&["capabilities", "runtime", "tools", "probe", "inventory"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Probe host capabilities",
                    r#"const host = "target-server";
const r = await hop.exec(host, `
    echo "=== Runtimes ==="
    command -v python3 >/dev/null 2>&1 && python3 --version 2>&1 || echo "python3: not found"
    command -v node >/dev/null 2>&1 && node --version 2>&1 || echo "node: not found"
    command -v ruby >/dev/null 2>&1 && ruby --version 2>&1 || echo "ruby: not found"
    echo "=== Containers ==="
    command -v docker >/dev/null 2>&1 && docker --version 2>&1 || echo "docker: not found"
    echo "=== Tools ==="
    for t in curl wget jq git make gcc; do
        command -v $t >/dev/null 2>&1 && echo "$t: $(command -v $t)" || echo "$t: not found"
    done
`);
hop.log(r.stdout);"#,
                    Some("=== Runtimes ===\nPython 3.10.12\nnode: not found\nruby: not found\n=== Containers ===\nDocker version 24.0.5\n=== Tools ===\ncurl: /usr/bin/curl\nwget: /usr/bin/wget\njq: /usr/bin/jq\ngit: /usr/bin/git\nmake: /usr/bin/make\ngcc: /usr/bin/gcc"),
                ),
            ],
            pitfalls: vec![
                s("Version output formats vary — parse with care if automating decisions."),
                s("Some tools may be installed but not in the PATH for the hop user."),
            ],
            related: tags(&["discover/check-command", "discover/system-fingerprint"]),
            sub_skills: vec![],
        },
    ]
}
