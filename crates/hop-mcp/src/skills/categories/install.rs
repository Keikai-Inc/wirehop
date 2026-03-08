use crate::skills::Skill;
use super::super::data::{s, tags, ex};

pub fn skills() -> Vec<Skill> {
    vec![
        // === Intent skills ===
        Skill {
            id: s("install/package"),
            category: s("install"),
            title: s("Install Package"),
            description: s("Detect the host's package manager and install a package. Automatically selects apt, dnf, brew, or apk based on what is available."),
            tags: tags(&["install", "package", "apt", "dnf", "brew", "apk"]),
            prerequisites: vec![s("discover/detect-package-manager")],
            examples: vec![
                ex(
                    "Install a package with auto-detection",
                    r#"const host = "target-server";
const pkg = "jq";

// Detect package manager
const detect = await hop.exec(host, `
    command -v apt-get >/dev/null 2>&1 && echo apt-get && exit 0
    command -v dnf >/dev/null 2>&1 && echo dnf && exit 0
    command -v yum >/dev/null 2>&1 && echo yum && exit 0
    command -v brew >/dev/null 2>&1 && echo brew && exit 0
    command -v apk >/dev/null 2>&1 && echo apk && exit 0
    echo unknown
`);
const pm = detect.stdout.trim();

let cmd;
switch (pm) {
    case "apt-get": cmd = `apt-get update -qq && apt-get install -y ${pkg}`; break;
    case "dnf":     cmd = `dnf install -y ${pkg}`; break;
    case "yum":     cmd = `yum install -y ${pkg}`; break;
    case "brew":    cmd = `brew install ${pkg}`; break;
    case "apk":     cmd = `apk add ${pkg}`; break;
    default:        hop.log(`No known package manager on ${host}`); return;
}

const r = await hop.exec(host, cmd);
hop.log(`[${pm}] ${r.exitCode === 0 ? "installed" : "FAILED"}: ${pkg}`);"#,
                    Some("[apt-get] installed: jq"),
                ),
            ],
            pitfalls: vec![
                s("Package names differ across managers: e.g., 'python3-dev' (apt) vs 'python3-devel' (dnf)."),
                s("brew runs as a normal user; apt/dnf/apk require root or sudo."),
            ],
            related: tags(&["install/check-installed", "install/list-installed", "discover/detect-package-manager"]),
            sub_skills: vec![
                s("install/package-apt"),
                s("install/package-dnf"),
                s("install/package-brew"),
                s("install/package-apk"),
            ],
        },
        Skill {
            id: s("install/check-installed"),
            category: s("install"),
            title: s("Check If Package Installed"),
            description: s("Check if a package is installed and its version, using the appropriate package manager for the host OS."),
            tags: tags(&["check", "installed", "version", "query", "package"]),
            prerequisites: vec![s("discover/detect-package-manager")],
            examples: vec![
                ex(
                    "Check if a package is installed (OS-adaptive)",
                    r#"const host = "target-server";
const pkg = "nginx";

const r = await hop.exec(host, `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        brew list --versions ${pkg} 2>/dev/null || echo "not installed"
    elif command -v dpkg >/dev/null 2>&1; then
        dpkg -l ${pkg} 2>/dev/null | grep "^ii" || echo "not installed"
    elif command -v rpm >/dev/null 2>&1; then
        rpm -q ${pkg} 2>/dev/null || echo "not installed"
    elif command -v apk >/dev/null 2>&1; then
        apk info ${pkg} 2>/dev/null || echo "not installed"
    fi
`);
hop.log(`${host}: ${r.stdout.trim()}`);"#,
                    Some("target-server: ii  nginx  1.24.0-1  amd64  high performance web server"),
                ),
            ],
            pitfalls: vec![
                s("A package may be installed but its service not running — check service status separately."),
            ],
            related: tags(&["install/package", "install/list-installed"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("install/list-installed"),
            category: s("install"),
            title: s("List Installed Packages"),
            description: s("List all installed packages with their versions, using the appropriate package manager for the host OS."),
            tags: tags(&["list", "installed", "packages", "inventory"]),
            prerequisites: vec![s("discover/detect-package-manager")],
            examples: vec![
                ex(
                    "List installed packages (OS-adaptive)",
                    r#"const host = "target-server";
const r = await hop.exec(host, `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        brew list --versions | head -20
    elif command -v dpkg >/dev/null 2>&1; then
        dpkg -l | grep "^ii" | awk '{print $2, $3}' | head -20
    elif command -v rpm >/dev/null 2>&1; then
        rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' | sort | head -20
    elif command -v apk >/dev/null 2>&1; then
        apk list --installed 2>/dev/null | head -20
    fi
`);
hop.log(r.stdout);"#,
                    Some("adduser 3.118ubuntu5\napt 2.4.11\nbase-files 12ubuntu4.4\nbash 5.1-6ubuntu1\n..."),
                ),
            ],
            pitfalls: vec![
                s("Package count can be large — use head or grep to filter."),
            ],
            related: tags(&["install/check-installed", "security/package-audit"]),
            sub_skills: vec![],
        },
        // === Implementation sub-skills ===
        Skill {
            id: s("install/package-apt"),
            category: s("install"),
            title: s("Install with apt (Debian/Ubuntu)"),
            description: s("Install packages using apt-get on Debian-based systems. Covers update, install, remove, and repository management."),
            tags: tags(&["apt", "apt-get", "debian", "ubuntu", "dpkg"]),
            prerequisites: vec![],
            examples: vec![
                ex(
                    "Install and manage packages with apt",
                    r#"const host = "ubuntu-host";

// Update package lists
await hop.exec(host, "apt-get update -qq");

// Install a package
await hop.exec(host, "apt-get install -y nginx curl jq");

// Check for upgradable packages
const upgradable = await hop.exec(host, "apt list --upgradable 2>/dev/null");
hop.log(upgradable.stdout);

// Remove a package
await hop.exec(host, "apt-get remove -y nginx && apt-get autoremove -y");"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("Always run apt-get update before install to avoid 404 errors on stale indices."),
                s("Use -y for non-interactive mode in automation."),
            ],
            related: tags(&["install/package"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("install/package-dnf"),
            category: s("install"),
            title: s("Install with dnf/yum (RHEL/Fedora)"),
            description: s("Install packages using dnf or yum on Red Hat-based systems. dnf is the modern replacement for yum."),
            tags: tags(&["dnf", "yum", "rpm", "rhel", "fedora", "centos"]),
            prerequisites: vec![],
            examples: vec![
                ex(
                    "Install and manage packages with dnf",
                    r#"const host = "rhel-host";

// Install a package
await hop.exec(host, "dnf install -y nginx curl jq");

// Check for updates
const updates = await hop.exec(host, "dnf check-update 2>/dev/null || true");
hop.log(updates.stdout);

// List installed
const installed = await hop.exec(host, "rpm -qa --last | head -10");
hop.log("Recently installed:\n" + installed.stdout);"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("dnf check-update returns exit code 100 when updates are available — not an error."),
                s("Use dnf over yum when both are available; yum is a compatibility shim on modern RHEL."),
            ],
            related: tags(&["install/package"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("install/package-brew"),
            category: s("install"),
            title: s("Install with brew (macOS)"),
            description: s("Install packages using Homebrew on macOS. brew does not require root and installs to /opt/homebrew (Apple Silicon) or /usr/local (Intel)."),
            tags: tags(&["brew", "homebrew", "macos", "cask"]),
            prerequisites: vec![],
            examples: vec![
                ex(
                    "Install and manage packages with brew",
                    r#"const host = "mac-host";

// Install a formula
await hop.exec(host, "brew install nginx curl jq");

// Install a GUI app (cask)
await hop.exec(host, "brew install --cask firefox");

// Update and upgrade
await hop.exec(host, "brew update && brew upgrade");

// List installed
const installed = await hop.exec(host, "brew list --versions");
hop.log(installed.stdout);

// Check for issues
const doctor = await hop.exec(host, "brew doctor 2>&1 || true");
hop.log(doctor.stdout);"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("brew should not be run as root — it manages its own prefix."),
                s("Service names may differ from Linux: e.g., 'nginx' formula installs but uses 'brew services' not systemctl."),
            ],
            related: tags(&["install/package", "services/manage-launchd"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("install/package-apk"),
            category: s("install"),
            title: s("Install with apk (Alpine)"),
            description: s("Install packages using apk on Alpine Linux. apk is fast and common in Docker containers."),
            tags: tags(&["apk", "alpine", "container", "docker"]),
            prerequisites: vec![],
            examples: vec![
                ex(
                    "Install and manage packages with apk",
                    r#"const host = "alpine-host";

// Update index and install
await hop.exec(host, "apk update && apk add nginx curl jq");

// Search for a package
const search = await hop.exec(host, "apk search python3");
hop.log(search.stdout);

// List installed
const installed = await hop.exec(host, "apk info -v | head -20");
hop.log(installed.stdout);"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("Alpine uses musl libc, not glibc — some pre-compiled binaries may not work."),
                s("Alpine packages are often stripped-down; you may need '-dev' packages for headers."),
            ],
            related: tags(&["install/package"]),
            sub_skills: vec![],
        },
    ]
}
