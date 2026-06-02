#!/usr/bin/env bash
# Daemon installer for hop (macOS + Linux)
# Usage:
#   curl -fsSL https://hop.keik.ai/install-daemon.sh | bash
#
# macOS:  Downloads the latest .pkg, installs it, starts the LaunchDaemon.
# Linux:  Installs the binary, creates a systemd service, enables it.
#
# Warren primers (applied to the daemon's host config):
#   --no-vpn               Disable the warren VPN data plane (default: on)
#   --tag <a,b>            Tag this host (drives role->tag reach + MagicDNS)
#   --default-role <name>  Role for invites that don't specify one (default: member)
#   --join <ticket>        Federate into an existing warren

set -euo pipefail

BASE_URL="${HOP_CDN_URL:-https://hop.keik.ai}"

# Warren primers (parsed below; applied by apply_daemon_primers).
NO_VPN=false
TAGS=""
DEFAULT_ROLE=""
JOIN_TICKET=""
HOP_BIN="/usr/local/bin/hop"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-vpn)       NO_VPN=true; shift ;;
    --tag)          TAGS="${TAGS:+${TAGS},}$2"; shift 2 ;;
    --default-role) DEFAULT_ROLE="$2"; shift 2 ;;
    --join)         JOIN_TICKET="$2"; shift 2 ;;
    *)              printf 'warn  Unknown option: %s\n' "$1" >&2; shift ;;
  esac
done

# Apply warren primers to the daemon's host config dir ($1). Best-effort; fixes
# ownership/perms on Linux so the daemon (root) and the hop group can read.
apply_daemon_primers() {
  local cfg_dir="$1" applied=false
  [[ "${NO_VPN}" == "true" ]]   && sudo "${HOP_BIN}" config set vpn off --config "${cfg_dir}" >/dev/null && applied=true && info "Warren VPN disabled"
  [[ -n "${TAGS}" ]]            && sudo "${HOP_BIN}" config set tags "${TAGS}" --config "${cfg_dir}" >/dev/null && applied=true && info "Host tags: ${TAGS}"
  [[ -n "${DEFAULT_ROLE}" ]]    && sudo "${HOP_BIN}" config set default_role "${DEFAULT_ROLE}" --config "${cfg_dir}" >/dev/null && applied=true && info "Default invite role: ${DEFAULT_ROLE}"
  if [[ -n "${JOIN_TICKET}" ]]; then
    printf '%s' "${JOIN_TICKET}" | sudo tee "${cfg_dir}/netdoc-join.ticket" >/dev/null && applied=true && info "Warren join ticket saved (federates on next daemon start)"
  fi
  if [[ "$(uname -s)" == "Linux" && "${applied}" == "true" ]]; then
    for f in host_config.json netdoc-join.ticket; do
      if sudo test -f "${cfg_dir}/${f}"; then
        sudo chown root:hop "${cfg_dir}/${f}" 2>/dev/null || true
        sudo chmod 660 "${cfg_dir}/${f}" 2>/dev/null || true
      fi
    done
  fi
}

# --- Colour helpers (disabled when piped) ------------------------------------

if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
  BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BOLD=''; RESET=''
fi

info()  { printf "${GREEN}info${RESET}  %s\n" "$*"; }
warn()  { printf "${YELLOW}warn${RESET}  %s\n" "$*"; }
error() { printf "${RED}error${RESET} %s\n" "$*" >&2; }
die()   { error "$@"; exit 1; }

# --- Temp dir with cleanup ---------------------------------------------------

TMPDIR_HOP=$(mktemp -d)
trap 'rm -rf "${TMPDIR_HOP}"' EXIT

# --- HTTP helpers ------------------------------------------------------------

fetch() {
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "${dest}" "${url}"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "${dest}" "${url}"
  else
    die "Neither curl nor wget found."
  fi
}

fetch_text() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${url}"
  else
    wget -qO- "${url}"
  fi
}

# --- Detect platform ---------------------------------------------------------

OS=$(uname -s)
ARCH=$(uname -m)

case "${ARCH}" in
  x86_64|amd64)  ARCH="x86_64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  armv7l|armv7)  ARCH="armv7" ;;
  *)             die "Unsupported architecture: ${ARCH}" ;;
esac

# --- Resolve version ---------------------------------------------------------

info "Fetching latest version..."
VERSION=$(fetch_text "${BASE_URL}/latest")
[[ -n "${VERSION}" ]] || die "Could not determine version"
info "Installing hop v${VERSION} daemon"

# --- macOS path --------------------------------------------------------------

if [[ "${OS}" == "Darwin" ]]; then
  PKG_NAME="hop-${VERSION}.pkg"
  PKG_URL="${BASE_URL}/v${VERSION}/${PKG_NAME}"

  info "Downloading ${PKG_NAME}..."
  fetch "${PKG_URL}" "${TMPDIR_HOP}/${PKG_NAME}"

  # Stop the client-side multiplexer agent so it restarts with the new binary.
  if command -v hop >/dev/null 2>&1; then
    if hop agent stop 2>/dev/null; then
      info "Restarted connection agent (will auto-launch on next use)"
    fi
  fi

  info "Installing package (sudo required)..."
  sudo installer -pkg "${TMPDIR_HOP}/${PKG_NAME}" -target /

  printf "\n${BOLD}hop v${VERSION}${RESET} daemon installed!\n"

  # Apply warren primers to the daemon config, then restart so they take effect.
  if [[ "${NO_VPN}" == "true" || -n "${TAGS}" || -n "${DEFAULT_ROLE}" || -n "${JOIN_TICKET}" ]]; then
    apply_daemon_primers "/Library/Application Support/hop"
    sudo launchctl kickstart -k system/com.hop.daemon >/dev/null 2>&1 || true
  fi

  # Verify the daemon is actually running (postinstall should have started it).
  sleep 1
  if sudo launchctl print system/com.hop.daemon >/dev/null 2>&1; then
    printf "The daemon is running.\n"
  else
    warn "The daemon may not be running. Check: sudo launchctl kickstart system/com.hop.daemon"
    warn "Logs: /var/log/hop-stderr.log"
  fi

  # Wait briefly for daemon to generate creator invite
  sleep 2
  CREATOR_INVITE="/Library/Application Support/hop/creator_invite"
  if [ -f "$CREATOR_INVITE" ]; then
    printf "\n${BOLD}=== CREATOR INVITE (expires in 1 hour) ===${RESET}\n\n"
    TOKEN=$(cat "$CREATOR_INVITE")
    printf "  hop connect %s\n\n" "$TOKEN"
    printf "This grants full admin access. Re-read with: ${BOLD}hop creator-invite${RESET}\n"
  else
    printf "Create an invite with: ${BOLD}hop invite${RESET}\n"
  fi
  exit 0
fi

# --- Linux path --------------------------------------------------------------

if [[ "${OS}" != "Linux" ]]; then
  die "Unsupported OS: ${OS}. This installer supports macOS and Linux."
fi

info "Detected platform: linux-${ARCH}"

# Download binary
BINARY_NAME="hop-linux-${ARCH}"
BINARY_URL="${BASE_URL}/v${VERSION}/${BINARY_NAME}"
CHECKSUM_URL="${BINARY_URL}.sha256"

info "Downloading ${BINARY_NAME}..."
fetch "${BINARY_URL}" "${TMPDIR_HOP}/hop"
fetch "${CHECKSUM_URL}" "${TMPDIR_HOP}/hop.sha256"

# Verify checksum
info "Verifying checksum..."
EXPECTED=$(cat "${TMPDIR_HOP}/hop.sha256" | tr -d '[:space:]')

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "${TMPDIR_HOP}/hop" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL=$(shasum -a 256 "${TMPDIR_HOP}/hop" | awk '{print $1}')
else
  warn "No sha256sum or shasum found — skipping checksum verification"
  ACTUAL="${EXPECTED}"
fi

[[ "${ACTUAL}" == "${EXPECTED}" ]] || die "Checksum mismatch!\n  expected: ${EXPECTED}\n  got:      ${ACTUAL}"

# Install binary
chmod +x "${TMPDIR_HOP}/hop"
info "Installing binary to /usr/local/bin/hop (sudo required)..."
sudo mv "${TMPDIR_HOP}/hop" /usr/local/bin/hop

# Create hop group and set up config directory permissions
if ! getent group hop >/dev/null 2>&1; then
  info "Creating system group 'hop'..."
  sudo groupadd --system hop
fi
CURRENT_USER=$(whoami)
if [ "$CURRENT_USER" != "root" ]; then
  sudo usermod -aG hop "$CURRENT_USER"
fi
sudo mkdir -p /etc/hop
sudo chown root:hop /etc/hop
sudo chmod 2770 /etc/hop
for f in peers.json pending_invites.json datastore.redb; do
  if [ -f "/etc/hop/$f" ]; then
    sudo chown root:hop "/etc/hop/$f"
    sudo chmod 660 "/etc/hop/$f"
  fi
done

# Migrate config to /etc/hop/ if daemon was previously running without
# --config /etc/hop (pre-0.3.5). Check root's config dir first, then
# the current user's config dir (covers manual `hop host` runs).
MIGRATE_SOURCES="/root/.config/hop"
if [ "$CURRENT_USER" != "root" ]; then
  USER_HOME=$(eval echo "~$CURRENT_USER")
  MIGRATE_SOURCES="$MIGRATE_SOURCES $USER_HOME/.config/hop"
fi
for f in identity.json peers.json pending_invites.json session_config.json; do
  if [ ! -f "/etc/hop/$f" ]; then
    for src in $MIGRATE_SOURCES; do
      if sudo test -f "$src/$f"; then
        info "Migrating $f from $src to /etc/hop..."
        sudo cp "$src/$f" "/etc/hop/$f"
        sudo chown root:hop "/etc/hop/$f"
        sudo chmod 660 "/etc/hop/$f"
        break
      fi
    done
  fi
done

# Install systemd service
info "Installing systemd service..."
SERVICE_URL="${BASE_URL}/hop.service"
sudo "${SHELL:-bash}" -c "$(
cat <<INNEREOF
if command -v curl >/dev/null 2>&1; then
  curl -fsSL -o /etc/systemd/system/hop.service "${SERVICE_URL}"
else
  wget -qO /etc/systemd/system/hop.service "${SERVICE_URL}"
fi
INNEREOF
)"

# Stop the client-side multiplexer agent so it restarts with the new binary.
if command -v hop >/dev/null 2>&1; then
  if hop agent stop 2>/dev/null; then
    info "Restarted connection agent (will auto-launch on next use)"
  fi
fi

# Apply warren primers to /etc/hop before first start so the daemon picks them up.
if [[ "${NO_VPN}" == "true" || -n "${TAGS}" || -n "${DEFAULT_ROLE}" || -n "${JOIN_TICKET}" ]]; then
  apply_daemon_primers "/etc/hop"
fi

# Enable and start (or restart if already running)
info "Enabling and starting hop daemon..."
sudo systemctl daemon-reload
if systemctl is-active --quiet hop 2>/dev/null; then
  sudo systemctl restart hop
  info "Hop daemon restarted."
else
  sudo systemctl enable --now hop
fi

printf "\n${BOLD}hop v${VERSION}${RESET} daemon installed!\n"
printf "The daemon is running.\n"

# Wait briefly for daemon to generate creator invite
sleep 2
CREATOR_INVITE="/etc/hop/creator_invite"
if [ -f "$CREATOR_INVITE" ]; then
    printf "\n${BOLD}=== CREATOR INVITE (expires in 1 hour) ===${RESET}\n\n"
    TOKEN=$(cat "$CREATOR_INVITE")
    printf "  hop connect %s\n\n" "$TOKEN"
    printf "This grants full admin access. Re-read with: ${BOLD}hop creator-invite${RESET}\n"
else
    printf "Create an invite with: ${BOLD}hop invite${RESET}\n"
fi
