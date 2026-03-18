#!/usr/bin/env bash
# Installer for hop
# Usage:
#   curl -fsSL https://hop.keik.ai/install.sh | bash
#   curl -fsSL https://hop.keik.ai/install.sh | bash -s -- --version 0.1.0
#   curl -fsSL https://hop.keik.ai/install.sh | bash -s -- --dir ~/.local/bin
#   curl -fsSL https://hop.keik.ai/install.sh | bash -s -- --daemon

set -euo pipefail

BASE_URL="${HOP_CDN_URL:-https://hop.keik.ai}"

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

# --- Parse arguments ---------------------------------------------------------

INSTALL_DIR="/usr/local/bin"
VERSION=""
DAEMON=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --dir)     INSTALL_DIR="$2"; shift 2 ;;
    --daemon)  DAEMON=true; shift ;;
    *)         die "Unknown option: $1" ;;
  esac
done

# --- HTTP helper (curl or wget) ----------------------------------------------

fetch() {
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "${dest}" "${url}"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "${dest}" "${url}"
  else
    die "Neither curl nor wget found. Please install one and retry."
  fi
}

fetch_text() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${url}"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "${url}"
  else
    die "Neither curl nor wget found. Please install one and retry."
  fi
}

# --- Detect platform ---------------------------------------------------------

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "${OS}" in
  darwin) OS="darwin" ;;
  linux)  OS="linux" ;;
  *)      die "Unsupported OS: ${OS}" ;;
esac

case "${ARCH}" in
  x86_64|amd64)  ARCH="x86_64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  armv7l|armv7)  ARCH="armv7" ;;
  *)             die "Unsupported architecture: ${ARCH}" ;;
esac

info "Detected platform: ${OS}-${ARCH}"

# --- Resolve version ---------------------------------------------------------

if [[ -z "${VERSION}" ]]; then
  info "Fetching latest version..."
  VERSION=$(fetch_text "${BASE_URL}/latest")
fi

[[ -n "${VERSION}" ]] || die "Could not determine version"
info "Installing hop v${VERSION}"

# --- Download binary + checksum ----------------------------------------------

BINARY_NAME="hop-${OS}-${ARCH}"
BINARY_URL="${BASE_URL}/v${VERSION}/${BINARY_NAME}"
CHECKSUM_URL="${BINARY_URL}.sha256"

info "Downloading ${BINARY_NAME}..."
fetch "${BINARY_URL}" "${TMPDIR_HOP}/hop"
fetch "${CHECKSUM_URL}" "${TMPDIR_HOP}/hop.sha256"

# --- Verify checksum ---------------------------------------------------------

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

# --- Install binary ----------------------------------------------------------

chmod +x "${TMPDIR_HOP}/hop"
mkdir -p "${INSTALL_DIR}" 2>/dev/null || true

if [[ -w "${INSTALL_DIR}" ]]; then
  mv "${TMPDIR_HOP}/hop" "${INSTALL_DIR}/hop"
else
  info "Elevated permissions required to install to ${INSTALL_DIR}"
  sudo mv "${TMPDIR_HOP}/hop" "${INSTALL_DIR}/hop"
fi

info "Installed hop to ${INSTALL_DIR}/hop"

# --- Restart running services ------------------------------------------------

# Stop the client-side multiplexer agent so it restarts with the new binary.
if command -v hop >/dev/null 2>&1; then
  if hop agent stop 2>/dev/null; then
    info "Restarted connection agent (will auto-launch on next use)"
  fi
fi

# Restart the host daemon if one is running.
if [[ "$(uname -s)" == "Darwin" ]]; then
  DAEMON_LABEL="com.hop.daemon"
  if launchctl print "system/${DAEMON_LABEL}" &>/dev/null 2>&1; then
    info "Restarting hop daemon..."
    sudo launchctl kickstart -k "system/${DAEMON_LABEL}" 2>/dev/null && \
      info "Hop daemon restarted." || \
      warn "Could not restart daemon (try: sudo launchctl kickstart -k system/${DAEMON_LABEL})"
  fi
else
  if systemctl is-active --quiet hop 2>/dev/null; then
    info "Restarting hop daemon..."
    sudo systemctl restart hop && \
      info "Hop daemon restarted." || \
      warn "Could not restart daemon (try: sudo systemctl restart hop)"
  fi
fi

# --- Daemon setup (--daemon) -------------------------------------------------

if [[ "${DAEMON}" == "true" ]]; then
  info "Delegating to install-daemon.sh for full daemon setup..."
  if command -v curl >/dev/null 2>&1; then
    exec bash <(curl -fsSL "${BASE_URL}/install-daemon.sh")
  elif command -v wget >/dev/null 2>&1; then
    exec bash <(wget -qO- "${BASE_URL}/install-daemon.sh")
  else
    die "Neither curl nor wget found."
  fi
fi

# --- PATH check --------------------------------------------------------------

if ! echo "${PATH}" | tr ':' '\n' | grep -qx "${INSTALL_DIR}"; then
  warn "${INSTALL_DIR} is not in your PATH."
  warn "Add it with:  export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

# --- Done --------------------------------------------------------------------

printf "\n${BOLD}hop v${VERSION}${RESET} installed successfully!\n"
printf "Run ${BOLD}hop --help${RESET} to get started.\n"

# Hint about daemon setup if service not already running
if [[ "${DAEMON}" == "false" ]]; then
  if [[ "${OS}" == "linux" ]] && ! systemctl is-active --quiet hop 2>/dev/null; then
    printf "\nTo run as a daemon (starts on boot):\n"
    printf "  curl -fsSL https://hop.keik.ai/install-daemon.sh | bash\n"
  elif [[ "${OS}" == "darwin" ]]; then
    DAEMON_LABEL="com.hop.daemon"
    if ! launchctl print "system/${DAEMON_LABEL}" &>/dev/null 2>&1; then
      printf "\nTo run as a daemon (starts on boot):\n"
      printf "  curl -fsSL https://hop.keik.ai/install-daemon.sh | bash\n"
    fi
  fi
fi
