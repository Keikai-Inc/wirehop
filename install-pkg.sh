#!/usr/bin/env bash
# macOS .pkg daemon installer for hop
# Usage:
#   curl -fsSL https://hop.keik.ai/install-pkg.sh | bash
#
# Downloads the latest .pkg, installs it (prompts for sudo), and starts
# the hop daemon automatically via LaunchDaemon.

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

# --- Platform check ----------------------------------------------------------

OS=$(uname -s)
[[ "${OS}" == "Darwin" ]] || die "This installer is for macOS only. Use install.sh for Linux."

# --- Temp dir with cleanup ---------------------------------------------------

TMPDIR_HOP=$(mktemp -d)
trap 'rm -rf "${TMPDIR_HOP}"' EXIT

# --- HTTP helper -------------------------------------------------------------

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

# --- Resolve version ---------------------------------------------------------

info "Fetching latest version..."
VERSION=$(fetch_text "${BASE_URL}/latest")
[[ -n "${VERSION}" ]] || die "Could not determine version"
info "Installing hop v${VERSION} daemon"

# --- Download .pkg -----------------------------------------------------------

PKG_NAME="hop-${VERSION}.pkg"
PKG_URL="${BASE_URL}/v${VERSION}/${PKG_NAME}"

info "Downloading ${PKG_NAME}..."
fetch "${PKG_URL}" "${TMPDIR_HOP}/${PKG_NAME}"

# --- Install -----------------------------------------------------------------

info "Installing package (sudo required)..."
sudo installer -pkg "${TMPDIR_HOP}/${PKG_NAME}" -target /

# --- Done --------------------------------------------------------------------

printf "\n${BOLD}hop v${VERSION}${RESET} daemon installed!\n"
printf "The daemon is running. Create an invite with: ${BOLD}hop invite${RESET}\n"
