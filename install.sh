#!/usr/bin/env bash
# Installer for hop
# Usage:
#   curl -fsSL https://hop.keikai.ai/install.sh | bash
#   curl -fsSL https://hop.keikai.ai/install.sh | bash -s -- --version 0.1.0
#   curl -fsSL https://hop.keikai.ai/install.sh | bash -s -- --dir ~/.local/bin
#   curl -fsSL https://hop.keikai.ai/install.sh | bash -s -- --daemon
#
# Tiers:
#   (default)              Client — reach hosts you're invited to. No sudo, no VPN.
#                          Installs to ~/.local/bin (zero sudo); an existing
#                          /usr/local/bin/hop is updated in place.
#   --host                 Node — put this machine on the warren VPN (sudo, daemon).
#                          Installs to a root-owned /usr/local/bin (decision 7).
#
# Warren options (forwarded to the --host path):
#   --invite <token>       Redeem an invite (it carries the warren) — join the network
#   --no-vpn               Set up a host but disable the VPN data plane
#   --tag <a,b>            Tag this host (drives role->tag reach + MagicDNS)
#   --default-role <name>  Role for invites that don't specify one (default: member)

set -euo pipefail

BASE_URL="${HOP_CDN_URL:-https://hop.keikai.ai}"

# Release signing public key (security-audit H9). Empty = unsigned releases →
# checksum-only verification (current behaviour). To enable: generate a keypair
# with scripts/gen-signing-key.sh, paste the PUBLIC key between the markers
# below, and sign releases with HOP_SIGNING_KEY set. `openssl dgst -sha256
# -verify` works on both OpenSSL and the LibreSSL shipped on macOS. Override for
# testing with HOP_PUBKEY env.
HOP_PUBKEY="${HOP_PUBKEY:-}"
# -----BEGIN HOP_PUBKEY----- (paste -----BEGIN PUBLIC KEY----- … here)
# -----END HOP_PUBKEY-----

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

INSTALL_DIR=""          # empty = auto (resolved below per decision 7)
VERSION=""
DAEMON=false
# Warren primers — applied to host config after install (see apply_primers).
NO_VPN=false
TAGS=""
DEFAULT_ROLE=""
JOIN_TICKET=""
INVITE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)      VERSION="$2"; shift 2 ;;
    --dir)          INSTALL_DIR="$2"; shift 2 ;;
    --host|--daemon) DAEMON=true; shift ;;   # --host: put this machine on the warren (node)
    --invite)       INVITE="$2"; shift 2 ;;  # unified: an invite carries the warren
    --no-vpn)       NO_VPN=true; shift ;;
    --tag)          TAGS="${TAGS:+${TAGS},}$2"; shift 2 ;;
    --default-role) DEFAULT_ROLE="$2"; shift 2 ;;
    --join)         JOIN_TICKET="$2"; shift 2 ;;  # hidden: raw netdoc ticket (back-compat)
    *)              die "Unknown option: $1" ;;
  esac
done

# --- Resolve install dir (decision 7: root-owned-binary invariant) -----------
# A pure client only ever runs as the user, so it installs zero-sudo into
# ~/.local/bin. Becoming a node (--host) runs an always-on root daemon, which
# must execute a root-owned, root-only-writable binary — so it promotes to
# /usr/local/bin under sudo. An existing /usr/local/bin/hop is updated in place
# so upgrades never fragment across two PATH entries. An explicit --dir wins.
if [[ -z "${INSTALL_DIR}" ]]; then
  if [[ "${DAEMON}" == true ]]; then
    INSTALL_DIR="/usr/local/bin"
  elif [[ -x /usr/local/bin/hop ]]; then
    INSTALL_DIR="/usr/local/bin"          # keep an existing system install in place
  else
    INSTALL_DIR="${HOME}/.local/bin"      # new pure-client install — no sudo
  fi
fi

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
  die "No sha256sum or shasum found — cannot verify the download. Install coreutils (sha256sum) or use a system with shasum, then retry."
fi

[[ "${ACTUAL}" == "${EXPECTED}" ]] || die "Checksum mismatch!\n  expected: ${EXPECTED}\n  got:      ${ACTUAL}"

# --- Verify signature (optional, security-audit H9) --------------------------
# When a public key is embedded (HOP_PUBKEY), require a valid detached signature
# over the binary — checksums alone don't prove provenance if the CDN/bucket is
# compromised. Fails closed: a missing or bad signature aborts the install.
# When HOP_PUBKEY is empty (unsigned releases) this is skipped entirely.
if [[ -n "${HOP_PUBKEY}" ]]; then
  command -v openssl >/dev/null 2>&1 || die "Signature verification needs openssl, which was not found."
  info "Verifying signature..."
  if ! fetch "${BINARY_URL}.sig" "${TMPDIR_HOP}/hop.sig" 2>/dev/null; then
    die "Signed releases expected, but no signature found for ${BINARY_NAME}. Aborting."
  fi
  printf '%s\n' "${HOP_PUBKEY}" > "${TMPDIR_HOP}/pub.pem"
  if openssl dgst -sha256 -verify "${TMPDIR_HOP}/pub.pem" \
        -signature "${TMPDIR_HOP}/hop.sig" "${TMPDIR_HOP}/hop" >/dev/null 2>&1; then
    info "Signature verified."
  else
    die "Signature verification FAILED for ${BINARY_NAME}. Refusing to install."
  fi
fi

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

# Recover onto the new binary: `hop recover` is one idempotent routine that
# kills leftover client agents (which share this machine's node-id and would
# keep colliding with the daemon at the relay), removes stale sockets, and
# restarts the host daemon. It never touches identity or membership. Run with
# sudo when a system daemon is present so it can actually restart it.
HOP_BIN="${INSTALL_DIR}/hop"
DAEMON_PRESENT=false
if [[ "$(uname -s)" == "Darwin" ]]; then
  launchctl print "system/com.hop.daemon" &>/dev/null 2>&1 && DAEMON_PRESENT=true
else
  systemctl is-active --quiet hop 2>/dev/null && DAEMON_PRESENT=true
fi
if [[ "${DAEMON_PRESENT}" == "true" ]]; then
  info "Recovering hop (clearing stale agents, restarting daemon)..."
  if sudo "${HOP_BIN}" recover --quiet; then
    info "Hop recovered onto the new version."
  else
    warn "Could not fully recover (try: sudo hop recover)"
  fi
else
  # Pure client (no daemon): clear any stale agents as the user.
  "${HOP_BIN}" recover --quiet 2>/dev/null || true
fi

# --- Daemon setup (--daemon) -------------------------------------------------

if [[ "${DAEMON}" == "true" ]]; then
  info "Delegating to install-daemon.sh for full daemon setup..."
  # Forward warren primers to the daemon installer.
  DAEMON_ARGS=()
  [[ "${NO_VPN}" == "true" ]]   && DAEMON_ARGS+=(--no-vpn)
  [[ -n "${TAGS}" ]]            && DAEMON_ARGS+=(--tag "${TAGS}")
  [[ -n "${DEFAULT_ROLE}" ]]    && DAEMON_ARGS+=(--default-role "${DEFAULT_ROLE}")
  [[ -n "${JOIN_TICKET}" ]]     && DAEMON_ARGS+=(--join "${JOIN_TICKET}")
  [[ -n "${INVITE}" ]]          && DAEMON_ARGS+=(--invite "${INVITE}")
  # Expand the array safely even when empty: macOS bash 3.2 under `set -u`
  # treats "${arr[@]}" on an empty array as an unbound-variable error, so use
  # the ${arr[@]+...} guard which expands to nothing when there are no args.
  if command -v curl >/dev/null 2>&1; then
    exec bash <(curl -fsSL "${BASE_URL}/install-daemon.sh") ${DAEMON_ARGS[@]+"${DAEMON_ARGS[@]}"}
  elif command -v wget >/dev/null 2>&1; then
    exec bash <(wget -qO- "${BASE_URL}/install-daemon.sh") ${DAEMON_ARGS[@]+"${DAEMON_ARGS[@]}"}
  else
    die "Neither curl nor wget found."
  fi
fi

# --- Apply warren primers to the user host config (client install) -----------

HOP_BIN="${INSTALL_DIR}/hop"
if [[ "${NO_VPN}" == "true" || -n "${TAGS}" || -n "${DEFAULT_ROLE}" || -n "${JOIN_TICKET}" ]]; then
  [[ "${NO_VPN}" == "true" ]] && "${HOP_BIN}" config set vpn off >/dev/null && info "Warren VPN disabled (run 'hop config set vpn on' to re-enable)"
  [[ -n "${TAGS}" ]]         && "${HOP_BIN}" config set tags "${TAGS}" >/dev/null && info "Host tags: ${TAGS}"
  [[ -n "${DEFAULT_ROLE}" ]] && "${HOP_BIN}" config set default_role "${DEFAULT_ROLE}" >/dev/null && info "Default invite role: ${DEFAULT_ROLE}"
  if [[ -n "${JOIN_TICKET}" ]]; then
    CFG_DIR="$("${HOP_BIN}" config path)"
    mkdir -p "${CFG_DIR}"
    # 0600 — this is a warren *write* ticket; world-readable would let any
    # local user gain warren write access (security-audit H7).
    ( umask 077; printf '%s' "${JOIN_TICKET}" > "${CFG_DIR}/netdoc-join.ticket" )
    chmod 600 "${CFG_DIR}/netdoc-join.ticket" 2>/dev/null || true
    info "Warren join ticket saved (federates on next 'hop host')"
  fi
fi

# Client + invite: redeem it now so the host is saved and (if the invite carries
# a warren) the ticket is stored for a later `hop warren join`. Non-fatal.
if [[ -n "${INVITE}" ]]; then
  info "Redeeming invite..."
  if "${HOP_BIN}" exec "${INVITE}" -- true >/dev/null 2>&1; then
    info "Connected. You can reach the host with: hop <name>"
    info "To put THIS machine on the warren VPN later: hop warren join"
  else
    warn "Could not auto-redeem the invite; connect manually with: hop connect ${INVITE}"
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

# Offer the warren-VPN upgrade if this is a client install and no host is running.
if [[ "${DAEMON}" == "false" ]]; then
  show_hint=false
  if [[ "${OS}" == "linux" ]] && ! systemctl is-active --quiet hop 2>/dev/null; then
    show_hint=true
  elif [[ "${OS}" == "darwin" ]] && ! launchctl print "system/com.hop.daemon" &>/dev/null 2>&1; then
    show_hint=true
  fi
  if [[ "${show_hint}" == "true" ]]; then
    printf "\nThis is a client install (reach hosts you're invited to — no VPN).\n"
    printf "To put this machine ON your warren (private network, always-on host):\n"
    printf "  curl -fsSL %s/install.sh | bash -s -- --host\n" "${BASE_URL}"
  fi
fi
