#!/usr/bin/env bash
#
# Full release script for hop.
#
# Usage:
#   ./scripts/release.sh              # Release current version from Cargo.toml
#   ./scripts/release.sh 0.3.0        # Bump to 0.3.0, commit, tag, and release
#   ./scripts/release.sh --site-only  # Re-deploy website without building binaries
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUCKET="hop-releases"
CF_DISTRIBUTION_ID="${HOP_CF_DISTRIBUTION_ID:-E1SBRBZNSQX4WA}"
DIST_DIR="${PROJECT_ROOT}/target/release-dist"

SITE_ONLY=false
NEW_VERSION=""

# --- Parse arguments --------------------------------------------------------

for arg in "$@"; do
  case "${arg}" in
    --site-only) SITE_ONLY=true ;;
    --help|-h)
      echo "Usage: $0 [VERSION] [--site-only]"
      echo ""
      echo "  VERSION      Bump to this version before releasing (e.g. 0.3.0)"
      echo "  --site-only  Re-deploy website and invalidate CDN without building"
      echo ""
      echo "Examples:"
      echo "  $0              # Release current version from Cargo.toml"
      echo "  $0 0.3.0        # Bump version, commit, tag, and release"
      echo "  $0 --site-only  # Redeploy website only"
      exit 0
      ;;
    *)
      if [[ "${arg}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        NEW_VERSION="${arg}"
      else
        echo "Error: Unknown argument '${arg}'"
        echo "Run '$0 --help' for usage."
        exit 1
      fi
      ;;
  esac
done

# --- Preflight checks -------------------------------------------------------

check_cmd() {
  if ! command -v "$1" &>/dev/null; then
    echo "Error: '$1' is not installed."
    exit 1
  fi
}

if [[ "${SITE_ONLY}" == false ]]; then
  echo "==> Checking prerequisites"
  check_cmd cargo
  check_cmd cross
  check_cmd aws
  check_cmd docker
  check_cmd strip

  # Release branch guard (security-audit P2): a release publishes signed-by-
  # nothing artifacts to the production bucket and tags the repo, so it must be
  # cut from the intended branch with a clean tree — never accidentally from a
  # half-finished feature branch. Expected branch defaults to 'main'; override
  # with HOP_RELEASE_BRANCH=<name>, or bypass entirely with HOP_RELEASE_ALLOW_DIRTY=1.
  EXPECTED_BRANCH="${HOP_RELEASE_BRANCH:-main}"
  CURRENT_BRANCH="$(git -C "${PROJECT_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  if [[ "${HOP_RELEASE_ALLOW_DIRTY:-0}" != "1" ]]; then
    if [[ "${CURRENT_BRANCH}" != "${EXPECTED_BRANCH}" ]]; then
      echo "Error: releasing from '${CURRENT_BRANCH}', expected '${EXPECTED_BRANCH}'."
      echo "  Switch to ${EXPECTED_BRANCH}, set HOP_RELEASE_BRANCH=${CURRENT_BRANCH}, or HOP_RELEASE_ALLOW_DIRTY=1 to override."
      exit 1
    fi
    if [[ -n "$(git -C "${PROJECT_ROOT}" status --porcelain)" ]]; then
      echo "Error: working tree is dirty — commit or stash before releasing (or HOP_RELEASE_ALLOW_DIRTY=1 to override)."
      exit 1
    fi
  fi

  if ! docker info &>/dev/null; then
    echo "Error: Docker is not running."
    exit 1
  fi

  if ! aws sts get-caller-identity &>/dev/null; then
    echo "Error: AWS credentials not configured."
    exit 1
  fi

  # Check Rust targets
  for target in aarch64-apple-darwin x86_64-apple-darwin; do
    if ! rustup target list --installed | grep -q "${target}"; then
      echo "Error: Rust target '${target}' is not installed."
      echo "  Run: rustup target add ${target}"
      exit 1
    fi
  done
fi

# --- Version bump (optional) ------------------------------------------------

if [[ -n "${NEW_VERSION}" ]]; then
  echo "==> Bumping version to ${NEW_VERSION}"

  # Update workspace Cargo.toml
  sed -i '' "s/^version = \".*\"/version = \"${NEW_VERSION}\"/" "${PROJECT_ROOT}/Cargo.toml"

  # Verify it took effect
  VERIFY=$(grep -m1 '^version' "${PROJECT_ROOT}/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')
  if [[ "${VERIFY}" != "${NEW_VERSION}" ]]; then
    echo "Error: Version bump failed (got '${VERIFY}', expected '${NEW_VERSION}')"
    exit 1
  fi

  echo "==> Running cargo check to verify version bump"
  cargo check -p hop-cli --quiet

  echo "==> Committing version bump"
  # Include Cargo.lock: the `cargo check` above rewrites the workspace crate
  # versions in the lockfile, so committing only Cargo.toml leaves the lock a
  # version behind and the next build dirties the tree (blocking the release).
  git -C "${PROJECT_ROOT}" add Cargo.toml Cargo.lock
  git -C "${PROJECT_ROOT}" commit -m "Bump version to ${NEW_VERSION}"
fi

# Extract version from workspace Cargo.toml
VERSION=$(grep -m1 '^version' "${PROJECT_ROOT}/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')
echo ""
echo "============================================"
echo "  Releasing hop v${VERSION}"
echo "============================================"
echo ""

# Build the invalidation path list from what actually exists in site/, so a new
# page is never served stale from the edge just because nobody updated a list.
site_paths() {
  local p
  for p in "${PROJECT_ROOT}"/site/*.html; do
    printf '/%s\n' "$(basename "${p}")"
  done
}

# --- Site-only mode ----------------------------------------------------------

if [[ "${SITE_ONLY}" == true ]]; then
  echo "==> Site-only mode — skipping builds"

  echo "==> Uploading site"
  # Every page in site/, not a hardcoded list: a new page that silently fails to
  # deploy looks exactly like a page that deployed fine.
  for page in "${PROJECT_ROOT}"/site/*.html; do
    aws s3 cp "${page}" "s3://${BUCKET}/$(basename "${page}")" \
      --content-type "text/html"
  done
  aws s3 cp "${PROJECT_ROOT}/site/shared.css" "s3://${BUCKET}/shared.css" \
    --content-type "text/css"
  aws s3 cp "${PROJECT_ROOT}/site/shared.js" "s3://${BUCKET}/shared.js" \
    --content-type "application/javascript"

  # install.sh / install-daemon.sh are deployed site assets too — keep them in
  # sync on a site-only redeploy (e.g. install-location or copy changes).
  aws s3 cp "${PROJECT_ROOT}/install.sh" "s3://${BUCKET}/install.sh" \
    --content-type "text/x-shellscript"
  if [[ -f "${PROJECT_ROOT}/install-daemon.sh" ]]; then
    aws s3 cp "${PROJECT_ROOT}/install-daemon.sh" "s3://${BUCKET}/install-daemon.sh" \
      --content-type "text/x-shellscript"
  fi

  for asset in favicon.ico favicon-32x32.png apple-touch-icon.png icon-192.png hop-icon.png; do
    if [[ -f "${PROJECT_ROOT}/site/${asset}" ]]; then
      content_type="image/png"
      [[ "${asset}" == *.ico ]] && content_type="image/x-icon"
      aws s3 cp "${PROJECT_ROOT}/site/${asset}" "s3://${BUCKET}/${asset}" \
        --content-type "${content_type}"
    fi
  done

  echo "==> Invalidating CloudFront cache"
  aws cloudfront create-invalidation \
    --distribution-id "${CF_DISTRIBUTION_ID}" \
    --paths "/" $(site_paths) "/shared.css" "/shared.js" \
      "/install.sh" "/install-daemon.sh" \
      "/favicon.ico" "/favicon-32x32.png" \
      "/apple-touch-icon.png" "/icon-192.png" "/hop-icon.png" \
    --output text --query 'Invalidation.Id'

  echo ""
  echo "============================================"
  echo "  Site deployed for hop v${VERSION}"
  echo "============================================"
  exit 0
fi

# --- Tests -------------------------------------------------------------------

echo "==> Running tests"
cargo test --quiet

# --- Resilience soak gate (WS5) ----------------------------------------------
# A release must not ship a warren that regresses recovery. Run the chaos soak
# (tests/e2e/soak-resilience.sh) and ABORT the release if any perturbation
# exceeds its per-scenario SLA budget (founder_restart ≤ FOUNDER_BUDGET_MS, the
# rest ≤ WARM_BUDGET_MS). A green soak is the contract for the "it just works
# and is reliable" free tier. Set SKIP_SOAK=1 to bypass (e.g. Docker
# unavailable) — only deliberately.
if [[ "${SKIP_SOAK:-0}" != "1" ]]; then
  echo "==> Running resilience soak gate (SOAK_CYCLES=${SOAK_CYCLES:-20})"
  if ! command -v docker &>/dev/null; then
    echo "Error: docker not found — the soak gate needs Docker (Colima on macOS)."
    echo "       Start Docker, or set SKIP_SOAK=1 to bypass (not recommended)."
    exit 1
  fi
  if ! SOAK_CYCLES="${SOAK_CYCLES:-20}" "${PROJECT_ROOT}/tests/e2e/soak-resilience.sh"; then
    echo "Error: resilience soak FAILED — recovery exceeded SLA budget. Release aborted."
    echo "       See tests/e2e/sla-results.md for the per-scenario breakdown."
    exit 1
  fi
else
  echo "==> SKIP_SOAK=1 — skipping resilience soak gate (NOT recommended)"
fi

# --- First-run acceptance gate -----------------------------------------------
# The free tier's promise is "each core job in ~60s, no docs." Run the first-run
# acceptance suite (tests/e2e/first-run.sh: reach-a-machine, private-network,
# expose, + the VPN-free client guard) and ABORT the release if any core job
# breaks or exceeds its step/time budget. The tutorials ARE the tests. Set
# SKIP_FIRSTRUN=1 to bypass (e.g. Docker unavailable) — only deliberately.
if [[ "${SKIP_FIRSTRUN:-0}" != "1" ]]; then
  echo "==> Running first-run acceptance gate"
  if ! command -v docker &>/dev/null; then
    echo "Error: docker not found — the first-run gate needs Docker (Colima on macOS)."
    echo "       Start Docker, or set SKIP_FIRSTRUN=1 to bypass (not recommended)."
    exit 1
  fi
  if ! "${PROJECT_ROOT}/tests/e2e/first-run.sh"; then
    echo "Error: first-run acceptance FAILED — a core job broke or exceeded budget. Release aborted."
    echo "       See tests/e2e/first-run-results.md for the per-job breakdown."
    exit 1
  fi
else
  echo "==> SKIP_FIRSTRUN=1 — skipping first-run acceptance gate (NOT recommended)"
fi

# --- Session-resilience gate (session-recovery-parity) -----------------------
# Interactive sessions must recover on the VPN's heels — SRT budgets per
# perturbation, including the zombie-path (silent stall) detection proof.
# Set SKIP_SESSION=1 to bypass (e.g. Docker unavailable) — only deliberately.
if [[ "${SKIP_SESSION:-0}" != "1" ]]; then
  echo "==> Running session-resilience gate (CYCLES=${CYCLES:-6})"
  if ! "${PROJECT_ROOT}/tests/e2e/session-resilience.sh"; then
    echo "Error: session resilience FAILED — session recovery exceeded SLA. Release aborted."
    echo "       See tests/e2e/session-results.md for the per-perturbation breakdown."
    exit 1
  fi
else
  echo "==> SKIP_SESSION=1 — skipping session-resilience gate (NOT recommended)"
fi

# --- Google OAuth client (build-time injection) ------------------------------
# `hop auth gmail` needs a client baked in at compile time (build.rs reads
# these and stores them obfuscated). A release built without them still works
# for everything else — gmail auth just tells the user to bring their own — but
# it is almost certainly not what you meant, so say so loudly.
if [[ -z "${HOP_GOOGLE_CLIENT_ID:-}" || -z "${HOP_GOOGLE_CLIENT_SECRET:-}" ]]; then
  echo "==> WARNING: HOP_GOOGLE_CLIENT_ID/SECRET unset — this release will ship"
  echo "             WITHOUT a default Google OAuth client (\`hop auth gmail\`"
  echo "             will ask users to supply their own)."
fi

# --- Build (parallel) --------------------------------------------------------

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

BUILD_LOG_DIR=$(mktemp -d)
BUILD_PIDS=()

# Helper: run a build in the background, log output, track PID
start_build() {
  local label="$1"
  shift
  local logfile="${BUILD_LOG_DIR}/${label}.log"
  echo "==> Starting: ${label}"
  ("$@") > "${logfile}" 2>&1 &
  BUILD_PIDS+=("$!:${label}:${logfile}")
}

# macOS targets (native cargo, full LTO)
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  case "${target}" in
    aarch64-apple-darwin) name="hop-darwin-arm64" ;;
    x86_64-apple-darwin)  name="hop-darwin-x86_64" ;;
  esac
  start_build "${name}" bash -c "
    cargo build --release --target '${target}' --manifest-path '${PROJECT_ROOT}/Cargo.toml' -p hop-cli \
    && strip '${PROJECT_ROOT}/target/${target}/release/hop' \
    && cp '${PROJECT_ROOT}/target/${target}/release/hop' '${DIST_DIR}/${name}'
  "
done

# Linux aarch64: native arm64 Docker build (no QEMU emulation)
start_build "hop-linux-arm64" bash -c "
  docker run --rm \
    -v '${PROJECT_ROOT}:/build' \
    -v '${HOME}/.cargo/registry:/usr/local/cargo/registry' \
    -v '${HOME}/.cargo/git:/usr/local/cargo/git' \
    hop-cross-aarch64-musl \
    cargo build --profile release-cross --target aarch64-unknown-linux-musl \
      --manifest-path /build/Cargo.toml -p hop-cli \
  && cp '${PROJECT_ROOT}/target/aarch64-unknown-linux-musl/release-cross/hop' '${DIST_DIR}/hop-linux-arm64'
"

# Linux x86_64 + armv7: cross under QEMU.
# Uses standard --release profile (not release-cross) because QEMU segfaults
# on aws-lc-sys assembly under thin LTO rebuilds. Full LTO is single-threaded
# but stable under emulation. These run sequentially to avoid resource contention.
start_build "hop-linux-qemu" bash -c "
  echo 'Building x86_64-unknown-linux-musl...' \
  && AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target x86_64-unknown-linux-musl \
    --manifest-path '${PROJECT_ROOT}/Cargo.toml' -p hop-cli \
  && cp '${PROJECT_ROOT}/target/x86_64-unknown-linux-musl/release/hop' '${DIST_DIR}/hop-linux-x86_64' \
  && echo 'Building armv7-unknown-linux-musleabihf...' \
  && AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target armv7-unknown-linux-musleabihf \
    --manifest-path '${PROJECT_ROOT}/Cargo.toml' -p hop-cli \
  && cp '${PROJECT_ROOT}/target/armv7-unknown-linux-musleabihf/release/hop' '${DIST_DIR}/hop-linux-armv7'
"

# Wait for all builds, report failures
echo "==> Waiting for all builds to complete..."
FAILED=0
for entry in "${BUILD_PIDS[@]}"; do
  IFS=':' read -r pid label logfile <<< "${entry}"
  if wait "${pid}"; then
    echo "  ✓ ${label}"
  else
    echo "  ✗ ${label} FAILED (see ${logfile})"
    tail -20 "${logfile}"
    echo ""
    FAILED=1
  fi
done

if [[ "${FAILED}" -ne 0 ]]; then
  echo "Error: One or more builds failed. Logs in ${BUILD_LOG_DIR}/"
  exit 1
fi

rm -rf "${BUILD_LOG_DIR}"

# --- Compress Linux binaries with UPX ----------------------------------------
# UPX shrinks the static-musl Linux binaries ~72-76% (e.g. ~30MB -> ~8MB) for a
# much smaller download. The daemon decompresses once at launch (negligible); a
# CLI invocation pays a small one-time decompress. Run BEFORE checksums/signing
# so the .sha256/.sig cover the PACKED file install.sh actually downloads.
#
# Done inside Docker (alpine + upx) rather than depending on a host upx — UPX
# rewrites the ELF based on its own arch header, so an arm64 container packs the
# x86_64/armv7 binaries fine. Linux only: macOS Mach-O + UPX trips Gatekeeper/
# AMFI, and macOS download size is handled by per-arch (non-universal) .pkgs.
# `upx -t` self-tests each packed binary and FAILS the release if a pack is
# broken. NOTE: armv7 can't be exec-tested in CI (no 32-bit-ARM emulation) — it's
# non-PIE static like arm64 (validated); the -t gate catches structural breakage,
# but smoke-test it on real hardware.
echo "==> Compressing Linux binaries with UPX (via Docker)"
docker run --rm -v "${DIST_DIR}:/dist" alpine:latest sh -c '
  set -e
  apk add --no-cache upx >/dev/null 2>&1
  for b in hop-linux-arm64 hop-linux-x86_64 hop-linux-armv7; do
    f="/dist/${b}"
    [ -f "${f}" ] || { echo "Error: ${f} missing before UPX"; exit 1; }
    before=$(wc -c < "${f}")
    upx --best --lzma "${f}" >/dev/null 2>&1 || { echo "Error: upx failed to pack ${b}"; exit 1; }
    upx -t "${f}" >/dev/null 2>&1 || { echo "Error: upx -t failed for ${b} (broken pack)"; exit 1; }
    after=$(wc -c < "${f}")
    echo "  ${b}: $((before / 1024 / 1024))MB -> $((after / 1024 / 1024))MB"
  done
' || { echo "Error: UPX compression step failed"; exit 1; }

# --- Checksums ---------------------------------------------------------------

echo "==> Generating checksums"
cd "${DIST_DIR}"
for f in hop-*; do
  shasum -a 256 "${f}" | awk '{print $1}' > "${f}.sha256"
done
cd "${PROJECT_ROOT}"

# --- Sign artifacts (security-audit H9) --------------------------------------
# Produce a detached `openssl dgst -sha256` signature next to each binary;
# install.sh verifies these against the public key embedded in it.
#
# FAIL-CLOSED: once install.sh carries an embedded pubkey, install.sh REQUIRES
# signatures — an unsigned release would break every install. So: default the
# key from ~/.hop-signing, and hard-abort if the pubkey is embedded but no
# private key is available.
if [[ -z "${HOP_SIGNING_KEY:-}" && -f "${HOME}/.hop-signing/hop-release-private.pem" ]]; then
  HOP_SIGNING_KEY="${HOME}/.hop-signing/hop-release-private.pem"
fi
if grep -q -- "-----BEGIN PUBLIC KEY-----" "${PROJECT_ROOT}/install.sh" \
   && [[ -z "${HOP_SIGNING_KEY:-}" ]]; then
  echo "Error: install.sh embeds a release pubkey, so releases MUST be signed." >&2
  echo "       Set HOP_SIGNING_KEY or restore ~/.hop-signing/hop-release-private.pem" >&2
  exit 1
fi
if [[ -n "${HOP_SIGNING_KEY:-}" ]]; then
  if [[ ! -f "${HOP_SIGNING_KEY}" ]]; then
    echo "Error: HOP_SIGNING_KEY=${HOP_SIGNING_KEY} not found" >&2
    exit 1
  fi
  echo "==> Signing artifacts with ${HOP_SIGNING_KEY}"
  cd "${DIST_DIR}"
  for f in hop-*; do
    case "${f}" in *.sha256|*.sig) continue ;; esac
    openssl dgst -sha256 -sign "${HOP_SIGNING_KEY}" -out "${f}.sig" "${f}"
    # Fail the release if our own signature doesn't verify (catches a bad key).
    pub="$(mktemp)"; openssl rsa -in "${HOP_SIGNING_KEY}" -pubout -out "${pub}" 2>/dev/null
    openssl dgst -sha256 -verify "${pub}" -signature "${f}.sig" "${f}" >/dev/null \
      || { echo "Error: self-verify failed for ${f}" >&2; exit 1; }
    rm -f "${pub}"
  done
  cd "${PROJECT_ROOT}"
else
  echo "==> HOP_SIGNING_KEY unset — unsigned release (install.sh verifies checksum only)"
fi

# --- macOS per-arch .pkg installers ------------------------------------------
# Per-arch, not universal: a universal .pkg fuses both Mac slices (~2x size,
# half of it dead weight on any given machine). Each per-arch .pkg ships only the
# slice that Mac runs (~half the download — e.g. 21MB universal -> 10MB arm64).
# build-pkg.sh wipes its staging dir on each call, so build + upload each one in
# the same iteration before the next build clobbers it.
for pkgarch in arm64 x86_64; do
  # Apple signing/notarization is env-gated in build-pkg.sh and inherited from
  # this environment. Warn loudly when absent: a .pkg downloaded via a browser
  # is Gatekeeper-blocked unless signed AND notarized. (curl|bash installs are
  # unaffected — curl sets no quarantine attribute.) Not a hard failure: the
  # keychain is only reachable from a local/VNC session, so unattended runs
  # legitimately produce unsigned .pkgs.
  if [[ -z "${HOP_INSTALLER_ID:-}" || -z "${HOP_NOTARY_PROFILE:-}" ]]; then
    echo "    WARNING: HOP_INSTALLER_ID/HOP_NOTARY_PROFILE unset — .pkg will be UNSIGNED"
    echo "             (browser-downloaded installers will hit Gatekeeper)"
  fi
  echo "==> Building macOS .pkg (${pkgarch})"
  "${PROJECT_ROOT}/pkg/build-pkg.sh" --arch "${pkgarch}" --binary-dir "${DIST_DIR}"
  PKG_SRC="${PROJECT_ROOT}/target/pkg-staging/output/hop-${VERSION}-${pkgarch}.pkg"
  if [[ ! -f "${PKG_SRC}" ]]; then
    echo "Error: .pkg not found at ${PKG_SRC}"
    exit 1
  fi
  echo "==> Uploading hop-${VERSION}-${pkgarch}.pkg to s3://${BUCKET}/v${VERSION}/"
  aws s3 cp "${PKG_SRC}" "s3://${BUCKET}/v${VERSION}/hop-${VERSION}-${pkgarch}.pkg"
done

# --- Upload to S3 ------------------------------------------------------------

echo "==> Uploading binaries to s3://${BUCKET}/v${VERSION}/"
aws s3 cp "${DIST_DIR}/" "s3://${BUCKET}/v${VERSION}/" \
  --recursive --exclude '*' --include 'hop-*'

echo "==> Uploading latest version marker"
echo -n "${VERSION}" > "${DIST_DIR}/latest"
aws s3 cp "${DIST_DIR}/latest" "s3://${BUCKET}/latest" \
  --content-type "text/plain"

echo "==> Uploading install.sh"
aws s3 cp "${PROJECT_ROOT}/install.sh" "s3://${BUCKET}/install.sh" \
  --content-type "text/plain"

echo "==> Uploading install-daemon.sh"
aws s3 cp "${PROJECT_ROOT}/install-daemon.sh" "s3://${BUCKET}/install-daemon.sh" \
  --content-type "text/plain"

echo "==> Uploading hop.service"
aws s3 cp "${PROJECT_ROOT}/pkg/hop.service" "s3://${BUCKET}/hop.service" \
  --content-type "text/plain"

# --- Website -----------------------------------------------------------------

echo "==> Uploading site"
# Every page in site/, not a hardcoded list: a new page that silently fails to
# deploy looks exactly like a page that deployed fine.
for page in "${PROJECT_ROOT}"/site/*.html; do
  aws s3 cp "${page}" "s3://${BUCKET}/$(basename "${page}")" \
    --content-type "text/html"
done
aws s3 cp "${PROJECT_ROOT}/site/shared.css" "s3://${BUCKET}/shared.css" \
  --content-type "text/css"
aws s3 cp "${PROJECT_ROOT}/site/shared.js" "s3://${BUCKET}/shared.js" \
  --content-type "application/javascript"

echo "==> Uploading site assets"
for asset in favicon.ico favicon-32x32.png apple-touch-icon.png icon-192.png hop-icon.png; do
  if [[ -f "${PROJECT_ROOT}/site/${asset}" ]]; then
    content_type="image/png"
    [[ "${asset}" == *.ico ]] && content_type="image/x-icon"
    aws s3 cp "${PROJECT_ROOT}/site/${asset}" "s3://${BUCKET}/${asset}" \
      --content-type "${content_type}"
  fi
done

# --- Git tag -----------------------------------------------------------------

echo "==> Tagging v${VERSION}"
if git -C "${PROJECT_ROOT}" rev-parse "v${VERSION}" &>/dev/null; then
  echo "    Tag v${VERSION} already exists, skipping"
else
  git -C "${PROJECT_ROOT}" tag "v${VERSION}"
fi

echo "==> Pushing to origin (with tags)"
git -C "${PROJECT_ROOT}" push
git -C "${PROJECT_ROOT}" push --tags

# --- Public GitHub release ---------------------------------------------------
# Mirror the artifacts onto the public repo's Releases page. The CDN stays the
# canonical install path (install.sh points there); this makes the release
# visible/downloadable to anyone browsing GitHub, which is where an
# open-source project's users actually look.
#
# Set HOP_PUBLIC_REPO=owner/name to enable; unset → skipped. Non-fatal: a
# GitHub hiccup must not fail a release whose artifacts are already live on
# the CDN. Requires `gh auth login`.
PUBLIC_REPO="${HOP_PUBLIC_REPO:-Keikai-Inc/wirehop}"
if [[ -n "${PUBLIC_REPO}" ]] && command -v gh &>/dev/null; then
  echo "==> Publishing GitHub release to ${PUBLIC_REPO}"
  if gh release view "v${VERSION}" --repo "${PUBLIC_REPO}" &>/dev/null; then
    echo "    Release v${VERSION} already exists — uploading assets (clobber)"
    gh release upload "v${VERSION}" "${DIST_DIR}"/hop-* --repo "${PUBLIC_REPO}" --clobber \
      || echo "    WARNING: asset upload failed (CDN artifacts are unaffected)"
  else
    gh release create "v${VERSION}" "${DIST_DIR}"/hop-* \
      --repo "${PUBLIC_REPO}" \
      --title "WireHop v${VERSION}" \
      --notes "WireHop v${VERSION} — single binary \`hop\`.

Install (verifies SHA-256 **and** an RSA signature against the key embedded in \`install.sh\`):

\`\`\`bash
curl -fsSL https://hop.keikai.ai/install.sh | bash
\`\`\`

Attached: per-arch binaries for macOS/Linux (x86_64, arm64, armv7) with \`.sha256\` and \`.sig\` sidecars, plus macOS \`.pkg\` installers." \
      || echo "    WARNING: GitHub release creation failed (CDN artifacts are unaffected)"
  fi
else
  echo "==> GitHub release skipped (HOP_PUBLIC_REPO unset or gh not installed)"
fi

# --- CloudFront invalidation ------------------------------------------------

echo "==> Invalidating CloudFront cache"
aws cloudfront create-invalidation \
  --distribution-id "${CF_DISTRIBUTION_ID}" \
  --paths "/" $(site_paths) "/shared.css" "/shared.js" \
    "/latest" "/install.sh" "/install-daemon.sh" "/hop.service" \
    "/favicon.ico" "/favicon-32x32.png" "/apple-touch-icon.png" \
    "/icon-192.png" "/hop-icon.png" "/v${VERSION}/*" \
  --output text --query 'Invalidation.Id'

# --- Done --------------------------------------------------------------------

echo ""
echo "============================================"
echo "  Released hop v${VERSION}"
echo "============================================"
echo ""
echo "Binaries:"
ls -lh "${DIST_DIR}"/hop-*
echo ""
echo "Packages (per-arch):"
for pkgarch in arm64 x86_64; do
  echo "  s3://${BUCKET}/v${VERSION}/hop-${VERSION}-${pkgarch}.pkg"
done
echo ""
echo "CDN: https://hop.keikai.ai"
echo "Install: curl -fsSL https://hop.keikai.ai/install.sh | bash"
