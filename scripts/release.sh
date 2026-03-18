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
  git -C "${PROJECT_ROOT}" add Cargo.toml
  git -C "${PROJECT_ROOT}" commit -m "Bump version to ${NEW_VERSION}"
fi

# Extract version from workspace Cargo.toml
VERSION=$(grep -m1 '^version' "${PROJECT_ROOT}/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')
echo ""
echo "============================================"
echo "  Releasing hop v${VERSION}"
echo "============================================"
echo ""

# --- Site-only mode ----------------------------------------------------------

if [[ "${SITE_ONLY}" == true ]]; then
  echo "==> Site-only mode — skipping builds"

  echo "==> Uploading site"
  aws s3 cp "${PROJECT_ROOT}/site/index.html" "s3://${BUCKET}/index.html" \
    --content-type "text/html"
  aws s3 cp "${PROJECT_ROOT}/site/fleet.html" "s3://${BUCKET}/fleet.html" \
    --content-type "text/html"
  aws s3 cp "${PROJECT_ROOT}/site/shared.css" "s3://${BUCKET}/shared.css" \
    --content-type "text/css"
  aws s3 cp "${PROJECT_ROOT}/site/shared.js" "s3://${BUCKET}/shared.js" \
    --content-type "application/javascript"

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
    --paths "/" "/index.html" "/fleet.html" "/shared.css" "/shared.js" \
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

# --- Build -------------------------------------------------------------------

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

# macOS targets (native cargo)
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  echo "==> Building ${target}"
  cargo build --release --target "${target}" --manifest-path "${PROJECT_ROOT}/Cargo.toml" -p hop-cli

  bin="${PROJECT_ROOT}/target/${target}/release/hop"
  strip "${bin}"

  case "${target}" in
    aarch64-apple-darwin) name="hop-darwin-arm64" ;;
    x86_64-apple-darwin)  name="hop-darwin-x86_64" ;;
  esac

  cp "${bin}" "${DIST_DIR}/${name}"
done

# Linux targets (cross, static musl)
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf; do
  echo "==> Building ${target} (via cross, static musl)"
  AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target "${target}" --manifest-path "${PROJECT_ROOT}/Cargo.toml" -p hop-cli

  bin="${PROJECT_ROOT}/target/${target}/release/hop"

  case "${target}" in
    x86_64-unknown-linux-musl)         name="hop-linux-x86_64" ;;
    aarch64-unknown-linux-musl)        name="hop-linux-arm64" ;;
    armv7-unknown-linux-musleabihf)    name="hop-linux-armv7" ;;
  esac

  cp "${bin}" "${DIST_DIR}/${name}"
done

# --- Checksums ---------------------------------------------------------------

echo "==> Generating checksums"
cd "${DIST_DIR}"
for f in hop-*; do
  shasum -a 256 "${f}" | awk '{print $1}' > "${f}.sha256"
done
cd "${PROJECT_ROOT}"

# --- macOS .pkg installer ----------------------------------------------------

echo "==> Building macOS universal .pkg"
"${PROJECT_ROOT}/pkg/build-pkg.sh" --arch universal
PKG_PATH="${PROJECT_ROOT}/target/pkg-staging/output/hop-${VERSION}.pkg"
if [[ ! -f "${PKG_PATH}" ]]; then
  echo "Error: .pkg not found at ${PKG_PATH}"
  exit 1
fi

# --- Upload to S3 ------------------------------------------------------------

echo "==> Uploading binaries to s3://${BUCKET}/v${VERSION}/"
aws s3 cp "${DIST_DIR}/" "s3://${BUCKET}/v${VERSION}/" \
  --recursive --exclude '*' --include 'hop-*'

echo "==> Uploading .pkg to s3://${BUCKET}/v${VERSION}/"
aws s3 cp "${PKG_PATH}" "s3://${BUCKET}/v${VERSION}/hop-${VERSION}.pkg"

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
aws s3 cp "${PROJECT_ROOT}/site/index.html" "s3://${BUCKET}/index.html" \
  --content-type "text/html"
aws s3 cp "${PROJECT_ROOT}/site/fleet.html" "s3://${BUCKET}/fleet.html" \
  --content-type "text/html"
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

# --- CloudFront invalidation ------------------------------------------------

echo "==> Invalidating CloudFront cache"
aws cloudfront create-invalidation \
  --distribution-id "${CF_DISTRIBUTION_ID}" \
  --paths "/" "/index.html" "/fleet.html" "/shared.css" "/shared.js" \
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
echo "Package:"
ls -lh "${PKG_PATH}"
echo ""
echo "CDN: https://hop.keik.ai"
echo "Install: curl -fsSL https://hop.keik.ai/install.sh | bash"
