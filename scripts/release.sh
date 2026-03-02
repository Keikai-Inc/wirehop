#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUCKET="hop-releases"
DIST_DIR="${PROJECT_ROOT}/target/release-dist"

# Extract version from workspace Cargo.toml
VERSION=$(grep -m1 '^version' "${PROJECT_ROOT}/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')
echo "==> Releasing hop v${VERSION}"

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

# --- macOS targets (native cargo) -------------------------------------------

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

# --- Linux targets (cross) --------------------------------------------------

for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
  echo "==> Building ${target} (via cross)"
  AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release --target "${target}" --manifest-path "${PROJECT_ROOT}/Cargo.toml" -p hop-cli

  bin="${PROJECT_ROOT}/target/${target}/release/hop"

  case "${target}" in
    x86_64-unknown-linux-gnu)  name="hop-linux-x86_64" ;;
    aarch64-unknown-linux-gnu) name="hop-linux-arm64" ;;
  esac

  cp "${bin}" "${DIST_DIR}/${name}"
done

# --- Checksums ---------------------------------------------------------------

echo "==> Generating checksums"
cd "${DIST_DIR}"
for f in hop-*; do
  shasum -a 256 "${f}" | awk '{print $1}' > "${f}.sha256"
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

# --- CloudFront invalidation ------------------------------------------------

if [[ -n "${HOP_CF_DISTRIBUTION_ID:-}" ]]; then
  echo "==> Invalidating CloudFront cache"
  aws cloudfront create-invalidation \
    --distribution-id "${HOP_CF_DISTRIBUTION_ID}" \
    --paths "/latest" "/install.sh" "/v${VERSION}/*"
else
  echo "==> Skipping CloudFront invalidation (HOP_CF_DISTRIBUTION_ID not set)"
fi

echo ""
echo "============================================"
echo " Released hop v${VERSION}"
echo "============================================"
ls -lh "${DIST_DIR}"/hop-*
