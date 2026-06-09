#!/usr/bin/env bash
# Generate the hop release signing keypair (security-audit H9).
#
# Run ONCE. Store the private key offline/secret; embed the PUBLIC key in
# install.sh (HOP_PUBKEY) and set HOP_SIGNING_KEY=<path to private key> when
# running scripts/release.sh so artifacts are signed.
#
# RSA (not ed25519) on purpose: `openssl dgst -sha256 -sign/-verify` works on
# both OpenSSL (Linux) and the LibreSSL that ships on macOS, so install.sh can
# verify with the stock `openssl` everywhere — no extra dependency to install.
set -euo pipefail

OUT_DIR="${1:-$HOME/.hop-signing}"
PRIV="${OUT_DIR}/hop-release-private.pem"
PUB="${OUT_DIR}/hop-release-public.pem"

if [[ -e "${PRIV}" ]]; then
  echo "Refusing to overwrite existing private key at ${PRIV}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
chmod 700 "${OUT_DIR}"

echo "==> Generating RSA-3072 release signing key in ${OUT_DIR}"
openssl genrsa -out "${PRIV}" 3072 2>/dev/null
chmod 600 "${PRIV}"
openssl rsa -in "${PRIV}" -pubout -out "${PUB}" 2>/dev/null

echo ""
echo "Private key (KEEP SECRET, store offline): ${PRIV}"
echo "Public key:                               ${PUB}"
echo ""
echo "Next steps:"
echo "  1. Paste the public key below into install.sh as HOP_PUBKEY (between the"
echo "     -----BEGIN PUBLIC KEY----- / -----END PUBLIC KEY----- markers)."
echo "  2. Run releases with:  HOP_SIGNING_KEY=${PRIV} ./scripts/release.sh <version>"
echo ""
echo "----- copy the public key below into install.sh HOP_PUBKEY -----"
cat "${PUB}"
echo "----------------------------------------------------------------"
