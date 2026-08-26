#!/usr/bin/env bash
# setup-ci-secrets.sh — upload everything the release workflow needs, from the
# machine that already holds the credentials.
#
# Run this on the Mac with the signing certs, in a LOCAL or VNC terminal (the
# keychain is per-security-session, so an SSH shell sees no identities).
#
# Every secret is piped straight from disk or the keychain into `gh secret set`
# via stdin. No value is ever echoed, passed as an argv (visible in `ps`), or
# written to a temp file that outlives the run.
#
# The .p12 export must happen FIRST; this script only uploads. Either:
#
#   A. one bundle straight from the keychain (no GUI navigation) --
#        security find-identity -v      # check what will be included
#        security export -k ~/Library/Keychains/login.keychain-db \
#          -t identities -f pkcs12 -P 'pick-a-password' -o ~/wirehop-certs.p12
#        ./scripts/setup-ci-secrets.sh --identities-p12 ~/wirehop-certs.p12
#
#   B. or two files via Keychain Access (login -> My Certificates -> export
#      each Developer ID cert, SAME password for both) --
#        ./scripts/setup-ci-secrets.sh --app-p12 ~/app.p12 --installer-p12 ~/installer.p12
#
# Run with no cert flags to set only the non-Apple secrets.
# Delete the .p12 files afterwards: they are your signing identity.
set -uo pipefail

REPO="${HOP_PUBLIC_REPO:-Keikai-Inc/wirehop}"
APP_P12="" ; INST_P12="" ; BOTH_P12="" ; ASC_P8="" ; KEY_ID="" ; ISSUER=""
while [ $# -gt 0 ]; do
  case "$1" in
    --app-p12)       APP_P12="$2"; shift 2 ;;
    --installer-p12) INST_P12="$2"; shift 2 ;;
    # One file holding BOTH identities, as `security export` produces.
    --identities-p12) BOTH_P12="$2"; shift 2 ;;
    --asc-p8)        ASC_P8="$2"; shift 2 ;;
    --asc-key-id)    KEY_ID="$2"; shift 2 ;;
    --asc-issuer)    ISSUER="$2"; shift 2 ;;
    --repo)          REPO="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

say()  { printf '\n== %s\n' "$*"; }
ok()   { printf '   set  %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

command -v gh >/dev/null || die "gh CLI not found"
gh auth status >/dev/null 2>&1 || die "run: gh auth login"

# set_secret <NAME>  — value on stdin, never in argv.
set_secret() { gh secret set "$1" --repo "$REPO" >/dev/null && ok "$1"; }

say "Target repository: $REPO"

# ── Apple signing identities ────────────────────────────────────────────────
# A single --identities-p12 stands in for both: the workflow imports the file
# and then selects identities BY NAME, so one bundle containing both is fine.
if [ -n "$BOTH_P12" ]; then APP_P12="$BOTH_P12"; INST_P12="$BOTH_P12"; fi

if [ -n "$APP_P12" ] || [ -n "$INST_P12" ]; then
  if [ ! -f "$APP_P12" ] || [ ! -f "$INST_P12" ]; then
    cat >&2 <<'HOWTO'
ERROR: certificate file(s) not found.

The .p12 export has to happen first; this script only uploads. Two ways:

  A. One command (try this first). Exports every code-signing identity in your
     login keychain into one bundle. Check what that includes first:

       security find-identity -v          # expect the two Developer ID certs

       security export -k ~/Library/Keychains/login.keychain-db \
         -t identities -f pkcs12 -P 'pick-a-password' -o ~/wirehop-certs.p12

     macOS may show an "allow access" prompt per key; click Allow. Then:

       ./scripts/setup-ci-secrets.sh --identities-p12 ~/wirehop-certs.p12

  B. Keychain Access, if you would rather export only the two:
       login -> My Certificates -> select "Developer ID Application: ..."
       -> File -> Export Items -> .p12, then the same for "Developer ID
       Installer: ...". Use the SAME password for both. Then:

       ./scripts/setup-ci-secrets.sh --app-p12 ~/app.p12 --installer-p12 ~/installer.p12

  Delete the .p12 files afterwards: they are your signing identity.
HOWTO
    exit 1
  fi

  say "Apple certificates"
  # Read the export password once, without echo, and verify it actually opens
  # both files before uploading anything. A wrong password here surfaces as an
  # opaque mid-release failure on the runner.
  printf '   .p12 export password: '
  read -rs P12_PASS; echo
  for f in "$APP_P12" "$INST_P12"; do
    openssl pkcs12 -in "$f" -passin pass:"$P12_PASS" -nokeys -legacy >/dev/null 2>&1 \
      || openssl pkcs12 -in "$f" -passin pass:"$P12_PASS" -nokeys >/dev/null 2>&1 \
      || die "password does not open $f"
  done
  echo "   both .p12 files verified"

  base64 -i "$APP_P12"  | set_secret APPLE_CERT_APPLICATION_P12
  base64 -i "$INST_P12" | set_secret APPLE_CERT_INSTALLER_P12
  printf '%s' "$P12_PASS" | set_secret APPLE_CERT_PASSWORD
  unset P12_PASS

  # Identity names must match the keychain strings EXACTLY; a mismatch reads as
  # "no identity found", which looks like a locked keychain and wastes an hour.
  APP_ID="$(security find-identity -v -p codesigning \
            | grep 'Developer ID Application:' | head -1 \
            | sed 's/.*"\(.*\)".*/\1/')"
  INST_ID="$(security find-identity -v \
             | grep 'Developer ID Installer:' | head -1 \
             | sed 's/.*"\(.*\)".*/\1/')"
  [ -n "$APP_ID" ]  || die "no 'Developer ID Application' identity in this keychain session"
  [ -n "$INST_ID" ] || die "no 'Developer ID Installer' identity in this keychain session"
  echo "   application identity: $APP_ID"
  echo "   installer identity:   $INST_ID"
  printf '%s' "$APP_ID"  | set_secret APPLE_SIGN_IDENTITY
  printf '%s' "$INST_ID" | set_secret APPLE_INSTALLER_IDENTITY
  printf '%s' "$(printf '%s' "$APP_ID" | sed 's/.*(\(.*\))/\1/')" | set_secret APPLE_TEAM_ID
else
  say "Apple certificates SKIPPED (pass --app-p12 and --installer-p12)"
fi

# ── Notarization ────────────────────────────────────────────────────────────
say "Notarization"
if [ -n "$ASC_P8" ]; then
  [ -f "$ASC_P8" ] || die "--asc-p8 not found: $ASC_P8"
  [ -n "$KEY_ID" ] && [ -n "$ISSUER" ] || die "--asc-p8 needs --asc-key-id and --asc-issuer"
  base64 -i "$ASC_P8" | set_secret APPLE_API_KEY_P8
  printf '%s' "$KEY_ID" | set_secret APPLE_API_KEY_ID
  printf '%s' "$ISSUER" | set_secret APPLE_API_ISSUER_ID
else
  echo "   No --asc-p8 given; falling back to an app-specific password."
  printf '   Apple ID (email): '
  read -r APPLE_ID
  printf '   app-specific password (xxxx-xxxx-xxxx-xxxx): '
  read -rs APPLE_PW; echo
  [ -n "$APPLE_ID" ] && [ -n "$APPLE_PW" ] || die "both are required"
  printf '%s' "$APPLE_ID" | set_secret APPLE_ID
  printf '%s' "$APPLE_PW" | set_secret APPLE_APP_PASSWORD
  unset APPLE_PW
fi

# ── Release signing key (RSA) ───────────────────────────────────────────────
say "Release signing key"
KEY="${HOP_SIGNING_KEY:-$HOME/.hop-signing/hop-release-private.pem}"
if [ -f "$KEY" ]; then
  openssl rsa -in "$KEY" -noout -check >/dev/null 2>&1 || die "not a valid RSA key: $KEY"
  # install.sh embeds the PUBLIC half and fails closed without a matching
  # signature, so a mismatch here breaks every install. Verify before upload.
  EMBEDDED="$(awk '/-----BEGIN PUBLIC KEY-----/{f=1} f{print} /-----END PUBLIC KEY-----/{if(f)exit}' \
              "$(dirname "$0")/../npm/release-pubkey.pem")"
  DERIVED="$(openssl rsa -in "$KEY" -pubout 2>/dev/null)"
  [ "$EMBEDDED" = "$DERIVED" ] || die "$KEY does not match the published release public key"
  echo "   key matches the published release public key"
  set_secret HOP_SIGNING_KEY_PEM < "$KEY"
else
  echo "   SKIPPED: $KEY not found (set HOP_SIGNING_KEY)"
fi

# ── Build-time OAuth client ─────────────────────────────────────────────────
say "Google OAuth client (build-time injected)"
if [ -n "${HOP_GOOGLE_CLIENT_ID:-}" ] && [ -n "${HOP_GOOGLE_CLIENT_SECRET:-}" ]; then
  printf '%s' "$HOP_GOOGLE_CLIENT_ID"     | set_secret HOP_GOOGLE_CLIENT_ID
  printf '%s' "$HOP_GOOGLE_CLIENT_SECRET" | set_secret HOP_GOOGLE_CLIENT_SECRET
else
  echo "   SKIPPED: export HOP_GOOGLE_CLIENT_ID / HOP_GOOGLE_CLIENT_SECRET first"
  echo "   (without these the release binary ships without \`hop auth gmail\`)"
fi

# ── AWS + CDN ───────────────────────────────────────────────────────────────
say "AWS publish role and CDN"
printf '%s' "${AWS_ROLE_ARN:-arn:aws:iam::064311028681:role/wirehop-github-release}" \
  | set_secret AWS_ROLE_ARN
printf '%s' "${HOP_CF_DISTRIBUTION_ID:-E1SBRBZNSQX4WA}" | set_secret CF_DISTRIBUTION_ID

say "Done"
gh secret list --repo "$REPO"
cat <<'NEXT'

Remaining manual step (once, in the browser):
  Settings -> Environments -> New environment -> name it exactly: release
  Add yourself as a Required reviewer.

  The release workflow pins both the macOS signing job and the publish job to
  that environment, so no signing credential and no AWS role is issued until a
  human approves the run. The IAM trust policy is scoped to
  `repo:<owner>/<repo>:environment:release`, so without the environment the
  AWS step cannot authenticate at all.

Then:  git tag v0.9.34 && git push --tags
NEXT
