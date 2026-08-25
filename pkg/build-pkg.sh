#!/bin/bash
# build-pkg.sh — Build the hop .pkg installer for macOS.
#
# Usage:
#   ./pkg/build-pkg.sh                    # Build for native architecture
#   ./pkg/build-pkg.sh --arch arm64       # Build for Apple Silicon
#   ./pkg/build-pkg.sh --arch x86_64      # Build for Intel
#   ./pkg/build-pkg.sh --arch universal   # Build universal binary (arm64 + x86_64)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG_ID="com.hop.pkg"
ARCH="native"
BINARY_DIR=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --binary-dir)
            BINARY_DIR="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [--arch native|arm64|x86_64|universal] [--binary-dir <path>]"
            exit 1
            ;;
    esac
done

# Extract version from workspace Cargo.toml
VERSION=$(grep -m1 '^version' "$PROJECT_ROOT/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')
if [ -z "$VERSION" ]; then
    echo "Error: Could not extract version from Cargo.toml"
    exit 1
fi
echo "Building hop v${VERSION} (arch: ${ARCH})"

# Set up staging directories
STAGING="$PROJECT_ROOT/target/pkg-staging"
PAYLOAD="$STAGING/payload"
SCRIPTS="$STAGING/scripts"
RESOURCES="$STAGING/resources"
OUTPUT="$STAGING/output"

rm -rf "$STAGING"
mkdir -p "$PAYLOAD/usr/local/bin"
mkdir -p "$PAYLOAD/Library/LaunchDaemons"
mkdir -p "$SCRIPTS"
mkdir -p "$RESOURCES"
mkdir -p "$OUTPUT"

# Build the binary
cd "$PROJECT_ROOT"

build_for_target() {
    local target="$1"
    echo "Building for $target..." >&2
    cargo build --release --target "$target" -p hop-cli
    local bin="$PROJECT_ROOT/target/$target/release/hop"
    if [ ! -f "$bin" ]; then
        echo "Error: Binary not found at $bin" >&2
        exit 1
    fi
    strip "$bin"
    echo "$bin"
}

# Arch suffix for the output .pkg filename (empty for native/universal so the
# canonical `hop-<version>.pkg` name is preserved; per-arch builds get a suffix).
PKG_SUFFIX=""

case "$ARCH" in
    native)
        echo "Building for native architecture..."
        cargo build --release -p hop-cli
        BINARY="$PROJECT_ROOT/target/release/hop"
        strip "$BINARY"
        ;;
    arm64)
        # Prefer the release-built, already-stripped binary when the pipeline
        # passes --binary-dir; otherwise build from source. Per-arch .pkgs are
        # ~half the size of the universal (one slice, not two) — that's the
        # whole point: ship the slice the user's Mac actually runs.
        if [[ -n "${BINARY_DIR}" && -f "${BINARY_DIR}/hop-darwin-arm64" ]]; then
            BINARY="${BINARY_DIR}/hop-darwin-arm64"
        else
            BINARY=$(build_for_target "aarch64-apple-darwin")
        fi
        PKG_SUFFIX="-arm64"
        ;;
    x86_64)
        if [[ -n "${BINARY_DIR}" && -f "${BINARY_DIR}/hop-darwin-x86_64" ]]; then
            BINARY="${BINARY_DIR}/hop-darwin-x86_64"
        else
            BINARY=$(build_for_target "x86_64-apple-darwin")
        fi
        PKG_SUFFIX="-x86_64"
        ;;
    universal)
        if [[ -n "${BINARY_DIR}" ]]; then
            ARM_BIN="${BINARY_DIR}/hop-darwin-arm64"
            X86_BIN="${BINARY_DIR}/hop-darwin-x86_64"
            for b in "$ARM_BIN" "$X86_BIN"; do
                [[ -f "$b" ]] || { echo "Error: Pre-built binary not found at $b"; exit 1; }
            done
        else
            ARM_BIN=$(build_for_target "aarch64-apple-darwin")
            X86_BIN=$(build_for_target "x86_64-apple-darwin")
        fi
        BINARY="$STAGING/hop-universal"
        echo "Creating universal binary with lipo..."
        lipo -create "$ARM_BIN" "$X86_BIN" -output "$BINARY"
        ;;
    *)
        echo "Error: Invalid architecture '$ARCH'. Use native, arm64, x86_64, or universal."
        exit 1
        ;;
esac

echo "Binary size: $(du -h "$BINARY" | cut -f1)"

# --- Apple code signing (opt-in) --------------------------------------------
# Gatekeeper blocks a browser-downloaded .pkg from an unidentified developer,
# and Sequoia removed the easy right-click bypass — so a public .pkg must be
# signed AND notarized. All three steps are env-gated so an unsigned local
# build still works exactly as before:
#
#   HOP_CODESIGN_ID   "Developer ID Application: … (TEAMID)"  — signs the binary
#   HOP_INSTALLER_ID  "Developer ID Installer: … (TEAMID)"    — signs the .pkg
#   HOP_NOTARY_PROFILE  notarytool keychain profile name      — notarize+staple
#
# NOTE: keychain unlocks are per-security-session on macOS, so these must run
# from a session that can see the login keychain (a local/VNC terminal), not a
# detached SSH/tool context. --options runtime (hardened runtime) is safe here:
# the JS runtime interprets, it does not JIT, so no extra entitlement is needed.
if [[ -n "${HOP_CODESIGN_ID:-}" ]]; then
    echo "Signing binary with: ${HOP_CODESIGN_ID}"
    codesign --force --sign "${HOP_CODESIGN_ID}" --options runtime --timestamp "$BINARY"
    codesign --verify --strict --verbose=1 "$BINARY" || { echo "Error: codesign verify failed"; exit 1; }
else
    echo "HOP_CODESIGN_ID unset — binary NOT signed (Gatekeeper will block a downloaded .pkg)"
fi

# Assemble payload
cp "$BINARY" "$PAYLOAD/usr/local/bin/hop"
cp "$SCRIPT_DIR/com.hop.daemon.plist" "$PAYLOAD/Library/LaunchDaemons/com.hop.daemon.plist"

# Copy install scripts
cp "$SCRIPT_DIR/preinstall" "$SCRIPTS/preinstall"
cp "$SCRIPT_DIR/postinstall" "$SCRIPTS/postinstall"
chmod 755 "$SCRIPTS/preinstall" "$SCRIPTS/postinstall"

# Create distribution.xml
cat > "$STAGING/distribution.xml" << 'DISTXML'
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>Hop</title>
    <options customize="never" require-scripts="false" hostArchitectures="arm64,x86_64"/>
    <domains enable_localSystem="true"/>
    <choices-outline>
        <line choice="default">
            <line choice="com.hop.pkg"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="com.hop.pkg" visible="false">
        <pkg-ref id="com.hop.pkg"/>
    </choice>
    <pkg-ref id="com.hop.pkg" version="VERSION" onConclusion="none">hop-component.pkg</pkg-ref>
</installer-gui-script>
DISTXML

# Substitute version into distribution.xml
sed -i '' "s/VERSION/${VERSION}/" "$STAGING/distribution.xml"

# Create welcome text
cat > "$RESOURCES/welcome.txt" << EOF
Welcome to the Hop installer (v${VERSION}).

This will install:
  - /usr/local/bin/hop (the CLI binary)
  - A LaunchDaemon that runs "hop host" as root at boot

After installation, hop will be available in any new terminal window.
EOF

# Build component package
echo "Building component package..."
pkgbuild \
    --root "$PAYLOAD" \
    --identifier "$PKG_ID" \
    --version "$VERSION" \
    --scripts "$SCRIPTS" \
    "$STAGING/hop-component.pkg"

# Build product archive (the final .pkg)
echo "Building product archive..."
FINAL_PKG="$OUTPUT/hop-${VERSION}${PKG_SUFFIX}.pkg"
if [[ -n "${HOP_INSTALLER_ID:-}" ]]; then
    # productbuild --sign produces the signed archive directly (no separate
    # productsign pass, which would require an unsigned intermediate).
    echo "Signing installer with: ${HOP_INSTALLER_ID}"
    productbuild \
        --distribution "$STAGING/distribution.xml" \
        --resources "$RESOURCES" \
        --package-path "$STAGING" \
        --sign "${HOP_INSTALLER_ID}" \
        --timestamp \
        "$FINAL_PKG"
    pkgutil --check-signature "$FINAL_PKG" >/dev/null \
        || { echo "Error: .pkg signature check failed"; exit 1; }
else
    echo "HOP_INSTALLER_ID unset — .pkg NOT signed"
    productbuild \
        --distribution "$STAGING/distribution.xml" \
        --resources "$RESOURCES" \
        --package-path "$STAGING" \
        "$FINAL_PKG"
fi

# --- Notarize + staple (opt-in) ---------------------------------------------
# Without stapling, Gatekeeper must reach Apple online to validate; a stapled
# ticket makes the .pkg work offline and on first launch. Requires the .pkg to
# be signed with a Developer ID Installer cert (Apple rejects unsigned
# submissions), so this only runs when both are configured.
if [[ -n "${HOP_NOTARY_PROFILE:-}" && -n "${HOP_INSTALLER_ID:-}" ]]; then
    echo "Notarizing (this waits on Apple; typically 1-5 min)..."
    if xcrun notarytool submit "$FINAL_PKG" \
            --keychain-profile "${HOP_NOTARY_PROFILE}" --wait --timeout 30m; then
        xcrun stapler staple "$FINAL_PKG" \
            || { echo "Error: stapling failed"; exit 1; }
        xcrun stapler validate "$FINAL_PKG" \
            || { echo "Error: staple validation failed"; exit 1; }
        echo "Notarized + stapled."
    else
        echo "Error: notarization FAILED — inspect with:"
        echo "  xcrun notarytool log <submission-id> --keychain-profile ${HOP_NOTARY_PROFILE}"
        exit 1
    fi
elif [[ -n "${HOP_NOTARY_PROFILE:-}" ]]; then
    echo "HOP_NOTARY_PROFILE set but HOP_INSTALLER_ID unset — skipping notarization (Apple rejects unsigned submissions)"
fi

# Clean up intermediate files
rm -f "$STAGING/hop-component.pkg"

echo ""
echo "Success! Installer package built:"
echo "  $OUTPUT/hop-${VERSION}${PKG_SUFFIX}.pkg"
echo ""
echo "Install with:"
echo "  sudo installer -pkg $OUTPUT/hop-${VERSION}${PKG_SUFFIX}.pkg -target /"
echo ""
echo "Uninstall with:"
echo "  sudo bash pkg/uninstall.sh"
