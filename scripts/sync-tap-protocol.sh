#!/usr/bin/env bash
# Sync hop-tap-protocol from the private hop-tap repo.
# Usage: ./scripts/sync-tap-protocol.sh [/path/to/hop-tap]
#
# Defaults to ../hop-tap if no path given.

set -euo pipefail

TAP_REPO="${1:-$(dirname "$0")/../../hop-tap}"

if [[ ! -d "$TAP_REPO/crates/hop-tap-protocol" ]]; then
    echo "Error: hop-tap-protocol not found at $TAP_REPO/crates/hop-tap-protocol"
    echo "Usage: $0 [/path/to/hop-tap]"
    exit 1
fi

SRC="$TAP_REPO/crates/hop-tap-protocol/src"
DEST="$(dirname "$0")/../vendor/hop-tap-protocol/src"

echo "Syncing from: $TAP_REPO/crates/hop-tap-protocol/src"
echo "          to: $DEST"

rsync -av --delete "$SRC/" "$DEST/"

# Show version
VERSION=$(grep '^version' "$TAP_REPO/crates/hop-tap-protocol/Cargo.toml" 2>/dev/null | head -1 || echo "unknown")
echo ""
echo "Synced. Source $VERSION"
echo "Remember to update vendor/hop-tap-protocol/Cargo.toml version if needed."
