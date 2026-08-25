#!/bin/bash
# uninstall.sh — Remove hop binary, LaunchDaemon, and package receipt.
# Usage: sudo bash pkg/uninstall.sh

set -e

BINARY="/usr/local/bin/hop"
PKG_ID="com.hop.pkg"

echo "Uninstalling hop..."

# Stop the system daemon
echo "Stopping daemon..."
launchctl bootout "system/com.hop.daemon" 2>/dev/null || true

# Also stop legacy LaunchAgent if present
CURRENT_UID=$(id -u "${SUDO_USER:-$USER}")
launchctl bootout "gui/$CURRENT_UID/com.hop.agent" 2>/dev/null || true

# Remove files
echo "Removing binary..."
rm -f "$BINARY"

echo "Removing LaunchDaemon plist..."
rm -f "/Library/LaunchDaemons/com.hop.daemon.plist"

echo "Removing legacy LaunchAgent plist (if present)..."
rm -f "/Library/LaunchAgents/com.hop.agent.plist"

# Forget the package receipt
echo "Removing package receipt..."
pkgutil --forget "$PKG_ID" 2>/dev/null || true

echo ""
echo "Hop has been uninstalled."
echo ""
echo "Your configuration has been preserved at:"
echo "  /Library/Application Support/hop/"
echo "To remove it manually:  sudo rm -rf '/Library/Application Support/hop/'"
