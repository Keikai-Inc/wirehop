#!/bin/bash
# uninstall.sh — Remove hop binary, LaunchAgent, and package receipt.
# Usage: sudo bash pkg/uninstall.sh

set -e

LABEL="com.hop.agent"
PLIST="/Library/LaunchAgents/com.hop.agent.plist"
BINARY="/usr/local/bin/hop"
PKG_ID="com.hop.pkg"

echo "Uninstalling hop..."

# Stop the daemon for the current user
CURRENT_UID=$(id -u)
echo "Stopping daemon..."
launchctl bootout "gui/$CURRENT_UID/$LABEL" 2>/dev/null || true

# Remove files
echo "Removing binary..."
rm -f "$BINARY"

echo "Removing LaunchAgent plist..."
rm -f "$PLIST"

# Forget the package receipt
echo "Removing package receipt..."
pkgutil --forget "$PKG_ID" 2>/dev/null || true

echo ""
echo "Hop has been uninstalled."
echo ""
echo "Your configuration (~/.config/hop/) has been preserved."
echo "To remove it manually:  rm -rf ~/.config/hop/"
