#!/usr/bin/env bash
set -euo pipefail

echo "[${HOP_HOST_NAME}] Starting hop host..."

# Create config directory
mkdir -p "$HOP_CONFIG_DIR"

# Start hop host in background
hop --config "$HOP_CONFIG_DIR" host --quiet &
HOP_PID=$!
echo "[${HOP_HOST_NAME}] hop host PID: $HOP_PID"

# Wait for creator_invite to appear (max 120s)
# endpoint.online().await can take 10-30s in Docker to connect to relay
INVITE_FILE="$HOP_CONFIG_DIR/creator_invite"
ELAPSED=0
while [ ! -f "$INVITE_FILE" ]; do
    if ! kill -0 "$HOP_PID" 2>/dev/null; then
        echo "[${HOP_HOST_NAME}] ERROR: hop host process died"
        exit 1
    fi
    if [ "$ELAPSED" -ge 120 ]; then
        echo "[${HOP_HOST_NAME}] ERROR: timed out waiting for creator_invite (120s)"
        exit 1
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done
echo "[${HOP_HOST_NAME}] creator_invite appeared after ${ELAPSED}s"

# Copy creator invite to shared volume
cp "$INVITE_FILE" "$HOP_INVITE_FILE"
echo "[${HOP_HOST_NAME}] Invite written to $HOP_INVITE_FILE"

# Save node ID to shared volume
hop --config "$HOP_CONFIG_DIR" id > "${HOP_INVITE_FILE}.nodeid"
echo "[${HOP_HOST_NAME}] Node ID: $(cat "${HOP_INVITE_FILE}.nodeid")"

# Signal readiness
touch "$HOP_READY_FILE"
echo "[${HOP_HOST_NAME}] Ready"

# Keep running until hop host exits
wait $HOP_PID
