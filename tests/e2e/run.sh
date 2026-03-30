#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Ensure cleanup runs on exit, interrupt, or error
cleanup() {
    echo ""
    echo "Cleaning up..."
    cd "$SCRIPT_DIR"
    docker compose down -v --rmi local 2>/dev/null || true
    rm -f "$SCRIPT_DIR/hop"
}
trap cleanup EXIT

echo "hop E2E Test Runner"
echo "==================="
echo ""

# 1. Build aarch64 binary (skip if exists and REBUILD!=1)
TARGET="target/aarch64-unknown-linux-gnu/release/hop"
if [ ! -f "$PROJECT_ROOT/$TARGET" ] || [ "${REBUILD:-0}" = "1" ]; then
    echo "Building hop for aarch64-unknown-linux-gnu..."
    cd "$PROJECT_ROOT"
    AWS_LC_SYS_CMAKE_BUILDER=1 cross build --release \
        --target aarch64-unknown-linux-gnu -p hop-cli
    echo "Build complete."
else
    echo "Using existing binary: $TARGET"
fi
echo ""

# 2. Copy binary to test build context
cp "$PROJECT_ROOT/$TARGET" "$SCRIPT_DIR/hop"

# 3. Clean up any stale containers/volumes from previous runs
cd "$SCRIPT_DIR"
docker compose down -v 2>/dev/null || true

# 4. Build Docker image + run tests
echo "Building Docker image..."
DOCKER_BUILDKIT=0 docker compose build

echo "Starting test containers..."
echo ""
docker compose up --abort-on-container-exit --exit-code-from hop-test \
    2>&1 | tee /tmp/hop-e2e.log
EXIT_CODE=${PIPESTATUS[0]}

# cleanup runs automatically via EXIT trap

if [ "$EXIT_CODE" -eq 0 ]; then
    echo "E2E tests passed."
else
    echo "E2E tests FAILED. Full log: /tmp/hop-e2e.log"
fi

exit $EXIT_CODE
