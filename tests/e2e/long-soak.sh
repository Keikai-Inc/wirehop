#!/usr/bin/env bash
# long-soak.sh — hours of randomized faults against ONE long-lived founder/member
# pair, judged on what only shows up over time (docs/technical/self-healing.md,
# Phase 4): every recovery within its budget with no manual step, no stray user
# agent, no crash-loop fallback, and no steady memory climb on either node.
#
# Built on session-resilience.sh (its containers live for the whole run): random
# perturbation order, CYCLES derived from SOAK_HOURS (~75 s per cycle on average,
# including each perturbation's own outage).
#
# Usage: SOAK_HOURS=24 ./tests/e2e/long-soak.sh   (REBUILD=1 to rebuild first)
# The memory-leak check needs >= 3 h of samples to judge, so runs under 3 h only
# report the trend. Intended for a nightly or weekly run, not for every merge.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOURS="${SOAK_HOURS:-1}"
CYCLES=$(python3 -c "print(max(7, int(float('$HOURS') * 3600 / 75)))")
echo "long soak: ${HOURS} h ≈ ${CYCLES} randomized cycles"
exec env CYCLES="$CYCLES" SOAK_RANDOM=1 SOAK_HEALTH=1 \
  SESS_ARTIFACT="$SCRIPT_DIR/long-soak-results.md" "$SCRIPT_DIR/session-resilience.sh"
