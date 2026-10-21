#!/usr/bin/env bash
# Usage: scripts/save_run.sh <run_name>      e.g. baseline | dynamic | heavy_attack
# Copies the logs of the run that just finished into runs/<run_name>/
set -e
BASE="$(cd "$(dirname "$0")/.." && pwd)"
NAME="${1:?usage: save_run.sh <run_name>}"
DEST="$BASE/runs/$NAME"
mkdir -p "$DEST"
cp "$BASE"/logs/*.log "$DEST"/
cp "$BASE"/results/controller_events.csv "$BASE"/results/flow_stats.csv "$DEST"/ 2>/dev/null || \
  echo "WARNING: controller CSVs not found in $BASE/results (was the DHBS controller running?)"
echo "Saved to $DEST"; ls "$DEST"
