#!/usr/bin/env bash
# Usage (third terminal, WHILE mininet is still running): scripts/dump_flows.sh <run_name>
# Saves the switch's OpenFlow table - this is the evidence that the DROP rule exists.
BASE="$(cd "$(dirname "$0")/.." && pwd)"
NAME="${1:?usage: dump_flows.sh <run_name>}"
mkdir -p "$BASE/runs/$NAME"
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | tee "$BASE/runs/$NAME/flows_s1.txt"
