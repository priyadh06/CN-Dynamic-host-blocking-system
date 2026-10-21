#!/usr/bin/env python3
"""Suggest a detection threshold from a BASELINE run.
Usage: python3 evaluation/calibrate.py results/flow_stats.csv
Run the baseline scenario first (normal + abnormal traffic, controller in baseline mode),
then run this. It prints the packet rate seen for each host and a threshold halfway
between the busiest normal host and the attacker."""
import csv, statistics, sys

path = sys.argv[1] if len(sys.argv) > 1 else "results/flow_stats.csv"
rates = {}
with open(path) as f:
    for r in csv.DictReader(f):
        rates.setdefault(r["ip"], []).append(float(r["pps"]))
print("%-10s %8s %8s %8s" % ("host", "median*", "max", "samples"))
for ip in sorted(rates):
    active = [x for x in rates[ip] if x > 0] or [0]
    print("%-10s %8.1f %8.1f %8d" % (ip, statistics.median(active), max(rates[ip]), len(rates[ip])))
print("(*median of non-zero windows; 10.0.0.1 is the server, ignored)")
normal = [max(v) for ip, v in rates.items() if ip not in ("10.0.0.1", "10.0.0.4")]
att = rates.get("10.0.0.4")
if normal and att:
    att_med = statistics.median([x for x in att if x > 0] or [0])
    hi_norm = max(normal)
    if att_med > hi_norm:
        print("\nSuggested DHBS_THRESHOLD_PPS = %.0f   (busiest normal %.1f, attacker typical %.1f)"
              % ((hi_norm + att_med) / 2, hi_norm, att_med))
    else:
        print("\nAttacker is not clearly above normal hosts - run a longer/faster attack.")
