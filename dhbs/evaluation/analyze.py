#!/usr/bin/env python3
"""
DHBS evaluation (Member 3).

Usage
  python3 evaluation/analyze.py runs/baseline runs/dynamic runs/heavy_attack
  python3 evaluation/analyze.py runs/dynamic            (one run is fine too)

Each run folder is created by scripts/save_run.sh and contains:
  server.log  h2_normal.log  h3_normal.log  h4_abnormal.log   (from Member 1)
  controller_events.csv  flow_stats.csv                       (from the controller)

For every run folder it writes
  metrics.json, summary.md, connections_per_second.png, controller_packet_rate.png
With two or more runs it also writes (to --out, default runs/_comparison)
  comparison.png, comparison.md
"""
import argparse
import csv
import glob
import json
import os
import re
import sys
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SERVER_IP = "10.0.0.1"
ATTACKER_IP = "10.0.0.4"
HOSTNAME = {"10.0.0.1": "h1 (server)", "10.0.0.2": "h2", "10.0.0.3": "h3", "10.0.0.4": "h4 (attacker)"}
COLORS = {"10.0.0.2": "#1f77b4", "10.0.0.3": "#2ca02c", "10.0.0.4": "#d62728", "10.0.0.1": "#7f7f7f"}

TS = re.compile(r"^\[(\d\d):(\d\d):(\d\d)\]")
CONN = re.compile(r"connection from (\d+\.\d+\.\d+\.\d+):\d+")
DONE = re.compile(r"DONE: attempts=(\d+) ok=(\d+) fail=(\d+) elapsed=([\d.]+)s")


def sod(h, m, s):
    return int(h) * 3600 + int(m) * 60 + int(s)


def epoch_to_sod(epoch):
    lt = time.localtime(epoch)
    return lt.tm_hour * 3600 + lt.tm_min * 60 + lt.tm_sec + (epoch - int(epoch))


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, errors="replace") as f:
        return [l.rstrip("\n") for l in f]


def parse_traffic_log(path):
    """returns dict(start, end, attempts, ok, fail) or None"""
    lines = read_lines(path)
    if not lines:
        return None
    out = {"start": None, "end": None, "attempts": 0, "ok": 0, "fail": 0, "done": False}
    for l in lines:
        m = TS.match(l)
        if not m:
            continue
        t = sod(*m.groups())
        if out["start"] is None:
            out["start"] = t
        out["end"] = t
        d = DONE.search(l)
        if d:
            out["attempts"], out["ok"], out["fail"] = int(d.group(1)), int(d.group(2)), int(d.group(3))
            out["done"] = True
    return out


def parse_server(path):
    conns = []
    for l in read_lines(path):
        m, c = TS.match(l), CONN.search(l)
        if m and c:
            conns.append((sod(*m.groups()), c.group(1)))
    return conns


def parse_events(path):
    ev = []
    if not os.path.exists(path):
        return ev
    with open(path) as f:
        for r in csv.DictReader(f):
            try:
                ev.append({"t": epoch_to_sod(float(r["epoch"])), "event": r["event"], "ip": r["ip"],
                           "pps": float(r["pps"]), "threshold": float(r["threshold"]), "mode": r["mode"]})
            except (KeyError, ValueError):
                pass
    return ev


def parse_stats(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as f:
        for r in csv.DictReader(f):
            try:
                rows.append({"t": epoch_to_sod(float(r["epoch"])), "ip": r["ip"], "pps": float(r["pps"])})
            except (KeyError, ValueError):
                pass
    return rows


def analyze_run(run):
    name = os.path.basename(os.path.normpath(run))
    traffic = {}
    for p in sorted(glob.glob(os.path.join(run, "h*_*.log"))):
        key = os.path.basename(p)[:-4]
        info = parse_traffic_log(p)
        if info:
            traffic[key] = info
    if not traffic:
        sys.exit("No traffic logs (h*_*.log) found in %s" % run)

    starts = [v["start"] for v in traffic.values()]
    ends = [v["end"] for v in traffic.values()]
    win_lo, win_hi = min(starts) - 1, max(ends) + 2
    attack = traffic.get("h4_abnormal")
    t0 = attack["start"] if attack else min(starts)

    conns = [(t, ip) for t, ip in parse_server(os.path.join(run, "server.log")) if win_lo <= t <= win_hi]
    events = parse_events(os.path.join(run, "controller_events.csv"))
    stats = parse_stats(os.path.join(run, "flow_stats.csv"))

    mode = next((e["mode"] for e in events if e["event"] == "CONTROLLER_START"), "unknown (no controller log)")
    det = next((e for e in events if e["event"] == "DETECTED" and e["ip"] == ATTACKER_IP), None)
    blk = next((e for e in events if e["event"] == "BLOCKED" and e["ip"] == ATTACKER_IP), None)
    false_pos = sorted({e["ip"] for e in events if e["event"] in ("DETECTED", "BLOCKED") and e["ip"] != ATTACKER_IP})

    per_src = {}
    for _, ip in conns:
        per_src[ip] = per_src.get(ip, 0) + 1

    m = {
        "run": name, "controller_mode": mode,
        "attack_start_sod": t0,
        "server_connections_per_source": per_src,
        "attack_connections_accepted": per_src.get(ATTACKER_IP, 0),
        "detection_time_s": round(det["t"] - t0, 2) if det and attack else None,
        "block_time_s": round(blk["t"] - t0, 2) if blk and attack else None,
        "detected_rate_pps": det["pps"] if det else None,
        "threshold_pps": events[0]["threshold"] if events else None,
        "false_positive_hosts": false_pos,
        "legit_hosts": {}, "attacker": None,
    }
    if blk:
        m["attack_connections_after_block"] = sum(1 for t, ip in conns if ip == ATTACKER_IP and t > blk["t"] + 1)
    for key, v in traffic.items():
        rec = {"attempts": v["attempts"], "ok": v["ok"], "fail": v["fail"],
               "success_pct": round(100.0 * v["ok"] / v["attempts"], 1) if v["attempts"] else None}
        if key == "h4_abnormal":
            m["attacker"] = rec
        else:
            m["legit_hosts"][key] = rec
    tot_att = sum(r["attempts"] for r in m["legit_hosts"].values())
    tot_ok = sum(r["ok"] for r in m["legit_hosts"].values())
    m["legit_success_pct"] = round(100.0 * tot_ok / tot_att, 1) if tot_att else None

    with open(os.path.join(run, "metrics.json"), "w") as f:
        json.dump(m, f, indent=2)
    draw_connections(run, name, conns, events, t0, win_hi)
    draw_rate(run, name, stats, events, t0)
    write_summary(run, m)
    return m


def draw_connections(run, name, conns, events, t0, hi):
    fig, ax = plt.subplots(figsize=(9, 4.5))
    span = int(hi - t0) + 2
    for ip in sorted({ip for _, ip in conns}):
        bins = [0] * (span + 3)
        for t, i in conns:
            if i == ip and 0 <= t - t0 + 2 < len(bins):
                bins[int(t - t0 + 2)] += 1
        ax.plot(range(-2, span + 1), bins, marker="o", ms=3, label=HOSTNAME.get(ip, ip), color=COLORS.get(ip))
    for e, style, lab in (("DETECTED", ":", "detected"), ("BLOCKED", "--", "blocked (DROP rule)")):
        ev = next((x for x in events if x["event"] == e and x["ip"] == ATTACKER_IP), None)
        if ev:
            ax.axvline(ev["t"] - t0, color="black", linestyle=style, label=lab)
    ax.set_xlabel("seconds since attack start")
    ax.set_ylabel("connections accepted by server / second")
    ax.set_title("Connections reaching the server per source - %s" % name)
    ax.legend()
    ax.grid(alpha=.3)
    fig.tight_layout()
    fig.savefig(os.path.join(run, "connections_per_second.png"), dpi=150)
    plt.close(fig)


def draw_rate(run, name, stats, events, t0):
    rows = [r for r in stats if r["ip"] != SERVER_IP]
    if not rows:
        return
    fig, ax = plt.subplots(figsize=(9, 4.5))
    for ip in sorted({r["ip"] for r in rows}):
        pts = [(r["t"] - t0, r["pps"]) for r in rows if r["ip"] == ip]
        ax.plot([p[0] for p in pts], [p[1] for p in pts], marker="o", ms=3,
                label=HOSTNAME.get(ip, ip), color=COLORS.get(ip))
    thr = events[0]["threshold"] if events else None
    if thr:
        ax.axhline(thr, color="orange", linestyle="--", label="threshold (%.0f pps)" % thr)
    blk = next((x for x in events if x["event"] == "BLOCKED" and x["ip"] == ATTACKER_IP), None)
    if blk:
        ax.axvline(blk["t"] - t0, color="black", linestyle="--", label="blocked")
    ax.set_xlabel("seconds since attack start")
    ax.set_ylabel("TCP packet rate seen by switch (packets/s)")
    ax.set_title("Controller view: per-host packet rate - %s" % name)
    ax.legend()
    ax.grid(alpha=.3)
    fig.tight_layout()
    fig.savefig(os.path.join(run, "controller_packet_rate.png"), dpi=150)
    plt.close(fig)


def fmt(v, suffix=""):
    return "n/a" if v is None else "%s%s" % (v, suffix)


def write_summary(run, m):
    L = ["# Run summary: %s" % m["run"], "",
         "- Controller mode: **%s**" % m["controller_mode"],
         "- Detection threshold: %s pps" % fmt(m["threshold_pps"]),
         "- Attack connections accepted by server: **%d**" % m["attack_connections_accepted"],
         "- Time from attack start to detection: %s" % fmt(m["detection_time_s"], " s"),
         "- Time from attack start to DROP rule (block): %s" % fmt(m["block_time_s"], " s"),
         "- Attacker connections accepted after block: %s" % fmt(m.get("attack_connections_after_block")),
         "- Legitimate-host success rate: **%s**" % fmt(m["legit_success_pct"], " %"),
         "- Wrongly flagged hosts (false positives): %s" % (", ".join(m["false_positive_hosts"]) or "none"),
         "", "| Host log | attempts | ok | fail | success % |", "|---|---|---|---|---|"]
    for k, r in list(m["legit_hosts"].items()) + ([("h4_abnormal", m["attacker"])] if m["attacker"] else []):
        L.append("| %s | %d | %d | %d | %s |" % (k, r["attempts"], r["ok"], r["fail"], fmt(r["success_pct"])))
    L += ["", "Server connections per source: " + json.dumps(m["server_connections_per_source"])]
    with open(os.path.join(run, "summary.md"), "w") as f:
        f.write("\n".join(L) + "\n")


def compare(runs_metrics, run_dirs, out):
    os.makedirs(out, exist_ok=True)
    fig, axs = plt.subplots(1, 3, figsize=(15, 4.5))
    names = [m["run"] for m in runs_metrics]

    for d, m in zip(run_dirs, runs_metrics):
        conns = [(t, ip) for t, ip in parse_server(os.path.join(d, "server.log"))
                 if ip == ATTACKER_IP and t >= m["attack_start_sod"] - 1]
        cum = {}
        for t, _ in conns:
            sec = int(t - m["attack_start_sod"])
            cum[sec] = cum.get(sec, 0) + 1
        xs = list(range(0, (max(cum) if cum else 0) + 12))
        ys, run_total = [], 0
        for x in xs:
            run_total += cum.get(x, 0)
            ys.append(run_total)
        axs[0].plot(xs, ys, label=m["run"])
    axs[0].set_title("Cumulative attacker connections\naccepted by server")
    axs[0].set_xlabel("seconds since attack start")
    axs[0].set_ylabel("connections")
    axs[0].legend()
    axs[0].grid(alpha=.3)

    vals = [m["legit_success_pct"] or 0 for m in runs_metrics]
    axs[1].bar(names, vals, color="#2ca02c")
    axs[1].set_ylim(0, 105)
    axs[1].set_title("Legitimate hosts (h2, h3)\nconnection success %")
    axs[1].tick_params(axis="x", rotation=20)
    for i, v in enumerate(vals):
        axs[1].text(i, v + 1, "%.0f%%" % v, ha="center")

    bt = [m["block_time_s"] if m["block_time_s"] is not None else 0 for m in runs_metrics]
    axs[2].bar(names, bt, color="#d62728")
    axs[2].set_title("Seconds from attack start\nto DROP rule (0 = never blocked)")
    axs[2].tick_params(axis="x", rotation=20)
    for i, v in enumerate(bt):
        axs[2].text(i, v + .1, "%.1f" % v if v else "none", ha="center")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "comparison.png"), dpi=150)
    plt.close(fig)

    L = ["# Comparison of runs", "",
         "| Run | Mode | Attacker conns accepted | Conns after block | Detect (s) | Block (s) | Legit success % | False positives |",
         "|---|---|---|---|---|---|---|---|"]
    for m in runs_metrics:
        L.append("| %s | %s | %d | %s | %s | %s | %s | %s |" % (
            m["run"], m["controller_mode"], m["attack_connections_accepted"],
            fmt(m.get("attack_connections_after_block")), fmt(m["detection_time_s"]),
            fmt(m["block_time_s"]), fmt(m["legit_success_pct"]),
            ", ".join(m["false_positive_hosts"]) or "none"))
    base = next((m for m in runs_metrics if str(m["controller_mode"]).startswith("baseline")), None)
    if base and base["attack_connections_accepted"]:
        L += ["", "Reduction in attacker connections reaching the server, relative to baseline (%d):" %
              base["attack_connections_accepted"], ""]
        for m in runs_metrics:
            if m is not base and m["controller_mode"] == "dynamic":
                red = 100.0 * (1 - m["attack_connections_accepted"] / base["attack_connections_accepted"])
                L.append("- %s: %.1f %%  (note: compare runs with the same attack rate/duration)" % (m["run"], red))
    with open(os.path.join(out, "comparison.md"), "w") as f:
        f.write("\n".join(L) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="+")
    ap.add_argument("--out", default="runs/_comparison")
    a = ap.parse_args()
    ms = []
    for r in a.runs:
        m = analyze_run(r)
        ms.append(m)
        print("analysed %-20s mode=%-10s attack_conns=%-4d block=%s legit=%s%%" % (
            m["run"], m["controller_mode"].split()[0], m["attack_connections_accepted"],
            fmt(m["block_time_s"], "s"), fmt(m["legit_success_pct"])))
    if len(ms) > 1:
        compare(ms, a.runs, a.out)
        print("comparison written to", a.out)


if __name__ == "__main__":
    main()
