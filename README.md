# Dynamic Host Blocking System (SDN + TCP sockets)

Computer Networks mini project (topic 12, SDN-Socket Programming). A Mininet network carries
TCP traffic from normal and abnormal hosts. An OS-Ken (OpenFlow 1.3) controller measures the
packet rate of every host, detects the abnormal one, adds it to a **dynamic blocklist** and installs
an **OpenFlow DROP rule** so the attacker is cut off while normal hosts keep working.

| Member | Part |
|---|---|
| 1 | Mininet topology, TCP server, normal/abnormal traffic generator |
| 2 | SDN controller idea: statistics, detection, blocklist, DROP rule |
| 3 | Logging, monitoring, graphs, performance evaluation, documentation, demo evidence |

## Architecture

```
 h2 (normal, 1 conn/s) --\
 h3 (normal, 1 conn/s) ---+--> [ s1  Open vSwitch, OpenFlow 1.3 ] --- h1  TCP server 10.0.0.1:5000
 h4 (abnormal, 5+ conn/s)-/              |  ^
                                  packet-in | | flow-mod (forward / DROP)
                                           v |  + flow-stats request every 2 s
                              [ OS-Ken controller  controller/dhbs_controller.py ]
                                  learning switch + per-host rate detection + blocklist
                                           |
                       results/controller_events.csv, results/flow_stats.csv
```

Flow of events
1. The first TCP packet of a conversation reaches the controller (packet-in). The controller installs a
   per-IP flow `ipv4_src, ipv4_dst, ip_proto=6` -> output port, so the switch now counts packets per host.
2. Every `DHBS_POLL` seconds (default 2) the controller reads the flow counters and computes
   packets/second for each source host.
3. If a host is above `DHBS_THRESHOLD_PPS` (default 12) it is flagged: it is added to the blocklist and a
   priority-100 flow `ipv4_src=<host>` with **no actions** (= DROP) is installed.
4. Everything is logged to CSV; `evaluation/analyze.py` turns the logs into graphs and metrics.

Why packet rate? OpenFlow 1.3 cannot match the TCP SYN flag, so the switch cannot count new connections
directly. Each connection costs a roughly constant number of packets, so packet rate is a good proxy.
Real connection counts are taken from the server log for the evaluation.

Note: M2's original `controller.py` contained the right idea (stats polling + blocklist + DROP). In this
integrated version it is merged with the learning switch (so hosts can communicate) and detects on a
per-host *rate* from per-IP flows. It also has a `baseline` mode (detect and log only) for comparison.

## Repository layout (inside `dhbs/`)
```
topology/topology.py          Mininet topology + CLI (Member 1)
traffic/                      tcp_server.py, traffic_gen.py (Member 1)
basectl/                      run_controller.py, learning_switch.py (Member 1)
controller/dhbs_controller.py integrated detection + blocking controller
evaluation/analyze.py         metrics + graphs + baseline-vs-dynamic comparison (Member 3)
evaluation/calibrate.py       suggests a threshold from a baseline run
scripts/save_run.sh           copies the logs of a finished run to runs/<name>/
scripts/dump_flows.sh         saves the switch flow table (shows the DROP rule)
runs/<name>/                  evidence of each experiment (logs, csv, graphs, summary)
```

## Setup (Ubuntu 24.04, a VM is fine)
```
~/dhbs/setup_env.sh                       # Mininet, Open vSwitch, OS-Ken in ~/dhbs/venv
~/dhbs/venv/bin/pip install matplotlib    # for the evaluation graphs
```

## Run one experiment (needs 3 terminals)
Terminal 1 - controller (choose the mode here):
```
cd ~/dhbs && source venv/bin/activate
DHBS_MODE=dynamic python basectl/run_controller.py ~/dhbs/controller/dhbs_controller.py
```
Terminal 2 - network:
```
sudo python3 ~/dhbs/topology/topology.py
mininet> normal 40            # h2 and h3 send 1 conn/s for 40 s
mininet> abnormal 5 20        # about 5 s later: h4 sends 5 conn/s for 20 s
```
Wait ~30 s. Then, still in Mininet:
```
mininet> results
mininet> h4 nc -zv -w 2 10.0.0.1 5000     # blocked in dynamic mode, connects in baseline mode
mininet> h2 nc -zv -w 2 10.0.0.1 5000     # always works
```
Terminal 3 (before leaving Mininet): `~/dhbs/scripts/dump_flows.sh dynamic`

Then `mininet> exit`, run `~/dhbs/scripts/save_run.sh dynamic`, and stop the controller with Ctrl-C.
If a run was killed: `sudo mn -c`.

## Experiments
| Name | Controller | Traffic | Purpose |
|---|---|---|---|
| `baseline` | `DHBS_MODE=baseline` | normal 40 + abnormal 5 20 | static network, nothing blocked |
| `dynamic` | `DHBS_MODE=dynamic` | same as baseline | proposed approach |
| `heavy_attack` | dynamic | normal 40 + abnormal 20 20 | challenging scenario: attacker at 4x rate |
| `low_rate` | dynamic | normal 40 + abnormal 2 20 | limitation: slow attacker stays under the threshold |

Calibrating the threshold: run `baseline` first, then
`python3 evaluation/calibrate.py results/flow_stats.csv`. If it suggests a different value, restart the
controller with `DHBS_THRESHOLD_PPS=<value>` for all later runs (use the same value for every run).

## Evaluate
```
cd ~/dhbs
python3 evaluation/analyze.py runs/baseline runs/dynamic runs/heavy_attack runs/low_rate
```
Output: `runs/<name>/summary.md`, `connections_per_second.png`, `controller_packet_rate.png`, and
`runs/_comparison/comparison.png` + `comparison.md`.

Metrics: attacker connections accepted by the server, time from attack start to detection and to the DROP
rule, attacker connections after the block, success rate of the legitimate hosts, false positives.

## Results
Paste the table from `runs/_comparison/comparison.md` here and insert the graphs
(`runs/_comparison/comparison.png`, `runs/dynamic/connections_per_second.png`,
`runs/dynamic/controller_packet_rate.png`).

## Test cases
| # | Test | Expected |
|---|---|---|
| T1 | `pingall` at start | 0% loss, learning switch works |
| T2 | Normal traffic only | no host detected, 100% success |
| T3 | Abnormal traffic, baseline mode | h4 detected in log, but all its connections reach the server |
| T4 | Abnormal traffic, dynamic mode | h4 detected, DROP rule in `flows_s1.txt`, its connections stop |
| T5 | During T4, h2 and h3 | stay at 100% success (no false positives) |
| T6 | `heavy_attack` | blocked faster; legitimate hosts unaffected |
| T7 | `low_rate` | not blocked (documented limitation of a fixed threshold) |

## Limitations / future work
Fixed threshold (adaptive thresholds would help); blocks are permanent (could add a timeout for automatic
recovery); detection by packet rate, not by SYN counting; one switch only.
