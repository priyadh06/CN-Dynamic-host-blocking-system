# Dynamic Host Blocking System (DHBS)
## Evaluation and Performance Analysis

### 1. Introduction

The Dynamic Host Blocking System (DHBS) is designed to detect suspicious hosts generating unusually high traffic and block them using Software-Defined Networking (SDN). The system monitors traffic rates and installs an OpenFlow DROP rule when a host exceeds the configured threshold.

The purpose of this evaluation is to compare normal baseline behaviour with dynamic blocking enabled, measure detection and blocking time, and verify whether legitimate traffic is affected.

### 2. Experimental Setup

The experiments were conducted in an Ubuntu environment using Mininet, Open vSwitch, OpenFlow 1.3, and an OS-Ken SDN controller.

The network consisted of one server and three clients connected through switch s1:

- h1: Server at 10.0.0.1, listening on TCP port 5000.
- h2: Legitimate client at 10.0.0.2.
- h3: Legitimate client at 10.0.0.3.
- h4: Suspicious client at 10.0.0.4.

The configured detection threshold was 12 packets per second. The controller monitored traffic and, in dynamic mode, installed a DROP rule for a host identified as suspicious.

### 3. Experimental Methodology

Two experiments were performed.

**Baseline mode:** Dynamic blocking was disabled. The clients generated traffic, and the number of successful connections to the server was recorded.

**Dynamic mode:** Dynamic blocking was enabled. The legitimate clients generated normal traffic, while h4 generated suspicious traffic. The controller detected the high traffic rate and installed a DROP rule.

The controller logs, client logs, server logs, flow statistics, and generated analysis files were used to evaluate performance.

### 4. Results

| Metric | Baseline mode | Dynamic mode |
|---|---:|---:|
| Detection threshold | 12 pps | 12 pps |
| Measured suspicious-host rate | 19.99 pps | 19.99 pps |
| Suspicious-host connections accepted by server | 100 | 14 |
| Time until detection | 4.08 s | 3.23 s |
| Time until blocking | Not blocked | 3.23 s |
| h2 successful connections | 40/40 | 40/40 |
| h3 successful connections | 40/40 | 40/40 |
| Legitimate traffic success rate | 100% | 100% |
| False-positive hosts | None recorded | None recorded |

### 5. Analysis and Discussion

In baseline mode, the server accepted 100 connections from the suspicious host. Although the controller detected a rate of approximately 19.99 packets per second, no blocking rule was installed.

In dynamic mode, the controller detected the suspicious host at approximately 19.99 packets per second, which exceeded the configured threshold of 12 packets per second. The controller then installed an OpenFlow DROP rule for 10.0.0.4.

The dynamic-mode client log recorded 32 connection attempts, of which 14 succeeded and 18 failed. The server accepted 14 connections from h4, and no attacker connections were recorded after the blocking event.

The observed reduction in accepted suspicious-host connections was:

Reduction = ((100 - 14) / 100) × 100 = 86%

Therefore, 86% fewer suspicious-host connections reached the server in the dynamic experiment than in the baseline experiment. This result applies to the recorded runs; it should not be treated as a universal performance guarantee because the number of connection attempts differed between runs.

Both legitimate clients achieved 40 successful connections out of 40 attempts in both modes. Their measured success rate remained 100%, indicating that the blocking action did not affect their recorded traffic.

### 6. Graphs and Supporting Evidence

The following files contain the experiment evidence and generated analysis:

- `evaluation/summary.csv/comparison.png` — comparison graphs for baseline and dynamic modes.
- `evaluation/summary.csv/comparison.md` — generated comparison table and reduction calculation.
- `runs/baseline/summary.md` — baseline experiment summary.
- `runs/dynamic/summary.md` — dynamic experiment summary.
- `runs/baseline/metrics.json` — baseline performance metrics.
- `runs/dynamic/metrics.json` — dynamic performance metrics.
- `runs/baseline/controller_events.csv` — baseline controller events.
- `runs/dynamic/controller_events.csv` — dynamic controller events.
- `runs/baseline/flows_s1.txt` — baseline switch flow-table evidence.
- `runs/baseline/controller_packet_rate.png` — baseline controller packet-rate graph.
- `runs/baseline/connections_per_second.png` — baseline connection-rate graph.

The dynamic controller log also records the detection of 10.0.0.4 and installation of the DROP rule. A dynamic switch flow-table dump was not saved during the experiment, so the recorded controller event and client/server results are used as supporting evidence for dynamic blocking.

### 7. Limitations

The baseline and dynamic runs did not record identical numbers of connection attempts. The baseline suspicious client completed 100 connections, whereas the dynamic client recorded 32 attempts before or during blocking, with 14 successful and 18 failed connections. The 86% reduction compares server-accepted connections and should be interpreted in this context.

The controller's detection threshold is expressed in packets per second, whereas the client logs report connection attempts and successful connections. These are different measurements and should not be interpreted as equivalent rates.

### 8. Conclusion

The experiments demonstrate the intended behaviour of the Dynamic Host Blocking System. In baseline mode, suspicious traffic reached the server without being blocked. In dynamic mode, the controller detected the suspicious host and installed an OpenFlow DROP rule.

The dynamic experiment recorded 14 accepted suspicious-host connections compared with 100 in the baseline experiment. Both legitimate clients maintained a 100% connection success rate, and no false-positive hosts were recorded. These results indicate that dynamic blocking reduced suspicious traffic reaching the server while preserving legitimate connectivity in the tested runs.
