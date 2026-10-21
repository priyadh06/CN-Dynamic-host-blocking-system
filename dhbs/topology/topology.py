import os
import time

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAFFIC = os.path.join(BASE, "traffic")
LOGS = os.path.join(BASE, "logs")
SERVER = os.path.join(TRAFFIC, "tcp_server.py")
GEN = os.path.join(TRAFFIC, "traffic_gen.py")


class DHBSTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        for i in range(1, 5):
            h = self.addHost("h%d" % i, ip="10.0.0.%d/24" % i)
            self.addLink(h, s1)


class DHBSCLI(CLI):
    def _run(self, host, rate, duration, label):
        cmd = "python3 %s --rate %s --duration %s --label %s > %s/%s.log 2>&1 &" % (
            GEN, rate, duration, label, LOGS, label.replace("-", "_"))
        self.mn.get(host).cmd(cmd)

    def do_normal(self, line):
        "normal [duration]: h2 and h3 each send 1 TCP connection per second"
        dur = line.strip() or "20"
        self._run("h2", 1, dur, "h2-normal")
        self._run("h3", 1, dur, "h3-normal")
        print("Normal traffic started on h2 and h3 for %s seconds" % dur)

    def do_abnormal(self, line):
        "abnormal [rate] [duration]: h4 sends many TCP connections per second (default 5/s, 20 s)"
        parts = line.split()
        rate = parts[0] if len(parts) > 0 else "5"
        dur = parts[1] if len(parts) > 1 else "20"
        self._run("h4", rate, dur, "h4-abnormal")
        print("Abnormal traffic started on h4: %s conn/s for %s seconds" % (rate, dur))

    def do_results(self, _line):
        "results: last line of each traffic log and server connections per source IP"
        for name in ("h2_normal", "h3_normal", "h4_abnormal"):
            path = os.path.join(LOGS, name + ".log")
            last = "(no log yet)"
            if os.path.exists(path):
                with open(path) as f:
                    lines = [l.strip() for l in f if l.strip()]
                if lines:
                    last = lines[-1]
            print("%s: %s" % (name, last))
        counts = {}
        spath = os.path.join(LOGS, "server.log")
        if os.path.exists(spath):
            with open(spath) as f:
                for l in f:
                    if "connection from" in l:
                        ip = l.split("connection from")[1].strip().split(":")[0]
                        counts[ip] = counts.get(ip, 0) + 1
        print("server connections per source:")
        for ip in sorted(counts):
            print("  %s: %d" % (ip, counts[ip]))


def main():
    setLogLevel("info")
    os.makedirs(LOGS, exist_ok=True)
    for f in os.listdir(LOGS):
        if f.endswith(".log"):
            os.remove(os.path.join(LOGS, f))

    net = Mininet(topo=DHBSTopo(), controller=None, switch=OVSSwitch,
                  autoSetMacs=True, waitConnected=False)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    net.start()
    try:
        info("*** Waiting for the switch to connect to the controller\n")
        if not net.waitConnected(timeout=15):
            print("ERROR: switch did not connect. Is the controller running in its tab?")
            return
        net.get("h1").cmd("python3 %s > %s/server.log 2>&1 &" % (SERVER, LOGS))
        time.sleep(1)
        info("*** TCP server started on h1 (10.0.0.1:5000)\n")
        net.pingAll()
        print("Commands: normal [sec] | abnormal [rate] [sec] | results | exit")
        DHBSCLI(net)
    finally:
        os.system("pkill -f tcp_server.py; pkill -f traffic_gen.py")
        net.stop()


if __name__ == "__main__":
    main()
