"""
DHBS controller: Dynamic Host Blocking System (OS-Ken, OpenFlow 1.3)

What it does
  1. Acts as a learning switch so hosts can talk to each other.
  2. For every TCP (IPv4) conversation it installs a per-IP flow
     (match: in_port, ipv4_src, ipv4_dst, ip_proto=6), so the switch keeps a
     packet counter per source host.
  3. Every POLL seconds it asks the switch for flow statistics and computes the
     packet RATE (packets/second) of each source host.
  4. If a host's rate is above THRESHOLD_PPS it is "suspicious":
        - dynamic mode : added to the blocklist + OpenFlow DROP rule installed
        - baseline mode: only logged (nothing is blocked) -> used for comparison
  5. Every statistic and event is written to CSV files for the evaluation.

Configuration (environment variables, all optional)
  DHBS_MODE           dynamic | baseline          (default dynamic)
  DHBS_THRESHOLD_PPS  packets/sec that is "abnormal"   (default 12)
  DHBS_POLL           stats polling interval, seconds  (default 2)
  DHBS_STRIKES        consecutive windows above threshold before blocking (default 1)
  DHBS_SERVER_IP      server that is never blocked     (default 10.0.0.1)
  DHBS_OUT_DIR        where the CSV files are written  (default <repo>/results)

Why packets/sec and not "connections/sec"?  OpenFlow 1.3 cannot match the TCP
SYN flag, so the switch cannot count new connections directly.  Every TCP
connection costs a roughly constant number of packets, so packet rate is a
good proxy.  The ground-truth connection counts come from the server log.
"""
import csv
import os
import tempfile
import time

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import ethernet, ether_types, ipv4, packet, tcp
from os_ken.ofproto import ofproto_v1_3

BaseClass = getattr(app_manager, "OSKenApp", None) or app_manager.RyuApp

PRIO_MAC = 1       # plain learning-switch flows (ARP, ICMP, ...)
PRIO_TCP = 10      # per-IP TCP flows, these are the ones we count
PRIO_DROP = 100    # blocking rules


class DHBSController(BaseClass):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        env = os.environ.get
        self.mode = env("DHBS_MODE", "dynamic").strip().lower()
        self.threshold = float(env("DHBS_THRESHOLD_PPS", "12"))
        self.poll = float(env("DHBS_POLL", "2"))
        self.strikes_needed = int(env("DHBS_STRIKES", "1"))
        self.server_ip = env("DHBS_SERVER_IP", "10.0.0.1")

        self.mac_to_port = {}
        self.datapaths = {}
        self.blocklist = set()
        self.detected = set()
        self.last_total = {}     # ip -> (packet_total, timestamp)
        self.strikes = {}        # ip -> consecutive windows above threshold

        self._open_logs(env("DHBS_OUT_DIR"))
        self.logger.info("DHBS started: mode=%s threshold=%.1f pps poll=%.1fs strikes=%d",
                         self.mode, self.threshold, self.poll, self.strikes_needed)
        self._log_event("CONTROLLER_START", "-", 0.0)
        hub.spawn(self._monitor)

    # ------------------------------------------------------------------ logs
    def _open_logs(self, out_dir):
        if not out_dir:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            out_dir = os.path.join(base, "results")
        try:
            os.makedirs(out_dir, exist_ok=True)
            open(os.path.join(out_dir, ".w"), "w").close()
        except OSError:
            out_dir = tempfile.mkdtemp(prefix="dhbs_")
            self.logger.warning("results dir not writable, using %s", out_dir)
        self.out_dir = out_dir
        self.events_path = os.path.join(out_dir, "controller_events.csv")
        self.stats_path = os.path.join(out_dir, "flow_stats.csv")
        with open(self.events_path, "w", newline="") as f:
            csv.writer(f).writerow(["epoch", "time", "event", "ip", "pps", "threshold", "mode"])
        with open(self.stats_path, "w", newline="") as f:
            csv.writer(f).writerow(["epoch", "time", "ip", "total_packets", "pps", "blocked"])
        self.logger.info("writing CSV logs to %s", out_dir)

    @staticmethod
    def _hms(ts):
        return time.strftime("%H:%M:%S", time.localtime(ts))

    def _log_event(self, event, ip, pps):
        now = time.time()
        with open(self.events_path, "a", newline="") as f:
            csv.writer(f).writerow([f"{now:.3f}", self._hms(now), event, ip,
                                    f"{pps:.2f}", self.threshold, self.mode])

    def _log_stat(self, ip, total, pps, blocked):
        now = time.time()
        with open(self.stats_path, "a", newline="") as f:
            csv.writer(f).writerow([f"{now:.3f}", self._hms(now), ip, total,
                                    f"{pps:.2f}", int(blocked)])

    # ------------------------------------------------------------- switch up
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self.datapaths[dp.id] = dp
        self.logger.info("SWITCH CONNECTED: dpid=%s", dp.id)
        self._log_event("SWITCH_CONNECTED", "-", 0.0)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    def add_flow(self, dp, priority, match, actions, idle=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                instructions=inst, idle_timeout=idle)
        dp.send_msg(mod)

    # ------------------------------------------------------- learning switch
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            ip4 = pkt.get_protocol(ipv4.ipv4)
            t = pkt.get_protocol(tcp.tcp)
            if ip4 is not None and t is not None:
                # per-IP TCP flow: this is what gives us packet counters per host
                match = parser.OFPMatch(in_port=in_port, eth_type=0x0800,
                                        ipv4_src=ip4.src, ipv4_dst=ip4.dst, ip_proto=6)
                self.add_flow(dp, PRIO_TCP, match, actions, idle=0)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
                self.add_flow(dp, PRIO_MAC, match, actions, idle=30)

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)

    # ------------------------------------------------------------ monitoring
    def _monitor(self):
        while True:
            hub.sleep(self.poll)
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def on_flow_stats(self, ev):
        dp = ev.msg.datapath
        totals = {}
        for stat in ev.msg.body:
            if stat.priority != PRIO_TCP:
                continue
            m = stat.match
            if "ipv4_src" in m:
                totals[m["ipv4_src"]] = totals.get(m["ipv4_src"], 0) + stat.packet_count
        for ip in self.evaluate(totals, time.time()):
            self.block(dp, ip)

    def evaluate(self, totals, now):
        """Turn cumulative packet totals into rates. Returns IPs that must be blocked.
        Kept free of OpenFlow calls so it can be unit-tested."""
        to_block = []
        for ip, total in totals.items():
            prev = self.last_total.get(ip)
            self.last_total[ip] = (total, now)
            if prev is None or now - prev[1] <= 0:
                continue
            pps = max(0, total - prev[0]) / (now - prev[1])
            blocked = ip in self.blocklist
            self._log_stat(ip, total, pps, blocked)
            if ip == self.server_ip or blocked:
                continue
            if pps > self.threshold:
                self.strikes[ip] = self.strikes.get(ip, 0) + 1
                if self.strikes[ip] >= self.strikes_needed and ip not in self.detected:
                    self.detected.add(ip)
                    self.logger.warning("ANOMALY DETECTED: %s at %.1f pps (threshold %.1f)",
                                        ip, pps, self.threshold)
                    self._log_event("DETECTED", ip, pps)
                    if self.mode == "dynamic":
                        to_block.append(ip)
                    else:
                        self._log_event("NOT_BLOCKED_BASELINE", ip, pps)
            else:
                self.strikes[ip] = 0
        return to_block

    # -------------------------------------------------------------- blocking
    def block(self, dp, ip):
        if ip in self.blocklist:
            return
        parser = dp.ofproto_parser
        self.blocklist.add(ip)
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        self.add_flow(dp, PRIO_DROP, match, [])      # no actions = DROP
        self.logger.warning("*** BLOCKED %s : OpenFlow DROP rule installed (priority %d) ***",
                            ip, PRIO_DROP)
        self._log_event("BLOCKED", ip, 0.0)
