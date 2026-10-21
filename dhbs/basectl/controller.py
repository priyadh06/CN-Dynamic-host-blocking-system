from os_ken.lib import hub
from os_ken.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from os_ken.controller import ofp_event
from os_ken.base import app_manager
from os_ken.ofproto import ofproto_v1_3

class SimpleBlockerController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.ofproto_v1_3]

    def __init__(self, *args, **kwargs):
        super(SimpleBlockerController, self).__init__(*args, **kwargs)
        self.blocklist = set()          # Tracks blocked IPs
        self.datapaths = {}             # Tracks active switches
        
        # Start a background thread to poll statistics every 5 seconds
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Save the datapath reference for the monitoring loop
        self.datapaths[datapath.id] = datapath

        # Install table-miss entry (send unmatched packets to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                         ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id or ofproto.OFP_NO_BUFFER,
                                priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def block_ip(self, datapath, malicious_ip):
        if malicious_ip in self.blocklist:
            return
            
        parser = datapath.ofproto_parser
        self.blocklist.add(malicious_ip)
        self.logger.info(f"*** BLOCKING MALICIOUS IP: {malicious_ip} ***")

        # High-priority OpenFlow DROP rule
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=malicious_ip)
        actions = [] # Empty actions = Drop packet
        self.add_flow(datapath, priority=100, match=match, actions=actions)

    # --- 1. STATISTICS-GATHERING ---
    def _monitor(self):
        while True:
            for datapath in self.datapaths.values():
                self._request_stats(datapath)
            hub.sleep(5)  # Poll statistics every 5 seconds

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # --- 2. THE DETECTION ENGINE ---
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath

        # Define threshold
        PACKET_THRESHOLD = 150 

        for stat in body:
            # Check if the flow rule matches an IPv4 source address
            if 'ipv4_src' in stat.match:
                src_ip = stat.match['ipv4_src']
                packet_count = stat.packet_count

                # Check if packet volume exceeds the threshold (Is not blocked already)
                if packet_count > PACKET_THRESHOLD and src_ip not in self.blocklist:
                    self.logger.warning(f"ANOMALY DETECTED: IP {src_ip} sent {packet_count} packets!")
                    self.block_ip(datapath, src_ip)