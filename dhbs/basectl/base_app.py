from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3

BaseClass = getattr(app_manager, "OSKenApp", None) or app_manager.RyuApp


class BaseController(BaseClass):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_switch_features(self, ev):
        dp = ev.msg.datapath
        self.logger.info("SWITCH CONNECTED: dpid=%s, OpenFlow version=0x%02x",
                         dp.id, dp.ofproto.OFP_VERSION)
