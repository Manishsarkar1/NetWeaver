from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub
import time


class SmartSwitchIDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SmartSwitchIDS, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.packet_count = {}
        self.blocked_hosts = set()

        self.THRESHOLD = 20        # packets per window
        self.TIME_WINDOW = 5       # seconds

        self.monitor_thread = hub.spawn(self.monitor)

    # -------------------------------
    # SWITCH CONNECTION
    # -------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                instructions=inst)
        datapath.send_msg(mod)

    # -------------------------------
    # PACKET HANDLER
    # -------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == 0x88cc:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        src = eth.src
        dst = eth.dst
        in_port = msg.match['in_port']

        # IDS: Count packets
        self.packet_count[src] = self.packet_count.get(src, 0) + 1

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.logger.info("IP %s → %s", ip_pkt.src, ip_pkt.dst)

        if src in self.blocked_hosts:
            self.logger.warning("BLOCKED packet from %s", src)
            return

        # Learning switch logic
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data)

        datapath.send_msg(out)

    # -------------------------------
    # MONITOR THREAD
    # -------------------------------
    def monitor(self):
        while True:
            hub.sleep(self.TIME_WINDOW)

            for host, count in list(self.packet_count.items()):
                if count > self.THRESHOLD:
                    self.logger.error(
                        "ATTACK DETECTED: %s sent %d packets", host, count)
                    self.blocked_hosts.add(host)

            self.packet_count.clear()