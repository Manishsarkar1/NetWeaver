# File: SmartIDSController.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4

import time

class SmartSwitchIDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # flood detection threshold (packets/sec)
    THRESHOLD = 100  

    def __init__(self, *args, **kwargs):
        super(SmartSwitchIDS, self).__init__(*args, **kwargs)
        self.ip_count = {}       # {src_ip: [packet_count, timestamp]}
        self.blocked_ips = set() # IPs currently blocked

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)

        if not ip:
            return  # ignore non-IP packets

        src_ip = ip.src

        # block if already marked
        if src_ip in self.blocked_ips:
            self.logger.info(f"DROPPING packet from blocked IP {src_ip}")
            return

        # count packets per second
        now = time.time()
        if src_ip not in self.ip_count:
            self.ip_count[src_ip] = [1, now]
        else:
            self.ip_count[src_ip][0] += 1
            elapsed = now - self.ip_count[src_ip][1]
            if elapsed >= 1:  # 1-second window
                if self.ip_count[src_ip][0] > self.THRESHOLD:
                    self.logger.warning(f"FLOOD DETECTED from {src_ip}, blocking...")
                    self.block_ip(datapath, src_ip)
                    self.blocked_ips.add(src_ip)
                # reset counter
                self.ip_count[src_ip] = [1, now]

        # Normal learning switch behavior (optional)
        out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match['in_port'],
            actions=actions, data=data
        )
        datapath.send_msg(out)

    def block_ip(self, datapath, ip_addr):
        """
        Install a flow to drop packets from a specific IP
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_addr)
        actions = []  # empty actions = drop
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath, priority=100,
            match=match, instructions=inst,
            hard_timeout=0, idle_timeout=0
        )
        datapath.send_msg(mod)
        self.logger.info(f"Installed drop flow for {ip_addr}")
