#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
import random

# =============================
# CONFIG
# =============================
PHASE = 2   # 0 = L2 only, 2 = Source-IP MTD

# =============================
# LEARNING SWITCH
# =============================

class LearningSwitch:
    def __init__(self):
        self.mac_to_port = {}

# =============================
# SOURCE-IP MTD
# =============================

class SourceIPMTD:
    def __init__(self):
        self.map = {}
        self.pool = [f"192.168.100.{i}" for i in range(10, 250)]
        random.shuffle(self.pool)

    def vip(self, real_ip):
        if real_ip not in self.map:
            self.map[real_ip] = self.pool.pop()
            print(f"[MTD] {real_ip} → {self.map[real_ip]}")
        return self.map[real_ip]

# =============================
# CONTROLLER
# =============================

class MTDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.switches = {}
        self.mtd = SourceIPMTD()
        print("\n[✓] Source-IP MTD Controller Started\n")

    # -------------------------
    # SWITCH CONNECT
    # -------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        self.switches[dp.id] = LearningSwitch()

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp,
            priority=0,
            match=match,
            instructions=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        ))

        print(f"[✓] Switch s{dp.id} connected")

    # -------------------------
    # PACKET IN
    # -------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        dpid = dp.id
        in_port = msg.match['in_port']

        sw = self.switches[dpid]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == 0x88cc:
            return

        # Learn MAC
        sw.mac_to_port[eth.src] = in_port
        out_port = sw.mac_to_port.get(eth.dst, ofp.OFPP_FLOOD)

        # ARP — DO NOT TOUCH
        if pkt.get_protocol(arp.arp):
            self._send(dp, msg, in_port, out_port)
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        if not ip or PHASE == 0:
            self._send(dp, msg, in_port, out_port)
            return

        # ============================
        # SOURCE-IP MTD (SAFE)
        # ============================

        vip = self.mtd.vip(ip.src)

        match_fwd = parser.OFPMatch(
            in_port=in_port,
            eth_type=0x0800,
            ipv4_src=ip.src,
            ipv4_dst=ip.dst
        )

        actions_fwd = [
            parser.OFPActionSetField(ipv4_src=vip),
            parser.OFPActionOutput(out_port)
        ]

        match_rev = parser.OFPMatch(
            in_port=out_port,
            eth_type=0x0800,
            ipv4_src=ip.dst,
            ipv4_dst=vip
        )

        actions_rev = [
            parser.OFPActionSetField(ipv4_dst=ip.src),
            parser.OFPActionOutput(in_port)
        ]

        self._add_flow(dp, match_fwd, actions_fwd)
        self._add_flow(dp, match_rev, actions_rev)

        self._send(dp, msg, in_port, out_port, actions_fwd)

    # -------------------------
    # HELPERS
    # -------------------------

    def _add_flow(self, dp, match, actions):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp,
            priority=100,
            match=match,
            instructions=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)],
            idle_timeout=60,
            hard_timeout=120
        ))

    def _send(self, dp, msg, in_port, out_port, actions=None):
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        if actions is None:
            actions = [parser.OFPActionOutput(out_port)]

        dp.send_msg(parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        ))
