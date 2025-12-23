from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.lib import hub

import random
import time

# ---------- COLORS ----------
G = "\033[92m"
R = "\033[91m"
Y = "\033[93m"
B = "\033[94m"
C = "\033[96m"
W = "\033[0m"

class MTDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.real_to_virtual = {}
        self.virtual_to_real = {}

        self.switches = {}
        self.shuffle_interval = 15  # seconds

        print(f"\n{G}✔ MTD IP Rewrite Controller Started{W}\n")

        hub.spawn(self.ip_shuffle_loop)

    # ------------------------------------------------
    # SWITCH SETUP
    # ------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        self.switches[dp.id] = dp
        self.mac_to_port.setdefault(dp.id, {})

        # TABLE MISS
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

        print(f"{C}[✓] Switch {dp.id} connected{W}")

    # ------------------------------------------------
    # FLOW INSTALL
    # ------------------------------------------------
    def add_flow(self, dp, priority, match, actions, idle=60, hard=0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle,
            hard_timeout=hard
        )
        dp.send_msg(mod)

    # ------------------------------------------------
    # PACKET HANDLER
    # ------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == 0x88cc:
            return

        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        out_port = self.mac_to_port[dpid].get(
            eth.dst, ofp.OFPP_FLOOD)

        # ---------------- ARP (DO NOT TOUCH) ----------------
        if pkt.get_protocol(arp.arp):
            actions = [parser.OFPActionOutput(out_port)]
            self.send_packet(dp, msg, in_port, actions)
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        if not ip:
            actions = [parser.OFPActionOutput(out_port)]
            self.send_packet(dp, msg, in_port, actions)
            return

        # Assign virtual IPs if not exists
        if ip.src not in self.real_to_virtual:
            self.assign_virtual_ip(ip.src)

        if ip.dst not in self.real_to_virtual:
            self.assign_virtual_ip(ip.dst)

        vip_src = self.real_to_virtual[ip.src]
        vip_dst = self.real_to_virtual[ip.dst]

        # ---------------- FORWARD FLOW ----------------
        match_fwd = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip.src,
            ipv4_dst=ip.dst
        )

        actions_fwd = [
            parser.OFPActionSetField(ipv4_src=vip_src),
            parser.OFPActionSetField(ipv4_dst=vip_dst),
            parser.OFPActionOutput(out_port)
        ]

        self.add_flow(dp, 10, match_fwd, actions_fwd)

        # ---------------- REVERSE FLOW ----------------
        match_rev = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=vip_dst,
            ipv4_dst=vip_src
        )

        actions_rev = [
            parser.OFPActionSetField(ipv4_src=ip.dst),
            parser.OFPActionSetField(ipv4_dst=ip.src),
            parser.OFPActionOutput(in_port)
        ]

        self.add_flow(dp, 10, match_rev, actions_rev)

        # Send first packet
        self.send_packet(dp, msg, in_port, actions_fwd)

    # ------------------------------------------------
    def send_packet(self, dp, msg, in_port, actions):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        dp.send_msg(out)

    # ------------------------------------------------
    # IP SHUFFLING
    # ------------------------------------------------
    def assign_virtual_ip(self, real_ip):
        vip = f"192.168.100.{random.randint(10, 250)}"
        self.real_to_virtual[real_ip] = vip
        self.virtual_to_real[vip] = real_ip

        print(f"{Y}[MAP]{W} {real_ip} → {vip}")

    def ip_shuffle_loop(self):
        while True:
            hub.sleep(self.shuffle_interval)
            print(f"\n{R}⚡ IP SHUFFLE TRIGGERED{W}")

            for real_ip in list(self.real_to_virtual.keys()):
                new_vip = f"192.168.100.{random.randint(10, 250)}"
                self.real_to_virtual[real_ip] = new_vip
                self.virtual_to_real[new_vip] = real_ip

                print(f"{C}{real_ip}{W} ⇒ {B}{new_vip}{W}")

            print("")
