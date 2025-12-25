from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib import hub
import random
import time

MTD_INTERVAL = 15  # seconds
VIRTUAL_NET = "192.168.100."

class MTDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.real_to_virtual = {}
        self.virtual_to_real = {}

        self.datapath = None
        self.monitor_thread = hub.spawn(self.mtd_loop)

        print("\n[✓] MTD Controller Started (REAL Flow-Based MTD)\n")

    # ---------- SWITCH SETUP ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapath = dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Table-miss
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

        print(f"[✓] Switch s{dp.id} connected")

    # ---------- FLOW UTILS ----------
    def add_flow(self, dp, priority, match, actions, idle=0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            idle_timeout=idle,
            match=match,
            instructions=inst
        )
        dp.send_msg(mod)

    # ---------- PACKET HANDLER ----------
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

        self.mac_to_port.setdefault(dp.id, {})
        self.mac_to_port[dp.id][eth.src] = in_port

        # ---------- ARP ----------
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.handle_arp(dp, in_port, eth, arp_pkt)
            return

        # ---------- IPV4 ----------
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.handle_ipv4(dp, in_port, eth, ip_pkt)
            return

        # ---------- L2 FALLBACK ----------
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(dp, msg.buffer_id, in_port, actions, msg.data)
        dp.send_msg(out)

    # ---------- ARP PROXY ----------
    def handle_arp(self, dp, in_port, eth, arp_pkt):
        parser = dp.ofproto_parser

        self.ip_to_mac[arp_pkt.src_ip] = eth.src

        if arp_pkt.opcode == arp.ARP_REQUEST:
            target_ip = arp_pkt.dst_ip

            if target_ip in self.real_to_virtual:
                reply_mac = eth.src
                reply_ip = target_ip

                arp_reply = packet.Packet()
                arp_reply.add_protocol(
                    ethernet.ethernet(
                        ethertype=0x0806,
                        dst=eth.src,
                        src=reply_mac
                    )
                )
                arp_reply.add_protocol(
                    arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=reply_mac,
                        src_ip=reply_ip,
                        dst_mac=eth.src,
                        dst_ip=arp_pkt.src_ip
                    )
                )
                arp_reply.serialize()

                out = parser.OFPPacketOut(
                    datapath=dp,
                    buffer_id=0xffffffff,
                    in_port=dp.ofproto.OFPP_CONTROLLER,
                    actions=[parser.OFPActionOutput(in_port)],
                    data=arp_reply.data
                )
                dp.send_msg(out)

    # ---------- IPV4 + MTD ----------
    def handle_ipv4(self, dp, in_port, eth, ip_pkt):
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        src_real = ip_pkt.src
        dst_real = ip_pkt.dst

        if src_real not in self.real_to_virtual:
            return

        src_virtual = self.real_to_virtual[src_real]
        dst_virtual = self.real_to_virtual.get(dst_real, dst_real)

        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)

        # FORWARD
        match_fwd = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src_real,
            ipv4_dst=dst_real
        )

        actions_fwd = [
            parser.OFPActionSetField(ipv4_src=src_virtual),
            parser.OFPActionSetField(ipv4_dst=dst_virtual),
            parser.OFPActionOutput(out_port)
        ]

        self.add_flow(dp, 10, match_fwd, actions_fwd, idle=30)

        # REVERSE
        match_rev = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=dst_virtual,
            ipv4_dst=src_virtual
        )

        actions_rev = [
            parser.OFPActionSetField(ipv4_src=dst_real),
            parser.OFPActionSetField(ipv4_dst=src_real),
            parser.OFPActionOutput(in_port)
        ]

        self.add_flow(dp, 10, match_rev, actions_rev, idle=30)

    # ---------- MTD LOOP ----------
    def mtd_loop(self):
        while True:
            time.sleep(MTD_INTERVAL)
            if not self.ip_to_mac:
                continue

            print("\n[MTD] Shuffling IPs")

            self.real_to_virtual.clear()
            self.virtual_to_real.clear()

            for real_ip in self.ip_to_mac.keys():
                virt_ip = VIRTUAL_NET + str(random.randint(10, 250))
                self.real_to_virtual[real_ip] = virt_ip
                self.virtual_to_real[virt_ip] = real_ip
                print(f"  {real_ip} → {virt_ip}")
