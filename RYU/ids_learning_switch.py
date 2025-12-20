from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, icmp, arp
from collections import defaultdict
import time
import eventlet

eventlet.monkey_patch()

from colorama import Fore, Style, init
init(autoreset=True)


class PiSwitchIDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port = {}

        # IDS state
        self.icmp_count = defaultdict(int)
        self.icmp_time = defaultdict(float)

        self.tcp_ports = defaultdict(set)
        self.tcp_time = defaultdict(float)

        print(Fore.CYAN + "[+] IDS Controller Started")


    # ---------------- SWITCH CONNECT ----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # TABLE-MISS
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

        print(Fore.GREEN + f"[✓] Switch {dp.id} connected")


    def add_flow(self, dp, priority, match, actions):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst
        )
        dp.send_msg(mod)


    # ---------------- PACKET IN ----------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id

        self.mac_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == 0x88cc:
            return

        src = eth.src
        dst = eth.dst
        in_port = msg.match['in_port']

        self.mac_to_port[dpid][src] = in_port

        # ---------------- ARP (MANDATORY) ----------------
        if pkt.get_protocol(arp.arp):
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=dp,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
            dp.send_msg(out)
            return

        # ---------------- NORMAL L2 FORWARD ----------------
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # ---------------- IDS LOGIC ----------------
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src

            if pkt.get_protocol(icmp.icmp):
                self.detect_icmp_flood(dpid, src_ip)

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                self.detect_tcp_scan(dpid, src_ip, tcp_pkt.dst_port)

        # ---------------- FLOW INSTALL ----------------
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=src,
                eth_dst=dst
            )
            self.add_flow(dp, 1, match, actions)

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        dp.send_msg(out)


    # ---------------- ICMP FLOOD ----------------
    def detect_icmp_flood(self, dpid, src_ip):
        now = time.time()

        if now - self.icmp_time[src_ip] > 1:
            self.icmp_time[src_ip] = now
            self.icmp_count[src_ip] = 0

        self.icmp_count[src_ip] += 1

        if self.icmp_count[src_ip] >= 20:
            print(Fore.RED + Style.BRIGHT +
                  f"[!!!] ICMP_FLOOD | src={src_ip} | switch={dpid}")
            self.icmp_count[src_ip] = 0


    # ---------------- TCP SCAN ----------------
    def detect_tcp_scan(self, dpid, src_ip, dst_port):
        now = time.time()

        if now - self.tcp_time[src_ip] > 5:
            self.tcp_ports[src_ip].clear()
            self.tcp_time[src_ip] = now

        self.tcp_ports[src_ip].add(dst_port)

        if len(self.tcp_ports[src_ip]) >= 10:
            print(Fore.MAGENTA + Style.BRIGHT +
                  f"[!!!] TCP_PORT_SCAN | src={src_ip} | switch={dpid}")
            self.tcp_ports[src_ip].clear()
