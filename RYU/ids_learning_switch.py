from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, icmp
from collections import defaultdict
import time
import eventlet

eventlet.monkey_patch()

from colorama import Fore, Style, init
init(autoreset=True)


class PiSwitchIDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PiSwitchIDS, self).__init__(*args, **kwargs)

        # MAC learning
        self.mac_to_port = {}

        # IDS DATA
        self.icmp_count = defaultdict(int)
        self.icmp_time = defaultdict(float)

        self.tcp_ports = defaultdict(set)
        self.tcp_time = defaultdict(float)

        print(Fore.CYAN + "[+] IDS Controller Started")


    # ---------------- SWITCH CONNECT ----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        print(Fore.GREEN + f"[✓] Switch {datapath.id} connected")


    # ---------------- FLOW INSTALL ----------------
    def add_flow(self, datapath, priority, match, actions):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                instructions=inst)
        datapath.send_msg(mod)


    # ---------------- PACKET IN ----------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == 0x88cc:
            return

        dst = eth.dst
        src = eth.src
        in_port = msg.match['in_port']

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # ---------- IDS ----------
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src

            if pkt.get_protocol(icmp.icmp):
                self.detect_icmp_flood(dpid, src_ip)

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                self.detect_tcp_scan(dpid, src_ip, tcp_pkt.dst_port)

        # ---------- NORMAL FORWARD ----------
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_dst=dst,
                                    eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        data = None if msg.buffer_id == ofp.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)


    # ---------------- ICMP FLOOD DETECTION ----------------
    def detect_icmp_flood(self, dpid, src_ip):
        now = time.time()

        if now - self.icmp_time[src_ip] > 1:
            self.icmp_time[src_ip] = now
            self.icmp_count[src_ip] = 0

        self.icmp_count[src_ip] += 1

        if self.icmp_count[src_ip] >= 15:
            print(Fore.RED + Style.BRIGHT +
                  f"[!!!] ICMP_FLOOD detected | src={src_ip} | switch={dpid}")
            self.icmp_count[src_ip] = 0


    # ---------------- TCP PORT SCAN DETECTION ----------------
    def detect_tcp_scan(self, dpid, src_ip, dst_port):
        now = time.time()

        if now - self.tcp_time[src_ip] > 5:
            self.tcp_time[src_ip] = now
            self.tcp_ports[src_ip].clear()

        self.tcp_ports[src_ip].add(dst_port)

        if len(self.tcp_ports[src_ip]) >= 10:
            print(Fore.MAGENTA + Style.BRIGHT +
                  f"[!!!] TCP_PORT_SCAN detected | src={src_ip} | switch={dpid}")
            self.tcp_ports[src_ip].clear()
