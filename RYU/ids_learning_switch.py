from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp, tcp
from collections import defaultdict, deque
import time
from colorama import Fore, Style, init

init(autoreset=True)

# ================= CONFIG =================
WINDOW = 3                 # seconds
ICMP_THRESHOLD = 20        # packets per window
TCP_SYN_THRESHOLD = 25
BLOCK_TIME = 20            # seconds
# =========================================


class IDS_LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port = defaultdict(dict)
        self.icmp_stats = defaultdict(deque)
        self.syn_stats = defaultdict(deque)
        self.blocked_ips = {}

        print(Fore.CYAN + Style.BRIGHT +
              "\n[+] IDS LEARNING SWITCH CONTROLLER STARTED\n")

    # ---------------------------------------------------------
    # Switch Connection
    # ---------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Table-miss: mirror to controller + normal flooding
        actions = [
            parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
            parser.OFPActionOutput(ofp.OFPP_FLOOD)
        ]

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        dp.send_msg(parser.OFPFlowMod(
            datapath=dp,
            priority=0,
            match=parser.OFPMatch(),
            instructions=inst
        ))

        print(Fore.GREEN + f"[✓] Switch {dp.id} connected")

    # ---------------------------------------------------------
    # Packet Processing
    # ---------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == 0x88cc:
            return

        dst = eth.dst
        src = eth.src
        dpid = dp.id

        self.mac_to_port[dpid][src] = in_port

        # Normal learning switch behavior
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow ONLY for non-flood behavior
        if out_port != ofp.OFPP_FLOOD:
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp,
                priority=1,
                match=parser.OFPMatch(
                    in_port=in_port,
                    eth_src=src,
                    eth_dst=dst
                ),
                instructions=[parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS, actions)]
            ))

        dp.send_msg(parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        ))

        # IDS LOGIC
        self.inspect_packet(pkt, dp)

    # ---------------------------------------------------------
    # IDS Logic
    # ---------------------------------------------------------
    def inspect_packet(self, pkt, dp):
        ip = pkt.get_protocol(ipv4.ipv4)
        if not ip:
            return

        src_ip = ip.src
        now = time.time()

        if src_ip in self.blocked_ips:
            return

        # -------- ICMP FLOOD --------
        if pkt.get_protocol(icmp.icmp):
            self.icmp_stats[src_ip].append(now)
            self.cleanup(self.icmp_stats[src_ip], now)

            print(Fore.YELLOW +
                  f"[ICMP] {src_ip} -> {len(self.icmp_stats[src_ip])}")

            if len(self.icmp_stats[src_ip]) > ICMP_THRESHOLD:
                self.block_ip(src_ip, dp, "ICMP FLOOD")

        # -------- TCP SYN FLOOD --------
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt and tcp_pkt.bits & tcp.TCP_SYN:
            self.syn_stats[src_ip].append(now)
            self.cleanup(self.syn_stats[src_ip], now)

            print(Fore.MAGENTA +
                  f"[TCP SYN] {src_ip} -> {len(self.syn_stats[src_ip])}")

            if len(self.syn_stats[src_ip]) > TCP_SYN_THRESHOLD:
                self.block_ip(src_ip, dp, "TCP SYN FLOOD")

    # ---------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------
    def cleanup(self, dq, now):
        while dq and now - dq[0] > WINDOW:
            dq.popleft()

    def block_ip(self, ip, dp, reason):
        if ip in self.blocked_ips:
            return

        parser = dp.ofproto_parser

        dp.send_msg(parser.OFPFlowMod(
            datapath=dp,
            priority=100,
            match=parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=ip
            ),
            instructions=[],
            hard_timeout=BLOCK_TIME
        ))

        self.blocked_ips[ip] = time.time()

        print(Style.BRIGHT + Fore.RED +
              f"\n[🔥 BLOCKED] {ip} | REASON: {reason}\n")
