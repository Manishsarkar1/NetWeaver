from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp, tcp
from collections import defaultdict, deque
import time
import threading
from colorama import Fore, Style, init

init(autoreset=True)

# ================= CONFIG =================
WINDOW_SIZE = 5          # seconds (sliding window)
ICMP_THRESHOLD = 40      # packets per window
TCP_SYN_THRESHOLD = 50
PORT_SCAN_THRESHOLD = 10
BLOCK_TIME = 30          # seconds
DASHBOARD_INTERVAL = 5
# ==========================================


class PiSwitchIDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PiSwitchIDS, self).__init__(*args, **kwargs)

        self.mac_to_port = defaultdict(dict)

        self.icmp_history = defaultdict(deque)
        self.tcp_syn_history = defaultdict(deque)
        self.port_scan_history = defaultdict(set)

        self.blocked_ips = {}

        print(Fore.CYAN + "[+] Advanced IDS Controller Started")

        threading.Thread(target=self.unblock_daemon, daemon=True).start()
        threading.Thread(target=self.dashboard, daemon=True).start()

    # ---------- SWITCH SETUP ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=0, match=match, instructions=inst))

        print(Fore.GREEN + f"[✓] Switch {dp.id} connected")

    # ---------- PACKET HANDLER ----------
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

        src = eth.src
        dst = eth.dst
        dpid = dp.id

        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src

            if src_ip in self.blocked_ips:
                return

            self.detect_attacks(pkt, src_ip, dp)

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port, eth_src=src, eth_dst=dst)
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, priority=1, match=match,
                instructions=[parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS, actions)],
                idle_timeout=60))

        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data))

    # ---------- IDS LOGIC ----------
    def detect_attacks(self, pkt, src_ip, dp):
        now = time.time()

        icmp_pkt = pkt.get_protocol(icmp.icmp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # ---- ICMP FLOOD ----
        if icmp_pkt:
            self.icmp_history[src_ip].append(now)
            self.cleanup(self.icmp_history[src_ip], now)

            if len(self.icmp_history[src_ip]) > ICMP_THRESHOLD:
                self.block(src_ip, dp, "ICMP_FLOOD")

        # ---- TCP ATTACKS ----
        if tcp_pkt:
            if tcp_pkt.bits & tcp.TCP_SYN:
                self.tcp_syn_history[src_ip].append(now)
                self.cleanup(self.tcp_syn_history[src_ip], now)

                self.port_scan_history[src_ip].add(tcp_pkt.dst_port)

                if len(self.tcp_syn_history[src_ip]) > TCP_SYN_THRESHOLD:
                    self.block(src_ip, dp, "TCP_SYN_FLOOD")

                if len(self.port_scan_history[src_ip]) > PORT_SCAN_THRESHOLD:
                    self.block(src_ip, dp, "PORT_SCAN")

    def cleanup(self, dq, now):
        while dq and now - dq[0] > WINDOW_SIZE:
            dq.popleft()

    # ---------- BLOCK / UNBLOCK ----------
    def block(self, src_ip, dp, reason):
        if src_ip in self.blocked_ips:
            return

        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)

        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=100, match=match,
            instructions=[], hard_timeout=BLOCK_TIME))

        self.blocked_ips[src_ip] = {
            "time": time.time(),
            "reason": reason,
            "dp": dp
        }

        print(Fore.RED + f"[🔥 BLOCKED] {src_ip} → {reason}")

    def unblock_daemon(self):
        while True:
            now = time.time()
            for ip in list(self.blocked_ips.keys()):
                if now - self.blocked_ips[ip]["time"] > BLOCK_TIME:
                    print(Fore.GREEN + f"[✓ UNBLOCKED] {ip}")
                    del self.blocked_ips[ip]
            time.sleep(1)

    # ---------- DASHBOARD ----------
    def dashboard(self):
        while True:
            print(Style.BRIGHT + Fore.YELLOW + "\n===== IDS DASHBOARD =====")
            print(Fore.CYAN + f"Active Attackers : {len(self.blocked_ips)}")
            for ip, info in self.blocked_ips.items():
                print(Fore.RED + f"{ip} → {info['reason']}")
            print(Fore.YELLOW + "========================\n")
            time.sleep(DASHBOARD_INTERVAL)
