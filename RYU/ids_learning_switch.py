from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp
from ryu.lib import hub
import time
from colorama import Fore, Style, init

init(autoreset=True)


class PiSwitchIDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.icmp_stats = {}
        self.tcp_stats = {}
        self.blocked_ips = set()

        self.ICMP_THRESHOLD = 30
        self.TCP_THRESHOLD = 50

        print(Fore.GREEN + Style.BRIGHT + "[+] IDS Learning Switch Started")

        # cleanup thread
        self.monitor_thread = hub.spawn(self.cleanup)

    def cleanup(self):
        while True:
            self.icmp_stats.clear()
            self.tcp_stats.clear()
            hub.sleep(1)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]

        self.add_flow(dp, 0, match, actions)
        print(Fore.CYAN + f"[✓] Switch {dp.id} connected")

    def add_flow(self, dp, priority, match, actions):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp,
                                priority=priority,
                                match=match,
                                instructions=inst)
        dp.send_msg(mod)

    def block_ip(self, dp, src_ip):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch(ipv4_src=src_ip, eth_type=0x0800)
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=100,
            match=match,
            instructions=[]
        )
        dp.send_msg(mod)

        self.blocked_ips.add(src_ip)
        print(Fore.RED + Style.BRIGHT +
              f"[!!!] BLOCKED IP {src_ip} on switch {dp.id}")

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

        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})

        src = eth.src
        dst = eth.dst

        self.mac_to_port[dpid][src] = in_port

        # ---------- IDS LOGIC ----------
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src

            if src_ip in self.blocked_ips:
                return

            # ICMP
            if pkt.get_protocol(icmp.icmp):
                self.icmp_stats[src_ip] = self.icmp_stats.get(src_ip, 0) + 1
                if self.icmp_stats[src_ip] > self.ICMP_THRESHOLD:
                    print(Fore.YELLOW + Style.BRIGHT +
                          f"[!!!] ICMP FLOOD from {src_ip}")
                    self.block_ip(dp, src_ip)
                    return

            # TCP
            if pkt.get_protocol(tcp.tcp):
                self.tcp_stats[src_ip] = self.tcp_stats.get(src_ip, 0) + 1
                if self.tcp_stats[src_ip] > self.TCP_THRESHOLD:
                    print(Fore.MAGENTA + Style.BRIGHT +
                          f"[!!!] TCP FLOOD from {src_ip}")
                    self.block_ip(dp, src_ip)
                    return

        # ---------- NORMAL SWITCH ----------
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        dp.send_msg(out)
