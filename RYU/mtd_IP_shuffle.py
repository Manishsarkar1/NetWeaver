from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.lib import hub

import random
import time

from colorama import Fore, Style, init
from tabulate import tabulate

init(autoreset=True)

SHUFFLE_INTERVAL = 15  # seconds
VIRTUAL_NET = "192.168.100."

class MTDIPShuffle(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MTDIPShuffle, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.host_db = {}      # real_ip -> data
        self.virtual_pool = list(range(10, 250))

        self.monitor_thread = hub.spawn(self.ip_shuffle_loop)

        print(Fore.GREEN + Style.BRIGHT + "\n[✔] MTD IP Shuffle Controller Started\n")

    # ---------- Switch Setup ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        print(Fore.CYAN + f"[✓] Switch {datapath.id} connected")

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    # ---------- Packet Handling ----------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == 0x88cc:
            return

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # Learn IP → host
        if ip_pkt:
            if ip_pkt.src not in self.host_db:
                vip = self.allocate_virtual_ip()
                self.host_db[ip_pkt.src] = {
                    "vip": vip,
                    "switch": dpid,
                    "last_shuffle": time.strftime("%H:%M:%S")
                }

        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)

        actions = []

        # --- IP Rewrite ---
        if ip_pkt:
            src_vip = self.host_db[ip_pkt.src]["vip"]
            dst_vip = self.get_real_from_virtual(ip_pkt.dst)

            if src_vip:
                actions.append(parser.OFPActionSetField(ipv4_src=src_vip))
            if dst_vip:
                actions.append(parser.OFPActionSetField(ipv4_dst=dst_vip))

        actions.append(parser.OFPActionOutput(out_port))

        match = parser.OFPMatch(
            in_port=in_port,
            eth_src=eth.src,
            eth_dst=eth.dst
        )

        self.add_flow(datapath, 10, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)

    # ---------- MTD Logic ----------
    def allocate_virtual_ip(self):
        octet = random.choice(self.virtual_pool)
        self.virtual_pool.remove(octet)
        return VIRTUAL_NET + str(octet)

    def reshuffle_ips(self):
        for real_ip in self.host_db:
            self.virtual_pool.append(int(self.host_db[real_ip]["vip"].split(".")[-1]))
            self.host_db[real_ip]["vip"] = self.allocate_virtual_ip()
            self.host_db[real_ip]["last_shuffle"] = time.strftime("%H:%M:%S")

    def get_real_from_virtual(self, vip):
        for real, data in self.host_db.items():
            if data["vip"] == vip:
                return real
        return None

    # ---------- Periodic Shuffle ----------
    def ip_shuffle_loop(self):
        while True:
            hub.sleep(SHUFFLE_INTERVAL)
            if not self.host_db:
                continue

            self.reshuffle_ips()
            self.print_status()

    # ---------- Pretty Output ----------
    def print_status(self):
        print(Fore.MAGENTA + Style.BRIGHT + "\n╔═══════════════ IP SHUFFLE EVENT ═══════════════╗")

        table = []
        for real, data in self.host_db.items():
            table.append([
                Fore.YELLOW + real,
                Fore.GREEN + data["vip"],
                Fore.CYAN + f"SW-{data['switch']}",
                Fore.WHITE + data["last_shuffle"]
            ])

        print(tabulate(
            table,
            headers=[
                Fore.RED + "REAL IP",
                Fore.RED + "VIRTUAL IP",
                Fore.RED + "SWITCH",
                Fore.RED + "LAST SHUFFLE"
            ],
            tablefmt="fancy_grid"
        ))

        print(Fore.MAGENTA + Style.BRIGHT + "╚═══════════════════════════════════════════════╝\n")
