from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib import hub

import random
import time
from collections import defaultdict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class MTDIPShuffle(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    SHUFFLE_INTERVAL = 30  # seconds

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port = defaultdict(dict)
        self.datapaths = {}

        self.hosts = {}       # real_ip -> {mac, dpid, port}
        self.vip_map = {}     # real_ip -> virtual_ip

        self.shuffle_thread = hub.spawn(self._shuffle_loop)

        console.print(Panel("[bold green]✔ MTD IP Shuffle Controller Started[/bold green]"))

    # ---------------- Switch Handling ---------------- #

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        self.datapaths[dp.id] = dp

        # Table-miss
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)

        console.print(f"[cyan][✓] Switch {dp.id} connected[/cyan]")

    # ---------------- Packet-In ---------------- #

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == 0x0806:  # ARP
            self._handle_arp(dp, pkt, in_port)
            return

        if eth.ethertype == 0x0800:  # IPv4
            self._handle_ipv4(dp, pkt, in_port)

    # ---------------- ARP PROXY ---------------- #

    def _handle_arp(self, dp, pkt, in_port):
        arp_pkt = pkt.get_protocol(arp.arp)

        src_ip = arp_pkt.src_ip
        dst_ip = arp_pkt.dst_ip

        # Learn host
        if src_ip not in self.hosts:
            self.hosts[src_ip] = {
                "mac": arp_pkt.src_mac,
                "dpid": dp.id,
                "port": in_port
            }
            self._assign_vip(src_ip)

        # Proxy ARP reply
        if dst_ip in self.hosts:
            parser = dp.ofproto_parser
            ofp = dp.ofproto

            arp_reply = packet.Packet()
            arp_reply.add_protocol(
                ethernet.ethernet(
                    dst=arp_pkt.src_mac,
                    src="aa:bb:cc:dd:ee:ff",
                    ethertype=0x0806
                )
            )
            arp_reply.add_protocol(
                arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac="aa:bb:cc:dd:ee:ff",
                    src_ip=dst_ip,
                    dst_mac=arp_pkt.src_mac,
                    dst_ip=src_ip
                )
            )
            arp_reply.serialize()

            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(
                datapath=dp,
                buffer_id=ofp.OFP_NO_BUFFER,
                in_port=ofp.OFPP_CONTROLLER,
                actions=actions,
                data=arp_reply.data
            )
            dp.send_msg(out)

    # ---------------- IPv4 HANDLING ---------------- #

    def _handle_ipv4(self, dp, pkt, in_port):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        src = ip_pkt.src
        dst = ip_pkt.dst

        if src not in self.hosts:
            return
        if dst not in self.hosts:
            return

        self._install_bidirectional_flows(src, dst)

    # ---------------- FLOW INSTALL ---------------- #

    def _install_bidirectional_flows(self, src, dst):
        src_vip = self.vip_map[src]
        dst_vip = self.vip_map[dst]

        src_info = self.hosts[src]
        dst_info = self.hosts[dst]

        # Ingress rewrite
        dp = self.datapaths[src_info["dpid"]]
        parser = dp.ofproto_parser

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src,
            ipv4_dst=dst
        )
        actions = [
            parser.OFPActionSetField(ipv4_src=src_vip),
            parser.OFPActionSetField(ipv4_dst=dst_vip),
            parser.OFPActionOutput(dp.ofproto.OFPP_NORMAL)
        ]
        self._add_flow(dp, 10, match, actions)

        # Egress restore
        dp2 = self.datapaths[dst_info["dpid"]]
        parser2 = dp2.ofproto_parser

        match2 = parser2.OFPMatch(
            eth_type=0x0800,
            ipv4_src=dst_vip,
            ipv4_dst=src_vip
        )
        actions2 = [
            parser2.OFPActionSetField(ipv4_src=dst),
            parser2.OFPActionSetField(ipv4_dst=src),
            parser2.OFPActionOutput(dst_info["port"])
        ]
        self._add_flow(dp2, 10, match2, actions2)

    # ---------------- FLOW UTILS ---------------- #

    def _add_flow(self, dp, priority, match, actions):
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst
        )
        dp.send_msg(mod)

    # ---------------- IP SHUFFLE ---------------- #

    def _assign_vip(self, real_ip):
        vip = f"192.168.100.{random.randint(10,250)}"
        self.vip_map[real_ip] = vip
        self._print_shuffle(real_ip)

    def _shuffle_loop(self):
        while True:
            hub.sleep(self.SHUFFLE_INTERVAL)
            if not self.hosts:
                continue

            console.print("\n[bold yellow]⚡ IP Shuffle Triggered[/bold yellow]")
            for ip in list(self.vip_map.keys()):
                self._assign_vip(ip)

    # ---------------- OUTPUT ---------------- #

    def _print_shuffle(self, ip):
        table = Table(title="IP SHUFFLE MAP", show_header=True)
        table.add_column("REAL IP", style="cyan")
        table.add_column("VIRTUAL IP", style="green")
        table.add_column("SWITCH", style="magenta")

        info = self.hosts[ip]
        table.add_row(
            ip,
            self.vip_map[ip],
            f"SW-{info['dpid']}"
        )
        console.print(table)
