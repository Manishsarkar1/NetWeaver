from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.lib import hub
import random
from rich.console import Console
from rich.table import Table

console = Console()

class FlowBasedMTD(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.real_to_virtual = {}
        self.virtual_to_real = {}

        self.VIP_POOL = [f"192.168.100.{i}" for i in range(10, 250)]

        console.print("\n[bold green]✔ Flow-Based MTD Controller Started[/bold green]\n")

    # ---------------- SWITCH SETUP ----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

        console.print(f"[cyan][✓] Switch {dp.id} connected[/cyan]")

    # ---------------- PACKET IN ----------------
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

        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)

        # ARP: DO NOT TOUCH
        if pkt.get_protocol(arp.arp):
            self.forward(dp, msg, in_port, out_port)
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        if not ip:
            self.forward(dp, msg, in_port, out_port)
            return

        src_ip = ip.src
        dst_ip = ip.dst

        if src_ip not in self.real_to_virtual:
            self.assign_virtual_ip(src_ip)

        vip_src = self.real_to_virtual[src_ip]

        # Forward flow
        self.install_flow(dp,
                          in_port=in_port,
                          src=src_ip,
                          dst=dst_ip,
                          new_src=vip_src,
                          out_port=out_port)

        # Reverse flow
        if dst_ip in self.real_to_virtual:
            vip_dst = self.real_to_virtual[dst_ip]
            self.install_flow(dp,
                              in_port=out_port,
                              src=dst_ip,
                              dst=vip_src,
                              new_dst=src_ip,
                              out_port=in_port)

        self.forward(dp, msg, in_port, out_port)

    # ---------------- FLOW INSTALL ----------------
    def install_flow(self, dp, in_port, src, dst, new_src=None, new_dst=None, out_port=None):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=0x0800,
            ipv4_src=src,
            ipv4_dst=dst
        )

        actions = []
        if new_src:
            actions.append(parser.OFPActionSetField(ipv4_src=new_src))
        if new_dst:
            actions.append(parser.OFPActionSetField(ipv4_dst=new_dst))

        actions.append(parser.OFPActionOutput(out_port))

        self.add_flow(dp, 100, match, actions, idle=20)

    def add_flow(self, dp, priority, match, actions, idle=0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle
        )

        dp.send_msg(mod)

    # ---------------- FORWARD ----------------
    def forward(self, dp, msg, in_port, out_port):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data
        )
        dp.send_msg(out)

    # ---------------- MTD MAP ----------------
    def assign_virtual_ip(self, real_ip):
        vip = random.choice(self.VIP_POOL)
        self.VIP_POOL.remove(vip)

        self.real_to_virtual[real_ip] = vip
        self.virtual_to_real[vip] = real_ip

        table = Table(title="MTD IP MAP")
        table.add_column("REAL IP")
        table.add_column("VIRTUAL IP")
        table.add_row(real_ip, vip)

        console.print(table)
