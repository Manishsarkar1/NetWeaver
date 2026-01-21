#!/usr/bin/env python3
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp
from ryu.controller.ofp_handler import OFPHandler

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import time

console = Console()

class CleanMTDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'ofp_handler': OFPHandler}
    
    def __init__(self, *args, **kwargs):
        super(CleanMTDController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.real_to_virtual = {}
        self.virtual_to_real = {}
        self.virtual_pool = self._init_virtual_pool()
        self.icmp_tracker = {}
        self._print_banner()
    
    def _print_banner(self):
        console.print("""
╔══════════════════════════════════════════════════════════╗
║       CLEAN MTD CONTROLLER - Reply-Triggered Morph      ║
║                  OpenFlow 1.3 | Ryu                     ║
╚══════════════════════════════════════════════════════════╝
        """, style="bold cyan")
    
    def _init_virtual_pool(self):
        pool = set()
        for i in range(1, 255):
            pool.add(f"192.168.100.{i}")
        return pool
    
    def _show_current_mappings(self):
        if not self.real_to_virtual:
            return
        table = Table(title="[cyan]Current VIP Assignments[/cyan]", 
                     show_header=True, header_style="bold blue")
        table.add_column("Real IP", style="white", width=15)
        table.add_column("↔", justify="center", width=3)
        table.add_column("Virtual IP", style="cyan bold", width=18)
        for real_ip, vip in sorted(self.real_to_virtual.items()):
            table.add_row(real_ip, "↔", vip)
        console.print(table)
        console.print("\n")
    
    def allocate_vip(self, real_ip):
        if real_ip in self.real_to_virtual:
            return self.real_to_virtual[real_ip]
        if not self.virtual_pool:
            console.print("[red]VIP pool exhausted![/red]")
            return real_ip
        vip = self.virtual_pool.pop()
        self.real_to_virtual[real_ip] = vip
        self.virtual_to_real[vip] = real_ip
        panel = Panel(
            f"[white]Real IP:[/white] [cyan bold]{real_ip}[/cyan bold]\n"
            f"[white]Assigned VIP:[/white] [green bold]{vip}[/green bold]",
            title="[green]✓ New VIP Allocated[/green]",
            border_style="green"
        )
        console.print(panel)
        return vip
    
    def morph_ip_pair(self, ip1, ip2):
        table = Table(title="[yellow bold]🔄 IP MORPHING TRIGGERED[/yellow bold]", 
                     show_header=True, header_style="bold magenta")
        table.add_column("Real IP", style="cyan", width=15)
        table.add_column("Old VIP", style="red", width=18)
        table.add_column("→", justify="center", width=3)
        table.add_column("New VIP", style="green bold", width=18)
        morphed = False
        for real_ip in [ip1, ip2]:
            if real_ip not in self.real_to_virtual:
                continue
            old_vip = self.real_to_virtual[real_ip]
            self.virtual_pool.add(old_vip)
            del self.virtual_to_real[old_vip]
            if not self.virtual_pool:
                console.print("[red]VIP pool exhausted![/red]")
                continue
            new_vip = self.virtual_pool.pop()
            self.real_to_virtual[real_ip] = new_vip
            self.virtual_to_real[new_vip] = real_ip
            table.add_row(real_ip, old_vip, "→", new_vip)
            morphed = True
        if morphed:
            console.print("\n")
            console.print(table)
            console.print("\n")
            self._show_current_mappings()
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        console.print(f"[green]✓ Switch s{datapath.id} connected[/green]")
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    
    def add_flow(self, datapath, priority, match, actions, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                instructions=inst, idle_timeout=idle, hard_timeout=hard)
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            actions = [parser.OFPActionOutput(out_port)]
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
            return
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ipv4_pkt:
            return
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        if icmp_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            if icmp_pkt.type == 8:
                pair_key = (src_ip, dst_ip)
                self.icmp_tracker[pair_key] = {'request_seen': True, 'time': time.time()}
                console.print(f"\n[blue]📤 ICMP Request:[/blue] {src_ip} → {dst_ip}")
                if src_ip in self.real_to_virtual:
                    console.print(f"   [dim]Using VIP: {self.real_to_virtual[src_ip]}[/dim]")
            elif icmp_pkt.type == 0:
                pair_key = (dst_ip, src_ip)
                console.print(f"[blue]📥 ICMP Reply:[/blue] {src_ip} → {dst_ip}")
                if pair_key in self.icmp_tracker:
                    console.print(f"[green bold]✅ Round-trip completed successfully![/green bold]\n")
                    self.morph_ip_pair(dst_ip, src_ip)
                    del self.icmp_tracker[pair_key]
                else:
                    console.print(f"[yellow]⚠ Reply received but no matching request tracked[/yellow]\n")
        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

if __name__ == '__main__':
    from ryu.cmd import manager
    import sys
    sys.argv = ['ryu-manager', __file__]
    manager.main()