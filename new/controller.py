#!/usr/bin/env python3
"""
CLEAN MOVING TARGET DEFENSE (MTD) CONTROLLER
Reply-Triggered IP Morphing - Simple & Working

CONCEPT:
1. Source sends ICMP request to destination
2. Destination replies
3. After reply arrives at source → BOTH IPs morph
4. Next interaction uses new VIPs

REQUIREMENTS:
    pip install ryu rich

USAGE:
    ryu-manager clean_mtd_controller.py
    
    sudo mn --controller=remote,port=6653 --topo=single,3
    mininet> h1 ping h2
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp
from ryu.controller.ofp_handler import OFPHandler  # CRITICAL: Must import this

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import random
import time

console = Console()


class CleanMTDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'ofp_handler': OFPHandler}  # CRITICAL: Register handler
    
    def __init__(self, *args, **kwargs):
        super(CleanMTDController, self).__init__(*args, **kwargs)
        
        # MAC learning (basic L2 forwarding)
        self.mac_to_port = {}
        
        # IP virtualization
        self.real_to_virtual = {}   # Real IP -> Virtual IP
        self.virtual_to_real = {}   # Virtual IP -> Real IP
        self.virtual_pool = self._init_virtual_pool()
        
        # ICMP tracking for reply-triggered morphing
        self.icmp_tracker = {}  # (src, dst) -> {'request_seen': bool}
        
        self._print_banner()
    
    def _print_banner(self):
        """Startup banner"""
        console.print("""
╔══════════════════════════════════════════════════════════╗
║       CLEAN MTD CONTROLLER - Reply-Triggered Morph      ║
║                  OpenFlow 1.3 | Ryu                     ║
╚══════════════════════════════════════════════════════════╝
        """, style="bold cyan")
    
    def _init_virtual_pool(self):
        """Initialize pool of virtual IPs"""
        pool = set()
        for i in range(1, 255):
            pool.add(f"192.168.100.{i}")
        return pool
    
    def _show_current_mappings(self):
        """Display current IP mappings"""
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
        """Allocate VIP for real IP"""
        if real_ip in self.real_to_virtual:
            return self.real_to_virtual[real_ip]
        
        if not self.virtual_pool:
            console.print("[red]VIP pool exhausted![/red]")
            return real_ip
        
        vip = self.virtual_pool.pop()
        self.real_to_virtual[real_ip] = vip
        self.virtual_to_real[vip] = real_ip
        
        # Show allocation with context
        panel = Panel(
            f"[white]Real IP:[/white] [cyan bold]{real_ip}[/cyan bold]\n"
            f"[white]Assigned VIP:[/white] [green bold]{vip}[/green bold]",
            title="[green]✓ New VIP Allocated[/green]",
            border_style="green"
        )
        console.print(panel)
        
        return vip
    
    def morph_ip_pair(self, ip1, ip2):
        """Morph both IPs after successful communication"""
        
        # Create a table showing the morphing
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
            
            # Return old VIP to pool
            self.virtual_pool.add(old_vip)
            del self.virtual_to_real[old_vip]
            
            # Allocate new VIP
            if not self.virtual_pool:
                console.print("[red]VIP pool exhausted![/red]")
                continue
                
            new_vip = self.virtual_pool.pop()
            self.real_to_virtual[real_ip] = new_vip
            self.virtual_to_real[new_vip] = real_ip
            
            # Add to table
            table.add_row(real_ip, old_vip, "→", new_vip)
            morphed = True
        
        if morphed:
            console.print("\n")
            console.print(table)
            console.print("\n")
            
            # Show current state
            self._show_current_mappings()
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        console.print(f"[green]✓ Switch s{datapath.id} connected[/green]")
        
        # Install table-miss flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    
    def add_flow(self, datapath, priority, match, actions, idle=0, hard=0):
        """Add a flow entry"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle,
            hard_timeout=hard
        )
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Main packet processing"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Initialize MAC table for this switch
        self.mac_to_port.setdefault(dpid, {})
        
        # Learn source MAC
        self.mac_to_port[dpid][eth.src] = in_port
        
        # Determine output port
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        # Handle ARP (never touch ARP - just forward)
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            actions = [parser.OFPActionOutput(out_port)]
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data
            )
            datapath.send_msg(out)
            return
        
        # Handle IP packets
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ipv4_pkt:
            return
        
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        
        # MTD LOGIC: Track ICMP request/reply
        if icmp_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            
            if icmp_pkt.type == 8:  # ICMP Echo Request
                # Allocate VIP for source if not already assigned
                if src_ip not in self.real_to_virtual:
                    self.allocate_vip(src_ip)
                
                # Allocate VIP for destination if not already assigned
                if dst_ip not in self.real_to_virtual:
                    self.allocate_vip(dst_ip)
                
                pair_key = (src_ip, dst_ip)
                self.icmp_tracker[pair_key] = {'request_seen': True, 'time': time.time()}
                
                console.print(f"\n[blue]📤 ICMP Request:[/blue] {src_ip} → {dst_ip}")
                console.print(f"   [dim]Source VIP: {self.real_to_virtual[src_ip]}[/dim]")
                console.print(f"   [dim]Dest VIP: {self.real_to_virtual[dst_ip]}[/dim]")
                
            elif icmp_pkt.type == 0:  # ICMP Echo Reply
                pair_key = (dst_ip, src_ip)  # Reverse for lookup
                
                console.print(f"\n[blue]📥 ICMP Reply:[/blue] {src_ip} → {dst_ip}")
                
                # Check if we saw the request
                if pair_key in self.icmp_tracker:
                    console.print(f"[green bold]✅ Round-trip completed successfully![/green bold]")
                    
                    # Show BEFORE morphing
                    console.print(f"\n[yellow]BEFORE MORPH:[/yellow]")
                    console.print(f"  {dst_ip} has VIP: {self.real_to_virtual.get(dst_ip, 'none')}")
                    console.print(f"  {src_ip} has VIP: {self.real_to_virtual.get(src_ip, 'none')}")
                    
                    # MORPH BOTH IPs NOW
                    self.morph_ip_pair(dst_ip, src_ip)
                    
                    # Clean up tracker
                    del self.icmp_tracker[pair_key]
                else:
                    console.print(f"[yellow]⚠ Reply received but no matching request tracked[/yellow]")
        
        # Simple forwarding (no flow installation for now - keep it simple)
        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)


if __name__ == '__main__':
    from ryu.cmd import manager
    import sys
    sys.argv = ['ryu-manager', __file__]
    manager.main()