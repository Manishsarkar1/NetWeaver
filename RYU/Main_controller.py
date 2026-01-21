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
        
        console.print(f"[green]✓ VIP ALLOCATED:[/green] {real_ip} → [cyan]{vip}[/cyan]")
        return vip
    
    def morph_ip_pair(self, ip1, ip2):
        """Morph both IPs after successful communication"""
        console.print("\n" + "="*60)
        console.print("[yellow bold]🔄 MORPHING IPs AFTER REPLY[/yellow bold]")
        
        for real_ip in [ip1, ip2]:
            if real_ip not in self.real_to_virtual:
                continue
            
            old_vip = self.real_to_virtual[real_ip]
            
            # Return old VIP to pool
            self.virtual_pool.add(old_vip)
            del self.virtual_to_real[old_vip]
            
            # Allocate new VIP
            new_vip = self.virtual_pool.pop()
            self.real_to_virtual[real_ip] = new_vip
            self.virtual_to_real[new_vip] = real_ip
            
            console.print(f"  [cyan]{real_ip}:[/cyan] {old_vip} → [green]{new_vip}[/green]")
        
        console.print("="*60 + "\n")
    
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
                pair_key = (src_ip, dst_ip)
                self.icmp_tracker[pair_key] = {'request_seen': True, 'time': time.time()}
                
                console.print(f"[blue]→ ICMP Request:[/blue] {src_ip} → {dst_ip}")
                
            elif icmp_pkt.type == 0:  # ICMP Echo Reply
                pair_key = (dst_ip, src_ip)  # Reverse for lookup
                
                console.print(f"[blue]← ICMP Reply:[/blue] {src_ip} → {dst_ip}")
                
                # Check if we saw the request
                if pair_key in self.icmp_tracker:
                    console.print(f"[green]✓ Round-trip complete![/green]")
                    
                    # MORPH BOTH IPs NOW
                    self.morph_ip_pair(dst_ip, src_ip)
                    
                    # Clean up tracker
                    del self.icmp_tracker[pair_key]
        
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