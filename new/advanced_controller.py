#!/usr/bin/env python3
"""
ENHANCED MOVING TARGET DEFENSE (MTD) CONTROLLER
Reply-Triggered IP Morphing for ICMP, TCP, and UDP

CONCEPT:
1. Source sends packet (ICMP/TCP/UDP) to destination
2. Destination replies
3. After reply arrives at source → BOTH IPs morph
4. Next interaction uses new VIPs

REQUIREMENTS:
    pip install ryu rich

USAGE:
    ryu-manager enhanced_mtd_controller.py

    sudo mn --controller=remote,port=6653 --topo=single,3
    mininet> h1 ping h2          # ICMP
    mininet> h1 iperf -s &       # TCP server
    mininet> h2 iperf -c h1 -t 5 # TCP client
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp, udp
from ryu.controller.ofp_handler import OFPHandler

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import time

console = Console()


class EnhancedMTDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'ofp_handler': OFPHandler}

    def __init__(self, *args, **kwargs):
        super(EnhancedMTDController, self).__init__(*args, **kwargs)

        # MAC learning (basic L2 forwarding)
        self.mac_to_port = {}

        # IP virtualization
        self.real_to_virtual = {}   # Real IP -> Virtual IP
        self.virtual_to_real = {}   # Virtual IP -> Real IP
        self.virtual_pool = self._init_virtual_pool()

        # Protocol-specific tracking for reply-triggered morphing
        self.icmp_tracker = {}      # (src, dst) -> {'request_seen': bool, 'time': timestamp}
        self.tcp_tracker = {}       # (src_ip, dst_ip, src_port, dst_port) -> {'syn_seen': bool, 'established': bool}
        self.udp_tracker = {}       # (src_ip, dst_ip, src_port, dst_port) -> {'request_seen': bool, 'time': timestamp}

        self._print_banner()

    def _print_banner(self):
        """Startup banner"""
        console.print("""
╔══════════════════════════════════════════════════════════════╗
║    ENHANCED MTD CONTROLLER - Multi-Protocol Support         ║
║         ICMP | TCP | UDP - Reply-Triggered Morph            ║
║                  OpenFlow 1.3 | Ryu                         ║
╚══════════════════════════════════════════════════════════════╝
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

        panel = Panel(
            f"[white]Real IP:[/white] [cyan bold]{real_ip}[/cyan bold]\n"
            f"[white]Assigned VIP:[/white] [green bold]{vip}[/green bold]",
            title="[green]✓ New VIP Allocated[/green]",
            border_style="green"
        )
        console.print(panel)

        return vip

    def morph_ip_pair(self, ip1, ip2, protocol=""):
        """Morph both IPs after successful communication"""
        table = Table(title=f"[yellow bold]🔄 IP MORPHING TRIGGERED ({protocol})[/yellow bold]",
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

            table.add_row(real_ip, old_vip, "→", new_vip)
            morphed = True

        if morphed:
            console.print("\n")
            console.print(table)
            console.print("\n")
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

    def handle_icmp(self, ipv4_pkt, icmp_pkt):
        """Handle ICMP packet tracking"""
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst

        # Allocate VIPs if needed
        if src_ip not in self.real_to_virtual:
            self.allocate_vip(src_ip)
        if dst_ip not in self.real_to_virtual:
            self.allocate_vip(dst_ip)

        if icmp_pkt.type == 8:  # ICMP Echo Request
            pair_key = (src_ip, dst_ip)
            self.icmp_tracker[pair_key] = {'request_seen': True, 'time': time.time()}

            console.print(f"\n[blue]📤 ICMP Request:[/blue] {src_ip} → {dst_ip}")
            console.print(f"   [dim]Source VIP: {self.real_to_virtual[src_ip]}[/dim]")
            console.print(f"   [dim]Dest VIP: {self.real_to_virtual[dst_ip]}[/dim]")

        elif icmp_pkt.type == 0:  # ICMP Echo Reply
            pair_key = (dst_ip, src_ip)  # Reverse for lookup

            console.print(f"\n[blue]📥 ICMP Reply:[/blue] {src_ip} → {dst_ip}")

            if pair_key in self.icmp_tracker:
                console.print(f"[green bold]✅ ICMP Round-trip completed![/green bold]")
                self.morph_ip_pair(dst_ip, src_ip, "ICMP")
                del self.icmp_tracker[pair_key]

    def handle_tcp(self, ipv4_pkt, tcp_pkt):
        """Handle TCP packet tracking (3-way handshake)"""
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        src_port = tcp_pkt.src_port
        dst_port = tcp_pkt.dst_port

        # Allocate VIPs if needed
        if src_ip not in self.real_to_virtual:
            self.allocate_vip(src_ip)
        if dst_ip not in self.real_to_virtual:
            self.allocate_vip(dst_ip)

        flow_key = (src_ip, dst_ip, src_port, dst_port)
        reverse_flow_key = (dst_ip, src_ip, dst_port, src_port)

        # SYN packet (connection initiation)
        if tcp_pkt.has_flags(tcp.TCP_SYN) and not tcp_pkt.has_flags(tcp.TCP_ACK):
            self.tcp_tracker[flow_key] = {
                'syn_seen': True,
                'established': False,
                'time': time.time()
            }
            console.print(f"\n[blue]📤 TCP SYN:[/blue] {src_ip}:{src_port} → {dst_ip}:{dst_port}")
            console.print(f"   [dim]Source VIP: {self.real_to_virtual[src_ip]}[/dim]")
            console.print(f"   [dim]Dest VIP: {self.real_to_virtual[dst_ip]}[/dim]")

        # SYN-ACK packet (server response)
        elif tcp_pkt.has_flags(tcp.TCP_SYN) and tcp_pkt.has_flags(tcp.TCP_ACK):
            console.print(f"\n[blue]📥 TCP SYN-ACK:[/blue] {src_ip}:{src_port} → {dst_ip}:{dst_port}")
            
            if reverse_flow_key in self.tcp_tracker:
                self.tcp_tracker[reverse_flow_key]['syn_ack_seen'] = True

        # ACK packet (connection established)
        elif tcp_pkt.has_flags(tcp.TCP_ACK) and not tcp_pkt.has_flags(tcp.TCP_SYN):
            # Check if this is the final ACK of 3-way handshake
            if flow_key in self.tcp_tracker and not self.tcp_tracker[flow_key].get('established', False):
                if self.tcp_tracker[flow_key].get('syn_ack_seen', False):
                    console.print(f"\n[blue]📥 TCP ACK (3rd handshake):[/blue] {src_ip}:{src_port} → {dst_ip}:{dst_port}")
                    console.print(f"[green bold]✅ TCP Connection Established![/green bold]")
                    
                    # Mark as established and morph
                    self.tcp_tracker[flow_key]['established'] = True
                    self.morph_ip_pair(src_ip, dst_ip, "TCP")
                    
                    # Clean up tracker after morphing
                    del self.tcp_tracker[flow_key]

        # FIN packet (connection termination) - optional: morph on close too
        elif tcp_pkt.has_flags(tcp.TCP_FIN):
            console.print(f"\n[yellow]🔚 TCP FIN:[/yellow] {src_ip}:{src_port} → {dst_ip}:{dst_port}")
            
            # Clean up any tracking for this flow
            if flow_key in self.tcp_tracker:
                del self.tcp_tracker[flow_key]
            if reverse_flow_key in self.tcp_tracker:
                del self.tcp_tracker[reverse_flow_key]

    def handle_udp(self, ipv4_pkt, udp_pkt):
        """Handle UDP packet tracking (request-reply pattern)"""
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        src_port = udp_pkt.src_port
        dst_port = udp_pkt.dst_port

        # Allocate VIPs if needed
        if src_ip not in self.real_to_virtual:
            self.allocate_vip(src_ip)
        if dst_ip not in self.real_to_virtual:
            self.allocate_vip(dst_ip)

        flow_key = (src_ip, dst_ip, src_port, dst_port)
        reverse_flow_key = (dst_ip, src_ip, dst_port, src_port)

        # Check if this is a reply to a previous request
        if reverse_flow_key in self.udp_tracker:
            console.print(f"\n[blue]📥 UDP Reply:[/blue] {src_ip}:{src_port} → {dst_ip}:{dst_port}")
            console.print(f"[green bold]✅ UDP Request-Reply completed![/green bold]")
            
            # Morph both IPs
            self.morph_ip_pair(dst_ip, src_ip, "UDP")
            
            # Clean up tracker
            del self.udp_tracker[reverse_flow_key]
        else:
            # This is a new request
            self.udp_tracker[flow_key] = {
                'request_seen': True,
                'time': time.time()
            }
            console.print(f"\n[blue]📤 UDP Request:[/blue] {src_ip}:{src_port} → {dst_ip}:{dst_port}")
            console.print(f"   [dim]Source VIP: {self.real_to_virtual[src_ip]}[/dim]")
            console.print(f"   [dim]Dest VIP: {self.real_to_virtual[dst_ip]}[/dim]")

    def cleanup_old_trackers(self):
        """Clean up old tracker entries (called periodically)"""
        current_time = time.time()
        timeout = 30  # 30 seconds timeout

        # Clean ICMP tracker
        expired_icmp = [k for k, v in self.icmp_tracker.items() 
                       if current_time - v.get('time', 0) > timeout]
        for key in expired_icmp:
            del self.icmp_tracker[key]

        # Clean TCP tracker
        expired_tcp = [k for k, v in self.tcp_tracker.items() 
                      if current_time - v.get('time', 0) > timeout]
        for key in expired_tcp:
            del self.tcp_tracker[key]

        # Clean UDP tracker
        expired_udp = [k for k, v in self.udp_tracker.items() 
                      if current_time - v.get('time', 0) > timeout]
        for key in expired_udp:
            del self.udp_tracker[key]

        if expired_icmp or expired_tcp or expired_udp:
            console.print(f"[dim]Cleaned up {len(expired_icmp)} ICMP, {len(expired_tcp)} TCP, "
                         f"{len(expired_udp)} UDP expired trackers[/dim]")

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

        # Protocol-specific handling
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if icmp_pkt:
            self.handle_icmp(ipv4_pkt, icmp_pkt)
        elif tcp_pkt:
            self.handle_tcp(ipv4_pkt, tcp_pkt)
        elif udp_pkt:
            self.handle_udp(ipv4_pkt, udp_pkt)

        # Periodic cleanup (every ~100 packets)
        if hasattr(self, '_packet_count'):
            self._packet_count += 1
            if self._packet_count % 100 == 0:
                self.cleanup_old_trackers()
        else:
            self._packet_count = 1

        # Simple forwarding
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