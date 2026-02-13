#!/usr/bin/env python3
"""
MTD CONTROLLER WITH EXTENSIONS
- Statistics Dashboard
- Time-based Morphing
- Configurable Policies

USAGE:
    ryu-manager mtd_with_extensions.py
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp, udp
from ryu.controller.ofp_handler import OFPHandler
from ryu.lib import hub  # For timer threads

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
import time
from datetime import datetime
from collections import defaultdict

console = Console()


class MTDStatistics:
    """Statistics tracker for MTD operations"""
    
    def __init__(self):
        self.total_morphs = 0
        self.morphs_by_protocol = defaultdict(int)
        self.packets_by_protocol = defaultdict(int)
        self.morph_history = []  # List of (timestamp, protocol, ip_pair)
        self.vip_allocations = 0
        self.start_time = time.time()
        
    def record_morph(self, protocol, ip1, ip2):
        """Record a morphing event"""
        self.total_morphs += 1
        self.morphs_by_protocol[protocol] += 1
        self.morph_history.append({
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'protocol': protocol,
            'ip_pair': f"{ip1} ↔ {ip2}"
        })
        # Keep only last 50 events
        if len(self.morph_history) > 50:
            self.morph_history.pop(0)
    
    def record_packet(self, protocol):
        """Record a packet processed"""
        self.packets_by_protocol[protocol] += 1
    
    def get_uptime(self):
        """Get controller uptime"""
        uptime_seconds = int(time.time() - self.start_time)
        hours = uptime_seconds // 3600
        minutes = (uptime_seconds % 3600) // 60
        seconds = uptime_seconds % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    def get_stats_table(self):
        """Generate statistics table"""
        table = Table(title="[cyan bold]MTD Statistics[/cyan bold]", 
                     show_header=True, header_style="bold blue")
        table.add_column("Metric", style="white", width=25)
        table.add_column("Value", style="green bold", width=15)
        
        table.add_row("Uptime", self.get_uptime())
        table.add_row("Total Morphs", str(self.total_morphs))
        table.add_row("VIP Allocations", str(self.vip_allocations))
        table.add_row("", "")  # Separator
        
        # Morphs by protocol
        for protocol in ['ICMP', 'TCP', 'UDP']:
            table.add_row(f"{protocol} Morphs", 
                         str(self.morphs_by_protocol.get(protocol, 0)))
        
        table.add_row("", "")  # Separator
        
        # Packets by protocol
        for protocol in ['ICMP', 'TCP', 'UDP', 'ARP']:
            table.add_row(f"{protocol} Packets", 
                         str(self.packets_by_protocol.get(protocol, 0)))
        
        return table
    
    def get_recent_events(self, limit=10):
        """Get recent morph events"""
        table = Table(title="[yellow]Recent Morph Events[/yellow]",
                     show_header=True, header_style="bold magenta")
        table.add_column("Time", style="cyan", width=10)
        table.add_column("Protocol", style="green", width=8)
        table.add_column("IP Pair", style="white", width=30)
        
        for event in self.morph_history[-limit:]:
            table.add_row(event['timestamp'], 
                         event['protocol'], 
                         event['ip_pair'])
        
        return table


class MorphingPolicy:
    """Configurable morphing policy"""
    
    def __init__(self):
        # Reply-triggered morphing (default: enabled)
        self.reply_triggered = True
        
        # Time-based morphing
        self.time_based_enabled = False
        self.morph_interval_seconds = 30
        
        # Packet-count based morphing
        self.packet_count_enabled = False
        self.morph_after_n_packets = 100
        
        # Per-protocol settings
        self.protocol_enabled = {
            'ICMP': True,
            'TCP': True,
            'UDP': True
        }
        
        # Whitelist (IPs that never morph)
        self.whitelist = set()
    
    def should_morph_on_reply(self, protocol):
        """Check if reply-triggered morphing is enabled for protocol"""
        return (self.reply_triggered and 
                self.protocol_enabled.get(protocol, True))
    
    def is_whitelisted(self, ip):
        """Check if IP is whitelisted"""
        return ip in self.whitelist
    
    def should_morph_time_based(self):
        """Check if time-based morphing is enabled"""
        return self.time_based_enabled


class MTDControllerExtended(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'ofp_handler': OFPHandler}

    def __init__(self, *args, **kwargs):
        super(MTDControllerExtended, self).__init__(*args, **kwargs)

        # MAC learning
        self.mac_to_port = {}

        # IP virtualization
        self.real_to_virtual = {}
        self.virtual_to_real = {}
        self.virtual_pool = self._init_virtual_pool()

        # Protocol tracking
        self.icmp_tracker = {}
        self.tcp_tracker = {}
        self.udp_tracker = {}

        # Statistics
        self.stats = MTDStatistics()
        
        # Morphing policy
        self.policy = MorphingPolicy()
        
        # Packet counters for packet-based morphing
        self.packet_counters = defaultdict(int)  # (ip1, ip2) -> count

        self._print_banner()
        
        # Start background threads
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.time_based_morph_thread = hub.spawn(self._time_based_morph_loop)

    def _print_banner(self):
        """Startup banner"""
        console.print("""
╔══════════════════════════════════════════════════════════════╗
║         MTD CONTROLLER - EXTENDED VERSION                   ║
║    Features: Stats | Time-Based Morph | Policies            ║
╚══════════════════════════════════════════════════════════════╝
        """, style="bold cyan")

    def _init_virtual_pool(self):
        """Initialize pool of virtual IPs"""
        pool = set()
        for i in range(1, 255):
            pool.add(f"192.168.100.{i}")
        return pool

    def _monitor_loop(self):
        """Background thread to display statistics"""
        while True:
            hub.sleep(5)  # Update every 5 seconds
            console.clear()
            console.print(self.stats.get_stats_table())
            console.print("\n")
            console.print(self.stats.get_recent_events(limit=5))
            console.print("\n")
            self._show_current_mappings()

    def _time_based_morph_loop(self):
        """Background thread for time-based morphing"""
        while True:
            hub.sleep(self.policy.morph_interval_seconds)
            
            if not self.policy.should_morph_time_based():
                continue
            
            # Morph all active IP pairs
            if len(self.real_to_virtual) >= 2:
                ips = list(self.real_to_virtual.keys())
                for i in range(0, len(ips) - 1, 2):
                    ip1, ip2 = ips[i], ips[i + 1]
                    if not (self.policy.is_whitelisted(ip1) or 
                           self.policy.is_whitelisted(ip2)):
                        console.print(f"\n[yellow]⏰ Time-based morph triggered[/yellow]")
                        self.morph_ip_pair(ip1, ip2, "TIME-BASED")

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
        
        self.stats.vip_allocations += 1

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
        
        # Check whitelist
        if self.policy.is_whitelisted(ip1) or self.policy.is_whitelisted(ip2):
            console.print(f"[yellow]⚠ Morph blocked - whitelisted IP[/yellow]")
            return

        table = Table(title=f"[yellow bold]🔄 IP MORPHING ({protocol})[/yellow bold]",
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
            
            # Record statistics
            self.stats.record_morph(protocol, ip1, ip2)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        console.print(f"[green]✓ Switch s{datapath.id} connected[/green]")

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
        
        self.stats.record_packet('ICMP')

        if src_ip not in self.real_to_virtual:
            self.allocate_vip(src_ip)
        if dst_ip not in self.real_to_virtual:
            self.allocate_vip(dst_ip)

        if icmp_pkt.type == 8:  # Echo Request
            pair_key = (src_ip, dst_ip)
            self.icmp_tracker[pair_key] = {'request_seen': True, 'time': time.time()}
            console.print(f"\n[blue]📤 ICMP Request:[/blue] {src_ip} → {dst_ip}")

        elif icmp_pkt.type == 0:  # Echo Reply
            pair_key = (dst_ip, src_ip)
            console.print(f"\n[blue]📥 ICMP Reply:[/blue] {src_ip} → {dst_ip}")

            if pair_key in self.icmp_tracker:
                console.print(f"[green bold]✅ ICMP Round-trip completed![/green bold]")
                
                if self.policy.should_morph_on_reply('ICMP'):
                    self.morph_ip_pair(dst_ip, src_ip, "ICMP")
                
                del self.icmp_tracker[pair_key]

    def handle_tcp(self, ipv4_pkt, tcp_pkt):
        """Handle TCP packet tracking"""
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        src_port = tcp_pkt.src_port
        dst_port = tcp_pkt.dst_port
        
        self.stats.record_packet('TCP')

        if src_ip not in self.real_to_virtual:
            self.allocate_vip(src_ip)
        if dst_ip not in self.real_to_virtual:
            self.allocate_vip(dst_ip)

        flow_key = (src_ip, dst_ip, src_port, dst_port)
        reverse_flow_key = (dst_ip, src_ip, dst_port, src_port)

        if tcp_pkt.has_flags(tcp.TCP_SYN) and not tcp_pkt.has_flags(tcp.TCP_ACK):
            self.tcp_tracker[flow_key] = {
                'syn_seen': True,
                'established': False,
                'time': time.time()
            }
            console.print(f"\n[blue]📤 TCP SYN:[/blue] {src_ip}:{src_port} → {dst_ip}:{dst_port}")

        elif tcp_pkt.has_flags(tcp.TCP_SYN) and tcp_pkt.has_flags(tcp.TCP_ACK):
            console.print(f"\n[blue]📥 TCP SYN-ACK:[/blue] {src_ip}:{src_port} → {dst_ip}:{dst_port}")
            if reverse_flow_key in self.tcp_tracker:
                self.tcp_tracker[reverse_flow_key]['syn_ack_seen'] = True

        elif tcp_pkt.has_flags(tcp.TCP_ACK) and not tcp_pkt.has_flags(tcp.TCP_SYN):
            if flow_key in self.tcp_tracker and not self.tcp_tracker[flow_key].get('established', False):
                if self.tcp_tracker[flow_key].get('syn_ack_seen', False):
                    console.print(f"\n[blue]📥 TCP ACK:[/blue] {src_ip}:{src_port} → {dst_ip}:{dst_port}")
                    console.print(f"[green bold]✅ TCP Connection Established![/green bold]")
                    
                    if self.policy.should_morph_on_reply('TCP'):
                        self.morph_ip_pair(src_ip, dst_ip, "TCP")
                    
                    self.tcp_tracker[flow_key]['established'] = True
                    del self.tcp_tracker[flow_key]

    def handle_udp(self, ipv4_pkt, udp_pkt):
        """Handle UDP packet tracking"""
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        src_port = udp_pkt.src_port
        dst_port = udp_pkt.dst_port
        
        self.stats.record_packet('UDP')

        if src_ip not in self.real_to_virtual:
            self.allocate_vip(src_ip)
        if dst_ip not in self.real_to_virtual:
            self.allocate_vip(dst_ip)

        flow_key = (src_ip, dst_ip, src_port, dst_port)
        reverse_flow_key = (dst_ip, src_ip, dst_port, src_port)

        if reverse_flow_key in self.udp_tracker:
            console.print(f"\n[blue]📥 UDP Reply:[/blue] {src_ip}:{src_port} → {dst_ip}:{dst_port}")
            console.print(f"[green bold]✅ UDP Request-Reply completed![/green bold]")
            
            if self.policy.should_morph_on_reply('UDP'):
                self.morph_ip_pair(dst_ip, src_ip, "UDP")
            
            del self.udp_tracker[reverse_flow_key]
        else:
            self.udp_tracker[flow_key] = {'request_seen': True, 'time': time.time()}
            console.print(f"\n[blue]📤 UDP Request:[/blue] {src_ip}:{src_port} → {dst_ip}:{dst_port}")

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

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # Handle ARP
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.stats.record_packet('ARP')
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
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if icmp_pkt:
            self.handle_icmp(ipv4_pkt, icmp_pkt)
        elif tcp_pkt:
            self.handle_tcp(ipv4_pkt, tcp_pkt)
        elif udp_pkt:
            self.handle_udp(ipv4_pkt, udp_pkt)

        # Forward packet
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