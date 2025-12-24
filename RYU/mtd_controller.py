#!/usr/bin/env python3
"""
STATEFUL SDN-BASED MOVING TARGET DEFENSE (MTD) SYSTEM
Production-grade implementation using Ryu + OpenFlow 1.3

REQUIREMENTS:
    pip install ryu click rich

USAGE:
    # Set phase via environment variable
    export MTD_PHASE=0 && ryu-manager mtd_controller.py
    export MTD_PHASE=2 && ryu-manager mtd_controller.py
    export MTD_PHASE=4 && ryu-manager mtd_controller.py
    
    # Or edit PHASE constant in code below

ARCHITECTURE:
    - Stateful flow tracking
    - Bidirectional flow locking
    - Safe IP rewriting with reverse flows
    - Attack-triggered dynamic shuffling
"""

import os

# ============================================================================
# CONFIGURATION - CHANGE THIS TO SWITCH PHASES
# ============================================================================
PHASE = int(os.environ.get('MTD_PHASE', 0))  # 0, 1, 2, 3, or 4
# ============================================================================

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp, udp
from ryu.lib import hub

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from datetime import datetime
import random
import time
import struct
import socket

console = Console()


# ============================================================================
# PHASE 0: BASELINE LEARNING SWITCH
# Pure L2 forwarding with no modifications - MUST WORK 100%
# ============================================================================

class BaselineLearningSwitch:
    """
    Pure learning switch implementation
    No IP rewriting, no MTD, just basic L2 forwarding
    This is our stable baseline - DO NOT MODIFY
    """
    
    def __init__(self, datapath):
        self.dp = datapath
        self.ofproto = datapath.ofproto
        self.parser = datapath.ofproto_parser
        self.mac_to_port = {}
        
    def add_flow(self, priority, match, actions, idle=0, hard=0, cookie=0):
        """Install a flow entry"""
        inst = [self.parser.OFPInstructionActions(
            self.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = self.parser.OFPFlowMod(
            datapath=self.dp,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle,
            hard_timeout=hard,
            cookie=cookie,
            flags=self.ofproto.OFPFF_SEND_FLOW_REM
        )
        self.dp.send_msg(mod)
    
    def handle_packet(self, msg, pkt, eth):
        """Pure L2 learning and forwarding"""
        in_port = msg.match['in_port']
        dpid = self.dp.id
        
        # Learn source MAC
        self.mac_to_port[eth.src] = in_port
        
        # Determine output port
        if eth.dst in self.mac_to_port:
            out_port = self.mac_to_port[eth.dst]
        else:
            out_port = self.ofproto.OFPP_FLOOD
        
        # Install flow if destination is known
        actions = [self.parser.OFPActionOutput(out_port)]
        
        if out_port != self.ofproto.OFPP_FLOOD:
            match = self.parser.OFPMatch(
                in_port=in_port,
                eth_dst=eth.dst,
                eth_src=eth.src
            )
            self.add_flow(priority=10, match=match, actions=actions, 
                         idle=30, hard=60)
        
        # Send packet out
        data = msg.data if msg.buffer_id == self.ofproto.OFP_NO_BUFFER else None
        out = self.parser.OFPPacketOut(
            datapath=self.dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        self.dp.send_msg(out)
        
        return out_port


# ============================================================================
# PHASE 1: TRAFFIC VISIBILITY LAYER
# Passive monitoring - classify traffic zones, log everything
# ============================================================================

class TrafficMonitor:
    """
    Monitors and classifies all traffic flows
    Tracks: MAC, IP, Port, Direction, Zone
    """
    
    def __init__(self):
        self.host_table = {}  # MAC -> {ip, switch, port, last_seen}
        self.flow_stats = {}  # Flow ID -> stats
        
    def update_host(self, mac, ip, switch_id, port):
        """Update host tracking table"""
        self.host_table[mac] = {
            'ip': ip,
            'switch': switch_id,
            'port': port,
            'last_seen': time.time()
        }
    
    def classify_zone(self, src_ip, dst_ip, real_subnet='10.0.0.0/24', 
                     virtual_subnet='192.168.100.0/24'):
        """Classify traffic into zones"""
        src_is_real = self._in_subnet(src_ip, real_subnet)
        dst_is_real = self._in_subnet(dst_ip, real_subnet)
        
        if src_is_real and dst_is_real:
            return "REAL→REAL"
        elif src_is_real and not dst_is_real:
            return "REAL→VIRTUAL"
        elif not src_is_real and dst_is_real:
            return "VIRTUAL→REAL"
        else:
            return "VIRTUAL→VIRTUAL"
    
    def _in_subnet(self, ip, subnet):
        """Check if IP is in subnet"""
        try:
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            net, mask = subnet.split('/')
            net_int = struct.unpack('!I', socket.inet_aton(net))[0]
            mask_int = (0xffffffff << (32 - int(mask))) & 0xffffffff
            return (ip_int & mask_int) == (net_int & mask_int)
        except:
            return False
    
    def log_flow(self, src_mac, dst_mac, src_ip, dst_ip, protocol, switch_id):
        """Log flow with classification"""
        zone = self.classify_zone(src_ip, dst_ip)
        
        table = Table(title="[cyan]FLOW TRACKED[/cyan]")
        table.add_column("Field", style="yellow")
        table.add_column("Value", style="green")
        
        table.add_row("Zone", zone)
        table.add_row("Source", f"{src_mac} ({src_ip})")
        table.add_row("Destination", f"{dst_mac} ({dst_ip})")
        table.add_row("Protocol", protocol)
        table.add_row("Switch", f"s{switch_id}")
        table.add_row("Timestamp", datetime.now().strftime("%H:%M:%S"))
        
        console.print(table)


# ============================================================================
# PHASE 2: FLOW-LOCKED IP VIRTUALIZATION
# Stateful IP rewriting with bidirectional flow pairing
# ============================================================================

class IPVirtualization:
    """
    Manages IP virtualization with flow-level state tracking
    Each real IP gets a virtual IP that's consistent per flow
    """
    
    def __init__(self):
        self.real_to_virtual = {}    # Real IP -> Virtual IP
        self.virtual_to_real = {}    # Virtual IP -> Real IP
        self.active_flows = {}       # Cookie -> Flow state
        self.next_cookie = 0x1000
        self.virtual_pool = set()
        self._init_virtual_pool()
    
    def _init_virtual_pool(self):
        """Initialize pool of available virtual IPs"""
        for i in range(1, 255):
            self.virtual_pool.add(f"192.168.100.{i}")
    
    def allocate_vip(self, real_ip):
        """Allocate or return existing VIP for real IP"""
        if real_ip in self.real_to_virtual:
            return self.real_to_virtual[real_ip]
        
        if not self.virtual_pool:
            raise Exception("Virtual IP pool exhausted")
        
        vip = self.virtual_pool.pop()
        self.real_to_virtual[real_ip] = vip
        self.virtual_to_real[vip] = real_ip
        
        console.print(f"[green]VIP ALLOCATED[/green]: {real_ip} → {vip}")
        return vip
    
    def get_real_ip(self, virtual_ip):
        """Get real IP from virtual IP"""
        return self.virtual_to_real.get(virtual_ip)
    
    def create_flow_pair(self):
        """Create a cookie for bidirectional flow pair"""
        cookie = self.next_cookie
        self.next_cookie += 1
        return cookie
    
    def install_rewrite_flows(self, datapath, in_port, out_port, 
                             src_ip_real, dst_ip_real, eth_src, eth_dst,
                             protocol=None):
        """
        Install bidirectional IP rewrite flows
        CRITICAL: Both directions use same cookie for pairing
        
        FORWARD: Real_A → Real_B (rewrite src to VIP_A)
        REVERSE: Real_B → Real_A (match on dst=VIP_A, rewrite back to Real_A)
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # Allocate VIPs
        src_vip = self.allocate_vip(src_ip_real)
        dst_vip = self.allocate_vip(dst_ip_real)
        
        # Create flow pair cookie
        cookie = self.create_flow_pair()
        
        # FORWARD FLOW: Real src → Real dst
        # Match: src=Real_A, dst=Real_B
        # Action: Rewrite src to VIP_A, forward
        match_fwd = parser.OFPMatch(
            in_port=in_port,
            eth_type=0x0800,
            ipv4_src=src_ip_real,
            ipv4_dst=dst_ip_real
        )
        
        actions_fwd = [
            parser.OFPActionSetField(ipv4_src=src_vip),
            parser.OFPActionOutput(out_port)
        ]
        
        self._add_flow(datapath, priority=100, match=match_fwd, 
                      actions=actions_fwd, idle=30, hard=60, cookie=cookie)
        
        # REVERSE FLOW: Real dst → Real src (return path)
        # Match: src=Real_B, dst=VIP_A (NOT Real_A!)
        # Action: Rewrite dst back to Real_A, forward back
        match_rev = parser.OFPMatch(
            in_port=out_port,
            eth_type=0x0800,
            ipv4_src=dst_ip_real,  # Reply comes from Real_B
            ipv4_dst=src_vip        # Destined to VIP_A (not Real_A!)
        )
        
        actions_rev = [
            parser.OFPActionSetField(ipv4_dst=src_ip_real),  # Rewrite back to Real_A
            parser.OFPActionOutput(in_port)
        ]
        
        self._add_flow(datapath, priority=100, match=match_rev,
                      actions=actions_rev, idle=30, hard=60, cookie=cookie)
        
        # Store flow state
        self.active_flows[cookie] = {
            'src_real': src_ip_real,
            'dst_real': dst_ip_real,
            'src_vip': src_vip,
            'dst_vip': dst_vip,
            'switch': datapath.id,
            'created': time.time()
        }
        
        # Log flow installation
        self._log_flow_locked(src_ip_real, src_vip, dst_ip_real, dst_vip, 
                             datapath.id, cookie)
    
    def _add_flow(self, datapath, priority, match, actions, idle, hard, cookie):
        """Helper to add flow with instructions"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle,
            hard_timeout=hard,
            cookie=cookie,
            flags=ofproto.OFPFF_SEND_FLOW_REM
        )
        datapath.send_msg(mod)
    
    def _log_flow_locked(self, src_real, src_vip, dst_real, dst_vip, switch_id, cookie):
        """Log flow lock with beautiful formatting"""
        panel = Panel(
            f"[yellow]SRC:[/yellow] {src_real} → [cyan]{src_vip}[/cyan]\n"
            f"[yellow]DST:[/yellow] {dst_real} → [cyan]{dst_vip}[/cyan]\n"
            f"[yellow]SWITCH:[/yellow] s{switch_id}\n"
            f"[yellow]COOKIE:[/yellow] 0x{cookie:x}",
            title="[green bold]🔒 FLOW LOCKED[/green bold]",
            border_style="green"
        )
        console.print(panel)
    
    def shuffle_vips(self):
        """Shuffle all VIP assignments (for MTD)"""
        console.print("\n[magenta bold]🔄 VIP SHUFFLE INITIATED[/magenta bold]\n")
        
        old_mappings = self.real_to_virtual.copy()
        
        for real_ip in list(self.real_to_virtual.keys()):
            old_vip = self.real_to_virtual[real_ip]
            
            # Return old VIP to pool
            self.virtual_pool.add(old_vip)
            
            # Allocate new VIP
            if self.virtual_pool:
                new_vip = self.virtual_pool.pop()
                self.real_to_virtual[real_ip] = new_vip
                self.virtual_to_real.pop(old_vip, None)
                self.virtual_to_real[new_vip] = real_ip
                
                console.print(f"[cyan]{real_ip}[/cyan]: {old_vip} → [green]{new_vip}[/green]")


# ============================================================================
# PHASE 4: ATTACK DETECTION & TRIGGERED MTD
# Lightweight detection with adaptive defense
# ============================================================================

class AttackDetector:
    """
    Detects suspicious patterns and triggers MTD responses
    """
    
    def __init__(self):
        self.syn_tracker = {}      # src_ip -> count
        self.icmp_tracker = {}     # src_ip -> count
        self.port_scanner = {}     # src_ip -> set(dst_ports)
        self.window_size = 10      # seconds
        self.last_cleanup = time.time()
        
        # Thresholds
        self.SYN_THRESHOLD = 50
        self.ICMP_THRESHOLD = 100
        self.PORT_SCAN_THRESHOLD = 20
    
    def track_syn(self, src_ip):
        """Track SYN packets for rate analysis"""
        self.syn_tracker[src_ip] = self.syn_tracker.get(src_ip, 0) + 1
        
        if self.syn_tracker[src_ip] > self.SYN_THRESHOLD:
            self._alert("SYN_SCAN", src_ip, self.syn_tracker[src_ip])
            return True
        return False
    
    def track_icmp(self, src_ip):
        """Track ICMP for flood detection"""
        self.icmp_tracker[src_ip] = self.icmp_tracker.get(src_ip, 0) + 1
        
        if self.icmp_tracker[src_ip] > self.ICMP_THRESHOLD:
            self._alert("ICMP_FLOOD", src_ip, self.icmp_tracker[src_ip])
            return True
        return False
    
    def track_port_scan(self, src_ip, dst_port):
        """Track port scanning behavior"""
        if src_ip not in self.port_scanner:
            self.port_scanner[src_ip] = set()
        
        self.port_scanner[src_ip].add(dst_port)
        
        if len(self.port_scanner[src_ip]) > self.PORT_SCAN_THRESHOLD:
            self._alert("PORT_SCAN", src_ip, len(self.port_scanner[src_ip]))
            return True
        return False
    
    def cleanup(self):
        """Periodic cleanup of tracking data"""
        now = time.time()
        if now - self.last_cleanup > self.window_size:
            self.syn_tracker.clear()
            self.icmp_tracker.clear()
            self.port_scanner.clear()
            self.last_cleanup = now
    
    def _alert(self, attack_type, src_ip, count):
        """Alert on detected attack"""
        panel = Panel(
            f"[red]TYPE:[/red] {attack_type}\n"
            f"[red]SOURCE:[/red] {src_ip}\n"
            f"[red]COUNT:[/red] {count}\n"
            f"[red]ACTION:[/red] Triggering MTD shuffle",
            title="[red bold]🚨 ATTACK DETECTED[/red bold]",
            border_style="red"
        )
        console.print(panel)


# ============================================================================
# MAIN CONTROLLER - INTEGRATES ALL PHASES
# ============================================================================

class StatefulMTDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(StatefulMTDController, self).__init__(*args, **kwargs)
        
        # Phase configuration
        self.phase = PHASE  # Use global constant
        
        # Components
        self.switches = {}          # dpid -> BaselineLearningSwitch
        self.monitor = TrafficMonitor()
        self.vip = IPVirtualization()
        self.detector = AttackDetector()
        
        # MTD settings
        self.shuffle_interval = 30  # seconds
        self.shuffle_thread = None
        
        self._print_banner()
        
        if self.phase >= 3:
            self.shuffle_thread = hub.spawn(self._mtd_loop)
    
    def _print_banner(self):
        """Print startup banner"""
        banner = f"""
╔══════════════════════════════════════════════════════════╗
║  STATEFUL SDN MOVING TARGET DEFENSE SYSTEM              ║
║  Phase {self.phase}: {self._get_phase_name()}
║  OpenFlow 1.3 | Ryu Framework                           ║
╚══════════════════════════════════════════════════════════╝
        """
        console.print(banner, style="bold cyan")
    
    def _get_phase_name(self):
        """Get phase name"""
        phases = {
            0: "Baseline Learning Switch          ",
            1: "Traffic Visibility Layer           ",
            2: "IP Virtualization                  ",
            3: "Controlled IP Shuffling            ",
            4: "Attack-Triggered MTD               "
        }
        return phases.get(self.phase, "Unknown Phase")
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection"""
        datapath = ev.msg.datapath
        dpid = datapath.id
        
        console.print(f"[green]✓ Switch s{dpid} connected[/green]")
        
        # Initialize baseline switch
        self.switches[dpid] = BaselineLearningSwitch(datapath)
        
        # Install table-miss flow
        self._install_table_miss(datapath)
    
    def _install_table_miss(self, datapath):
        """Install table-miss flow entry"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Main packet processing logic"""
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        
        if dpid not in self.switches:
            return
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Phase 0: Pure learning switch
        if self.phase == 0:
            self.switches[dpid].handle_packet(msg, pkt, eth)
            return
        
        # Extract protocols
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        
        # Handle ARP (never rewrite)
        if arp_pkt:
            self.switches[dpid].handle_packet(msg, pkt, eth)
            return
        
        # Phase 1: Monitor traffic
        if self.phase >= 1 and ipv4_pkt:
            protocol = "TCP" if tcp_pkt else "UDP" if udp_pkt else "ICMP" if icmp_pkt else "IP"
            self.monitor.log_flow(eth.src, eth.dst, ipv4_pkt.src, ipv4_pkt.dst, 
                                 protocol, dpid)
        
        # Phase 2+: IP virtualization
        if self.phase >= 2 and ipv4_pkt:
            in_port = msg.match['in_port']
            
            # Determine output port (use baseline logic)
            out_port = self.switches[dpid].handle_packet(msg, pkt, eth)
            
            if out_port != datapath.ofproto.OFPP_FLOOD:
                # Install rewrite flows
                self.vip.install_rewrite_flows(
                    datapath, in_port, out_port,
                    ipv4_pkt.src, ipv4_pkt.dst,
                    eth.src, eth.dst
                )
            return
        
        # Phase 4: Attack detection
        if self.phase >= 4:
            if tcp_pkt and tcp_pkt.bits & 0x02:  # SYN flag
                if self.detector.track_syn(ipv4_pkt.src):
                    self._trigger_emergency_shuffle()
            
            if icmp_pkt:
                if self.detector.track_icmp(ipv4_pkt.src):
                    self._trigger_emergency_shuffle()
            
            if tcp_pkt:
                if self.detector.track_port_scan(ipv4_pkt.src, tcp_pkt.dst_port):
                    self._trigger_emergency_shuffle()
            
            self.detector.cleanup()
        
        # Fallback to baseline
        self.switches[dpid].handle_packet(msg, pkt, eth)
    
    def _mtd_loop(self):
        """Background MTD shuffle loop"""
        while True:
            hub.sleep(self.shuffle_interval)
            console.print(f"\n[yellow]⏰ Scheduled shuffle (interval: {self.shuffle_interval}s)[/yellow]\n")
            self.vip.shuffle_vips()
    
    def _trigger_emergency_shuffle(self):
        """Trigger immediate VIP shuffle on attack detection"""
        console.print("\n[red bold]⚡ EMERGENCY SHUFFLE TRIGGERED[/red bold]\n")
        self.vip.shuffle_vips()


# Entry point - no custom argument parsing needed
if __name__ == '__main__':
    from ryu.cmd import manager
    import sys
    sys.argv = ['ryu-manager', __file__]
    manager.main()