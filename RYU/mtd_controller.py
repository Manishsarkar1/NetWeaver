#!/usr/bin/env python3
"""
Stateful SDN Moving Target Defense Controller (Ryu + OpenFlow 1.3)

Features:
- Phase 0: Baseline learning switch (pure L2 forwarding)
- Phase 1: Traffic visibility (passive monitoring, classification)
- Phase 2: Flow-locked IP virtualization (paired forward/reverse rewrites)
- Phase 3: Controlled IP shuffling (time or trigger based; never reshuffle active flows)
- Phase 4: Attack detection & triggered MTD (SYN/ICMP/port-scan detectors)

Design principles (why):
- Deterministic VIP allocation: avoid non-determinism across runs and tests.
- Paired flows with same cookie: allow safe deletion by cookie and atomic swap.
- Track last_seen and handle flow-removed events: know which flows are active.
- Install new flows before deleting old ones during shuffle: avoid transient blackholes.
- Never rewrite ARP: preserve host discovery and ping reliability.
"""

import os
import time
import struct
import socket
import threading

from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp, udp
from ryu.lib import hub

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# ====================================================================
# CONFIGURATION
# ====================================================================
PHASE = int(os.environ.get('MTD_PHASE', 0))  # 0..4
# Shuffle interval for scheduled shuffles (phase >=3)
DEFAULT_SHUFFLE_INTERVAL = 30  # seconds
# Active threshold: flows seen within this many seconds are considered active and not reshuffled
DEFAULT_ACTIVE_THRESHOLD = 60  # seconds

# ====================================================================
# PHASE 0: Baseline Learning Switch
# ====================================================================
class BaselineLearningSwitch:
    """
    Pure L2 learning switch.
    Kept minimal and deterministic: this is the stable baseline that must
    always preserve connectivity (pingall).
    """
    def __init__(self, datapath):
        self.dp = datapath
        self.ofproto = datapath.ofproto
        self.parser = datapath.ofproto_parser
        self.mac_to_port = {}

    def add_flow(self, priority, match, actions, idle=0, hard=0, cookie=0):
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
        in_port = msg.match['in_port']
        dpid = self.dp.id

        # Learn source MAC -> port
        self.mac_to_port[eth.src] = in_port

        # Determine output port
        if eth.dst in self.mac_to_port:
            out_port = self.mac_to_port[eth.dst]
        else:
            out_port = self.ofproto.OFPP_FLOOD

        actions = [self.parser.OFPActionOutput(out_port)]

        # Install flow for known destination to reduce controller load
        if out_port != self.ofproto.OFPP_FLOOD:
            match = self.parser.OFPMatch(
                in_port=in_port,
                eth_dst=eth.dst,
                eth_src=eth.src
            )
            self.add_flow(priority=10, match=match, actions=actions, idle=30, hard=60)

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

# ====================================================================
# PHASE 1: Traffic Monitor
# ====================================================================
class TrafficMonitor:
    """
    Passive traffic visibility. Tracks MAC->IP->switch->port and classifies zones.
    This component never modifies packets.
    """
    def __init__(self):
        self.host_table = {}  # mac -> {ip, switch, port, last_seen}
        self.flow_stats = {}  # flow_id -> stats

    def update_host(self, mac, ip, switch_id, port):
        self.host_table[mac] = {
            'ip': ip,
            'switch': switch_id,
            'port': port,
            'last_seen': time.time()
        }

    def _in_subnet(self, ip, subnet):
        try:
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            net, mask = subnet.split('/')
            net_int = struct.unpack('!I', socket.inet_aton(net))[0]
            mask_int = (0xffffffff << (32 - int(mask))) & 0xffffffff
            return (ip_int & mask_int) == (net_int & mask_int)
        except Exception:
            return False

    def classify_zone(self, src_ip, dst_ip, real_subnet='10.0.0.0/24', virtual_subnet='192.168.100.0/24'):
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

    def log_flow(self, src_mac, dst_mac, src_ip, dst_ip, protocol, switch_id):
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

# ====================================================================
# PHASE 2: IP Virtualization (flow-locked)
# ====================================================================
class IPVirtualization:
    """
    Manage deterministic VIP allocation and flow-level state.
    Key invariants:
    - VIP allocation is deterministic (list, pop(0))
    - Each flow pair (forward+reverse) uses the same cookie
    - Flow state stores last_seen to protect active flows during shuffles
    - Rewrites are reversible and installed atomically (install new flows before deleting old)
    """
    def __init__(self):
        self.real_to_virtual = {}    # real_ip -> vip
        self.virtual_to_real = {}    # vip -> real_ip
        self.active_flows = {}       # cookie -> flow metadata
        self.next_cookie = 0x1000
        self.virtual_pool = []
        self._init_virtual_pool()

    def _init_virtual_pool(self):
        # Deterministic ascending VIP pool
        for i in range(1, 255):
            self.virtual_pool.append(f"192.168.100.{i}")

    def allocate_vip(self, real_ip):
        # Return existing mapping if present
        if real_ip in self.real_to_virtual:
            return self.real_to_virtual[real_ip]
        if not self.virtual_pool:
            raise Exception("Virtual IP pool exhausted")
        vip = self.virtual_pool.pop(0)  # deterministic: lowest available
        self.real_to_virtual[real_ip] = vip
        self.virtual_to_real[vip] = real_ip
        console.print(f"[green]VIP ALLOCATED[/green]: {real_ip} → {vip}")
        return vip

    def release_vip(self, vip):
        # Return VIP to pool deterministically (append to end)
        if not vip:
            return
        if vip in self.virtual_pool:
            return
        # Remove mapping if exists
        real = self.virtual_to_real.pop(vip, None)
        if real:
            self.real_to_virtual.pop(real, None)
        self.virtual_pool.append(vip)

    def get_real_ip(self, virtual_ip):
        return self.virtual_to_real.get(virtual_ip)

    def create_flow_pair_cookie(self):
        cookie = self.next_cookie
        self.next_cookie += 1
        return cookie

    def _add_flow(self, datapath, priority, match, actions, idle, hard, cookie):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
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

    def install_rewrite_flows(self, datapath, in_port, out_port,
                              src_ip_real, dst_ip_real, eth_src, eth_dst,
                              proto=None, src_port=None, dst_port=None,
                              idle=30, hard=60):
        """
        Install paired forward and reverse flows that rewrite both source and destination IPs.
        Forward: Real_A -> Real_B  (rewrite src->VIP_A, dst->VIP_B)
        Reverse: Reply from Real_B -> Real_A (match on src=Real_B, dst=VIP_B; rewrite dst->Real_A, src->Real_B)
        Both flows share the same cookie for atomic deletion.
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Allocate VIPs deterministically
        src_vip = self.allocate_vip(src_ip_real)
        dst_vip = self.allocate_vip(dst_ip_real)

        cookie = self.create_flow_pair_cookie()

        # Build forward match (match on IPs and optionally transport ports)
        match_fields_fwd = {
            'eth_type': 0x0800,
            'ipv4_src': src_ip_real,
            'ipv4_dst': dst_ip_real
        }
        if proto == 'TCP':
            match_fields_fwd['ip_proto'] = 6
            if src_port:
                match_fields_fwd['tcp_src'] = src_port
            if dst_port:
                match_fields_fwd['tcp_dst'] = dst_port
        elif proto == 'UDP':
            match_fields_fwd['ip_proto'] = 17
            if src_port:
                match_fields_fwd['udp_src'] = src_port
            if dst_port:
                match_fields_fwd['udp_dst'] = dst_port

        match_fwd = parser.OFPMatch(**match_fields_fwd)

        actions_fwd = [
            parser.OFPActionSetField(ipv4_src=src_vip),
            parser.OFPActionSetField(ipv4_dst=dst_vip),
            parser.OFPActionOutput(out_port)
        ]

        self._add_flow(datapath, priority=200, match=match_fwd,
                       actions=actions_fwd, idle=idle, hard=hard, cookie=cookie)

        # Reverse flow: packets from Real_B to VIP_B (reply path)
        match_fields_rev = {
            'eth_type': 0x0800,
            'ipv4_src': dst_ip_real,
            'ipv4_dst': dst_vip
        }
        if proto == 'TCP':
            match_fields_rev['ip_proto'] = 6
            if src_port:
                match_fields_rev['tcp_dst'] = src_port  # reply dst is original src port
            if dst_port:
                match_fields_rev['tcp_src'] = dst_port
        elif proto == 'UDP':
            match_fields_rev['ip_proto'] = 17
            if src_port:
                match_fields_rev['udp_dst'] = src_port
            if dst_port:
                match_fields_rev['udp_src'] = dst_port

        match_rev = parser.OFPMatch(**match_fields_rev)

        actions_rev = [
            parser.OFPActionSetField(ipv4_dst=src_ip_real),
            parser.OFPActionSetField(ipv4_src=dst_ip_real),
            parser.OFPActionOutput(in_port)
        ]

        self._add_flow(datapath, priority=200, match=match_rev,
                       actions=actions_rev, idle=idle, hard=hard, cookie=cookie)

        # Store flow state (last_seen will be updated on packet events)
        self.active_flows[cookie] = {
            'src_real': src_ip_real,
            'dst_real': dst_ip_real,
            'src_vip': src_vip,
            'dst_vip': dst_vip,
            'switch': datapath.id,
            'created': time.time(),
            'last_seen': time.time(),
            'cookie': cookie,
            'proto': proto,
            'in_port': in_port,
            'out_port': out_port
        }

        # Log flow lock
        self._log_flow_locked(src_ip_real, src_vip, dst_ip_real, dst_vip, datapath.id, cookie)

        return cookie

    def _log_flow_locked(self, src_real, src_vip, dst_real, dst_vip, switch_id, cookie):
        panel = Panel(
            f"[yellow]SRC:[/yellow] {src_real} → [cyan]{src_vip}[/cyan]\n"
            f"[yellow]DST:[/yellow] {dst_real} → [cyan]{dst_vip}[/cyan]\n"
            f"[yellow]SWITCH:[/yellow] s{switch_id}\n"
            f"[yellow]COOKIE:[/yellow] 0x{cookie:x}",
            title="[green bold]🔒 FLOW LOCKED[/green bold]",
            border_style="green"
        )
        console.print(panel)

    # Helper to delete flows by cookie (use cookie and cookie_mask)
    def delete_flows_by_cookie(self, datapath, cookie):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Delete flows with exact cookie
        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            cookie_mask=0xffffffffffffffff,
            table_id=ofproto.OFPTT_ALL,
            command=ofproto.OFPFC_DELETE
        )
        datapath.send_msg(mod)

    # Helper to install paired flows given explicit VIPs and cookie (used during shuffle)
    def install_paired_flows_with_vips(self, datapath, in_port, out_port,
                                       src_real, dst_real, src_vip, dst_vip,
                                       proto=None, src_port=None, dst_port=None,
                                       idle=30, hard=60, cookie=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        if cookie is None:
            cookie = self.create_flow_pair_cookie()

        # Forward
        match_fields_fwd = {
            'eth_type': 0x0800,
            'ipv4_src': src_real,
            'ipv4_dst': dst_real
        }
        if proto == 'TCP':
            match_fields_fwd['ip_proto'] = 6
            if src_port:
                match_fields_fwd['tcp_src'] = src_port
            if dst_port:
                match_fields_fwd['tcp_dst'] = dst_port
        elif proto == 'UDP':
            match_fields_fwd['ip_proto'] = 17
            if src_port:
                match_fields_fwd['udp_src'] = src_port
            if dst_port:
                match_fields_fwd['udp_dst'] = dst_port

        match_fwd = parser.OFPMatch(**match_fields_fwd)
        actions_fwd = [
            parser.OFPActionSetField(ipv4_src=src_vip),
            parser.OFPActionSetField(ipv4_dst=dst_vip),
            parser.OFPActionOutput(out_port)
        ]
        self._add_flow(datapath, priority=200, match=match_fwd,
                       actions=actions_fwd, idle=idle, hard=hard, cookie=cookie)

        # Reverse
        match_fields_rev = {
            'eth_type': 0x0800,
            'ipv4_src': dst_real,
            'ipv4_dst': dst_vip
        }
        if proto == 'TCP':
            match_fields_rev['ip_proto'] = 6
            if src_port:
                match_fields_rev['tcp_dst'] = src_port
            if dst_port:
                match_fields_rev['tcp_src'] = dst_port
        elif proto == 'UDP':
            match_fields_rev['ip_proto'] = 17
            if src_port:
                match_fields_rev['udp_dst'] = src_port
            if dst_port:
                match_fields_rev['udp_src'] = dst_port

        match_rev = parser.OFPMatch(**match_fields_rev)
        actions_rev = [
            parser.OFPActionSetField(ipv4_dst=src_real),
            parser.OFPActionSetField(ipv4_src=dst_real),
            parser.OFPActionOutput(in_port)
        ]
        self._add_flow(datapath, priority=200, match=match_rev,
                       actions=actions_rev, idle=idle, hard=hard, cookie=cookie)

        # Return cookie used
        return cookie

    # Shuffle algorithm: only reshuffle inactive flows
    def shuffle_vips_safe(self, datapath_getter, active_threshold=DEFAULT_ACTIVE_THRESHOLD):
        """
        Shuffle VIPs only for flows that have been inactive for at least active_threshold seconds.
        Steps for each inactive flow:
          1. Allocate new VIPs deterministically
          2. Install new paired flows (new cookie)
          3. Delete old flows by cookie
          4. Release old VIPs
          5. Update active_flows mapping
        This preserves connectivity by installing new flows before deleting old ones.
        """
        console.print("\n[magenta bold]🔄 VIP SHUFFLE INITIATED (safe)[/magenta bold]\n")
        now = time.time()
        # Collect candidates (cookie keys) to shuffle
        candidates = []
        for cookie, f in list(self.active_flows.items()):
            last = f.get('last_seen', f.get('created', 0))
            if now - last > active_threshold:
                candidates.append((cookie, f))

        if not candidates:
            console.print("[yellow]No inactive flows eligible for shuffle.[/yellow]")
            return

        for old_cookie, f in candidates:
            src_real = f['src_real']
            dst_real = f['dst_real']
            dp_id = f['switch']
            datapath = datapath_getter(dp_id)
            if datapath is None:
                console.print(f"[red]Datapath s{dp_id} not found; skipping shuffle for cookie 0x{old_cookie:x}[/red]")
                continue

            old_src_vip = f['src_vip']
            old_dst_vip = f['dst_vip']

            # Allocate new VIPs deterministically
            new_src_vip = self.allocate_vip(src_real)
            new_dst_vip = self.allocate_vip(dst_real)

            # Install new paired flows with new cookie
            new_cookie = self.create_flow_pair_cookie()
            self.install_paired_flows_with_vips(
                datapath,
                in_port=f.get('in_port'),
                out_port=f.get('out_port'),
                src_real=src_real,
                dst_real=dst_real,
                src_vip=new_src_vip,
                dst_vip=new_dst_vip,
                proto=f.get('proto'),
                src_port=None,
                dst_port=None,
                idle=30,
                hard=60,
                cookie=new_cookie
            )

            # Delete old flows by cookie
            self.delete_flows_by_cookie(datapath, old_cookie)

            # Release old VIPs
            self.release_vip(old_src_vip)
            self.release_vip(old_dst_vip)

            # Update active_flows mapping
            old_entry = self.active_flows.pop(old_cookie, None)
            self.active_flows[new_cookie] = {
                'src_real': src_real,
                'dst_real': dst_real,
                'src_vip': new_src_vip,
                'dst_vip': new_dst_vip,
                'switch': dp_id,
                'created': time.time(),
                'last_seen': old_entry.get('last_seen', old_entry.get('created', time.time())),
                'cookie': new_cookie,
                'proto': old_entry.get('proto'),
                'in_port': old_entry.get('in_port'),
                'out_port': old_entry.get('out_port')
            }

            # Log mapping change
            console.print(f"[cyan]{src_real}[/cyan]: {old_src_vip} → [green]{new_src_vip}[/green]")
            console.print(f"[cyan]{dst_real}[/cyan]: {old_dst_vip} → [green]{new_dst_vip}[/green]")

# ====================================================================
# PHASE 4: Attack Detector
# ====================================================================
class AttackDetector:
    """
    Lightweight detectors for SYN scans, ICMP floods, and port sweeps.
    On detection, it signals for an emergency shuffle (controller coordinates).
    """
    def __init__(self):
        self.syn_tracker = {}      # src_ip -> count
        self.icmp_tracker = {}     # src_ip -> count
        self.port_scanner = {}     # src_ip -> set(dst_ports)
        self.window_size = 10      # seconds
        self.last_cleanup = time.time()
        # Thresholds (tunable)
        self.SYN_THRESHOLD = 50
        self.ICMP_THRESHOLD = 100
        self.PORT_SCAN_THRESHOLD = 20

    def track_syn(self, src_ip):
        self.syn_tracker[src_ip] = self.syn_tracker.get(src_ip, 0) + 1
        if self.syn_tracker[src_ip] > self.SYN_THRESHOLD:
            self._alert("SYN_SCAN", src_ip, self.syn_tracker[src_ip])
            return True
        return False

    def track_icmp(self, src_ip):
        self.icmp_tracker[src_ip] = self.icmp_tracker.get(src_ip, 0) + 1
        if self.icmp_tracker[src_ip] > self.ICMP_THRESHOLD:
            self._alert("ICMP_FLOOD", src_ip, self.icmp_tracker[src_ip])
            return True
        return False

    def track_port_scan(self, src_ip, dst_port):
        if src_ip not in self.port_scanner:
            self.port_scanner[src_ip] = set()
        self.port_scanner[src_ip].add(dst_port)
        if len(self.port_scanner[src_ip]) > self.PORT_SCAN_THRESHOLD:
            self._alert("PORT_SCAN", src_ip, len(self.port_scanner[src_ip]))
            return True
        return False

    def cleanup(self):
        now = time.time()
        if now - self.last_cleanup > self.window_size:
            self.syn_tracker.clear()
            self.icmp_tracker.clear()
            self.port_scanner.clear()
            self.last_cleanup = now

    def _alert(self, attack_type, src_ip, count):
        panel = Panel(
            f"[red]TYPE:[/red] {attack_type}\n"
            f"[red]SOURCE:[/red] {src_ip}\n"
            f"[red]COUNT:[/red] {count}\n"
            f"[red]ACTION:[/red] Triggering MTD shuffle",
            title="[red bold]🚨 ATTACK DETECTED[/red bold]",
            border_style="red"
        )
        console.print(panel)

# ====================================================================
# MAIN CONTROLLER
# ====================================================================
class StatefulMTDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(StatefulMTDController, self).__init__(*args, **kwargs)
        self.phase = PHASE
        self.switches = {}  # dpid -> BaselineLearningSwitch
        self.monitor = TrafficMonitor()
        self.vip = IPVirtualization()
        self.detector = AttackDetector()

        self.shuffle_interval = DEFAULT_SHUFFLE_INTERVAL
        self.shuffle_thread = None
        self._shuffle_mutex = threading.Lock()
        self._datapaths = {}  # dpid -> datapath object (for lookup)

        self._print_banner()

        # Start scheduled shuffle thread only for phase >= 3
        if self.phase >= 3:
            self.shuffle_thread = hub.spawn(self._mtd_loop)

    def _print_banner(self):
        banner = f"""
╔══════════════════════════════════════════════════════════╗
║  STATEFUL SDN MOVING TARGET DEFENSE SYSTEM              ║
║  Phase {self.phase}: {self._get_phase_name()}
║  OpenFlow 1.3 | Ryu Framework                           ║
╚══════════════════════════════════════════════════════════╝
        """
        console.print(banner, style="bold cyan")

    def _get_phase_name(self):
        phases = {
            0: "Baseline Learning Switch          ",
            1: "Traffic Visibility Layer           ",
            2: "IP Virtualization                  ",
            3: "Controlled IP Shuffling            ",
            4: "Attack-Triggered MTD               "
        }
        return phases.get(self.phase, "Unknown Phase")

    # -------------------------
    # Switch connection handlers
    # -------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        console.print(f"[green]✓ Switch s{dpid} connected[/green]")
        self.switches[dpid] = BaselineLearningSwitch(datapath)
        self._datapaths[dpid] = datapath
        self._install_table_miss(datapath)

    def _install_table_miss(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    # -------------------------
    # Packet-in handler
    # -------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        if dpid not in self.switches:
            # Should not happen, but be defensive
            return

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Phase 0: baseline learning switch only
        if self.phase == 0:
            self.switches[dpid].handle_packet(msg, pkt, eth)
            return

        # Extract protocols
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        # Always handle ARP with baseline (never rewrite ARP)
        if arp_pkt:
            self.switches[dpid].handle_packet(msg, pkt, eth)
            return

        # Phase 1: passive monitoring
        if self.phase >= 1 and ipv4_pkt:
            protocol = "TCP" if tcp_pkt else "UDP" if udp_pkt else "ICMP" if icmp_pkt else "IP"
            self.monitor.log_flow(eth.src, eth.dst, ipv4_pkt.src, ipv4_pkt.dst, protocol, dpid)

        # Phase 2+: IP virtualization and flow-locked rewriting
        if self.phase >= 2 and ipv4_pkt:
            in_port = msg.match['in_port']
            # Use baseline to learn MACs and determine out_port
            out_port = self.switches[dpid].handle_packet(msg, pkt, eth)

            # If flood, do not install rewrite flows (let learning switch flood)
            if out_port == datapath.ofproto.OFPP_FLOOD:
                return

            # Determine transport info for more specific matching (optional)
            proto = None
            src_port = None
            dst_port = None
            if tcp_pkt:
                proto = 'TCP'
                src_port = tcp_pkt.src_port
                dst_port = tcp_pkt.dst_port
            elif udp_pkt:
                proto = 'UDP'
                src_port = udp_pkt.src_port
                dst_port = udp_pkt.dst_port

            # Install paired rewrite flows (this will allocate VIPs deterministically)
            cookie = self.vip.install_rewrite_flows(
                datapath=datapath,
                in_port=in_port,
                out_port=out_port,
                src_ip_real=ipv4_pkt.src,
                dst_ip_real=ipv4_pkt.dst,
                eth_src=eth.src,
                eth_dst=eth.dst,
                proto=proto,
                src_port=src_port,
                dst_port=dst_port,
                idle=30,
                hard=60
            )

            # After installing flows, we should not process this packet further (flows will handle)
            return

        # Phase 4: attack detection (only runs if phase >= 4)
        if self.phase >= 4 and ipv4_pkt:
            if tcp_pkt and (tcp_pkt.bits & 0x02):  # SYN flag
                if self.detector.track_syn(ipv4_pkt.src):
                    self._trigger_emergency_shuffle()

            if icmp_pkt:
                if self.detector.track_icmp(ipv4_pkt.src):
                    self._trigger_emergency_shuffle()

            if tcp_pkt:
                if self.detector.track_port_scan(ipv4_pkt.src, tcp_pkt.dst_port):
                    self._trigger_emergency_shuffle()

            self.detector.cleanup()

        # Fallback: baseline forwarding
        self.switches[dpid].handle_packet(msg, pkt, eth)

    # -------------------------
    # Flow removed handler
    # -------------------------
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        cookie = msg.cookie
        # When a flow is removed, free VIPs and remove state
        if cookie in self.vip.active_flows:
            f = self.vip.active_flows.pop(cookie)
            console.print(f"[yellow]Flow removed cookie 0x{cookie:x}[/yellow]")
            # Release VIPs deterministically
            self.vip.release_vip(f.get('src_vip'))
            self.vip.release_vip(f.get('dst_vip'))

    # -------------------------
    # Helper: get datapath by dpid
    # -------------------------
    def _get_datapath(self, dpid):
        return self._datapaths.get(dpid)

    # -------------------------
    # MTD loop and shuffle coordination
    # -------------------------
    def _mtd_loop(self):
        """Scheduled shuffle loop (runs in a green thread)."""
        while True:
            hub.sleep(self.shuffle_interval)
            console.print(f"\n[yellow]⏰ Scheduled shuffle (interval: {self.shuffle_interval}s)[/yellow]\n")
            # Acquire mutex to avoid concurrent shuffles
            with self._shuffle_mutex:
                self.vip.shuffle_vips_safe(self._get_datapath, active_threshold=DEFAULT_ACTIVE_THRESHOLD)

    def _trigger_emergency_shuffle(self):
        """Trigger immediate VIP shuffle on attack detection (synchronized)."""
        console.print("\n[red bold]⚡ EMERGENCY SHUFFLE TRIGGERED[/red bold]\n")
        # Run shuffle synchronously under lock to avoid races with scheduled shuffle
        with self._shuffle_mutex:
            # Optionally reduce active_threshold to be more aggressive during emergency
            self.vip.shuffle_vips_safe(self._get_datapath, active_threshold=int(DEFAULT_ACTIVE_THRESHOLD / 2))

    # -------------------------
    # Update last_seen for flows when relevant (optional improvement)
    # -------------------------
    # This method can be called by packet processing paths if you detect a packet
    # that belongs to an existing flow mapping. For simplicity, we update last_seen
    # in install_rewrite_flows and rely on flow-removed events and scheduled updates.
    def update_flow_last_seen(self, src_real, dst_real):
        now = time.time()
        for cookie, f in self.vip.active_flows.items():
            if f['src_real'] == src_real and f['dst_real'] == dst_real:
                f['last_seen'] = now
                break

# Entry point for running as a script
if __name__ == '__main__':
    from ryu.cmd import manager
    import sys
    sys.argv = ['ryu-manager', __file__]
    manager.main()
