#!/usr/bin/env python3
"""
Stateful SDN MTD Controller (Ryu + OpenFlow 1.3)

Reply-triggered morphing:
- After each successful ICMP echo reply, immediately reshuffle VIPs for the two endpoints.
- Atomic update: install new paired flows first, then delete old flows by cookie.
- Edge-only rewrites on the true ingress (host access) switch to avoid multi-hop mismatch.
- Deterministic VIP allocation (ordered list).
- Flow index to find and replace the exact flow pair per (switch, src, dst).
- ARP untouched.

Usage:
    export MTD_PHASE=2
    export MTD_MORPH=reply
    ryu-manager mtd_controller.py
"""
import os
import time
import struct
import socket
import threading
from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp, udp
from ryu.lib import hub

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# =============================================================================
# CONFIG
# =============================================================================
PHASE = int(os.environ.get('MTD_PHASE', 0))       # 0..4
MORPH_STRATEGY = os.environ.get('MTD_MORPH', 'reply')  # 'reply' or 'time'
DEFAULT_SHUFFLE_INTERVAL = 30  # seconds (used only if time strategy)
HOST_DEBOUNCE = 0.2            # seconds before treating a port as stable ingress
IDLE_TIMEOUT = 60              # seconds for installed flows
HARD_TIMEOUT = 120             # seconds

# =============================================================================
# PHASE 0: Baseline learning switch
# =============================================================================
class BaselineLearningSwitch:
    def __init__(self, datapath):
        self.dp = datapath
        self.ofproto = datapath.ofproto
        self.parser = datapath.ofproto_parser
        self.mac_to_port = {}

    def add_flow(self, priority, match, actions, idle=0, hard=0, cookie=0):
        inst = [self.parser.OFPInstructionActions(self.ofproto.OFPIT_APPLY_ACTIONS, actions)]
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
        # Learn MAC
        self.mac_to_port[eth.src] = in_port
        # Choose out port
        if eth.dst in self.mac_to_port:
            out_port = self.mac_to_port[eth.dst]
        else:
            out_port = self.ofproto.OFPP_FLOOD
        actions = [self.parser.OFPActionOutput(out_port)]
        # Install L2 flow if known
        if out_port != self.ofproto.OFPP_FLOOD:
            match = self.parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            self.add_flow(priority=10, match=match, actions=actions, idle=IDLE_TIMEOUT, hard=HARD_TIMEOUT)
        # Send packet
        data = msg.data if msg.buffer_id == self.ofproto.OFP_NO_BUFFER else None
        out = self.parser.OFPPacketOut(datapath=self.dp, buffer_id=msg.buffer_id,
                                       in_port=in_port, actions=actions, data=data)
        self.dp.send_msg(out)
        return out_port

# =============================================================================
# PHASE 1: Traffic monitor
# =============================================================================
class TrafficMonitor:
    def __init__(self):
        self.host_table = {}  # mac -> {ip, switch, port, last_seen}

    def update_host(self, mac, ip, switch_id, port):
        self.host_table[mac] = {'ip': ip, 'switch': switch_id, 'port': port, 'last_seen': time.time()}

    def _in_subnet(self, ip, subnet):
        try:
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            net, mask = subnet.split('/')
            net_int = struct.unpack('!I', socket.inet_aton(net))[0]
            mask_int = (0xffffffff << (32 - int(mask))) & 0xffffffff
            return (ip_int & mask_int) == (net_int & mask_int)
        except Exception:
            return False

    def classify_zone(self, src_ip, dst_ip, real_subnet='10.0.0.0/24'):
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

# =============================================================================
# PHASE 2: IP virtualization (edge-only, reply-triggered morph)
# =============================================================================
class IPVirtualization:
    """
    Deterministic VIP pool, edge-only paired rewrites, per-flow index for safe replacement.
    """
    def __init__(self):
        self.real_to_virtual = {}       # real_ip -> vip
        self.virtual_to_real = {}       # vip -> real_ip
        self.active_flows = {}          # cookie -> flow meta
        self.flow_index = {}            # (switch, src_real, dst_real) -> cookie
        self.next_cookie = 0x1000
        self.virtual_pool = []
        self._init_virtual_pool()

    def _init_virtual_pool(self):
        for i in range(1, 255):
            self.virtual_pool.append(f"192.168.100.{i}")

    def allocate_vip(self, real_ip):
        if real_ip in self.real_to_virtual:
            return self.real_to_virtual[real_ip]
        if not self.virtual_pool:
            raise Exception("Virtual IP pool exhausted")
        vip = self.virtual_pool.pop(0)
        self.real_to_virtual[real_ip] = vip
        self.virtual_to_real[vip] = real_ip
        console.print(f"[green]VIP ALLOCATED[/green]: {real_ip} → {vip}")
        return vip

    def release_vip(self, vip):
        if not vip:
            return
        if vip in self.virtual_pool:
            return
        real = self.virtual_to_real.pop(vip, None)
        if real:
            self.real_to_virtual.pop(real, None)
        self.virtual_pool.append(vip)

    def create_cookie(self):
        c = self.next_cookie
        self.next_cookie += 1
        return c

    def _add_flow(self, datapath, priority, match, actions, idle, hard, cookie):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                instructions=inst,
                                idle_timeout=idle,
                                hard_timeout=hard,
                                cookie=cookie,
                                flags=ofproto.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(mod)

    def _delete_by_cookie(self, datapath, cookie):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        mod = parser.OFPFlowMod(datapath=datapath,
                                cookie=cookie,
                                cookie_mask=0xffffffffffffffff,
                                table_id=ofproto.OFPTT_ALL,
                                command=ofproto.OFPFC_DELETE)
        datapath.send_msg(mod)

    def _log_lock(self, src_real, src_vip, dst_real, dst_vip, switch_id, cookie):
        panel = Panel(
            f"[yellow]SRC:[/yellow] {src_real} → [cyan]{src_vip}[/cyan]\n"
            f"[yellow]DST:[/yellow] {dst_real} → [cyan]{dst_vip}[/cyan]\n"
            f"[yellow]SWITCH:[/yellow] s{switch_id}\n"
            f"[yellow]COOKIE:[/yellow] 0x{cookie:x}",
            title="[green bold]🔒 FLOW LOCKED[/green bold]",
            border_style="green"
        )
        console.print(panel)

    def install_edge_pair(self, datapath, in_port, out_port, src_real, dst_real,
                          idle=IDLE_TIMEOUT, hard=HARD_TIMEOUT):
        """
        Paired forward+reverse flows on ingress switch:
        - Forward match: real src/dst. Actions: set src->vip(src), dst->vip(dst), output out_port.
        - Reverse match: src=real dst, dst=vip(dst). Actions: set dst->real src, output in_port.
        """
        parser = datapath.ofproto_parser
        src_vip = self.allocate_vip(src_real)
        dst_vip = self.allocate_vip(dst_real)
        cookie = self.create_cookie()

        match_fwd = parser.OFPMatch(in_port=in_port, eth_type=0x0800,
                                    ipv4_src=src_real, ipv4_dst=dst_real)
        actions_fwd = [
            parser.OFPActionSetField(ipv4_src=src_vip),
            parser.OFPActionSetField(ipv4_dst=dst_vip),
            parser.OFPActionOutput(out_port)
        ]
        self._add_flow(datapath, priority=200, match=match_fwd, actions=actions_fwd,
                       idle=idle, hard=hard, cookie=cookie)

        match_rev = parser.OFPMatch(eth_type=0x0800, ipv4_src=dst_real, ipv4_dst=dst_vip)
        actions_rev = [
            parser.OFPActionSetField(ipv4_dst=src_real),
            parser.OFPActionSetField(ipv4_src=dst_real),
            parser.OFPActionOutput(in_port)
        ]
        self._add_flow(datapath, priority=200, match=match_rev, actions=actions_rev,
                       idle=idle, hard=hard, cookie=cookie)

        # Track state
        self.active_flows[cookie] = {
            'src_real': src_real, 'dst_real': dst_real,
            'src_vip': src_vip, 'dst_vip': dst_vip,
            'switch': datapath.id, 'created': time.time(),
            'last_seen': time.time(),
            'in_port': in_port, 'out_port': out_port
        }
        self.flow_index[(datapath.id, src_real, dst_real)] = cookie
        self._log_lock(src_real, src_vip, dst_real, dst_vip, datapath.id, cookie)
        return cookie

    def morph_pair_now(self, datapath, src_real, dst_real):
        """
        Change VIPs for src_real and dst_real immediately:
        - Find existing cookie via flow_index.
        - Install new paired flows with new VIPs first.
        - Delete old flows by cookie.
        - Release old VIPs and update indices.
        """
        key = (datapath.id, src_real, dst_real)
        old_cookie = self.flow_index.get(key)
        # If no old flow exists yet, just install new
        in_port = None
        out_port = None
        old_src_vip = None
        old_dst_vip = None

        if old_cookie and old_cookie in self.active_flows:
            f = self.active_flows[old_cookie]
            in_port = f['in_port']
            out_port = f['out_port']
            old_src_vip = f['src_vip']
            old_dst_vip = f['dst_vip']

        # If ports unknown, we can't install; skip safely
        if in_port is None or out_port is None:
            return

        # Allocate new VIPs
        new_src_vip = self.allocate_vip(src_real)
        new_dst_vip = self.allocate_vip(dst_real)

        # Install new paired flows (new cookie)
        new_cookie = self.create_cookie()

        parser = datapath.ofproto_parser

        match_fwd = parser.OFPMatch(in_port=in_port, eth_type=0x0800,
                                    ipv4_src=src_real, ipv4_dst=dst_real)
        actions_fwd = [
            parser.OFPActionSetField(ipv4_src=new_src_vip),
            parser.OFPActionSetField(ipv4_dst=new_dst_vip),
            parser.OFPActionOutput(out_port)
        ]
        self._add_flow(datapath, priority=200, match=match_fwd, actions=actions_fwd,
                       idle=IDLE_TIMEOUT, hard=HARD_TIMEOUT, cookie=new_cookie)

        match_rev = parser.OFPMatch(eth_type=0x0800, ipv4_src=dst_real, ipv4_dst=new_dst_vip)
        actions_rev = [
            parser.OFPActionSetField(ipv4_dst=src_real),
            parser.OFPActionSetField(ipv4_src=dst_real),
            parser.OFPActionOutput(in_port)
        ]
        self._add_flow(datapath, priority=200, match=match_rev, actions=actions_rev,
                       idle=IDLE_TIMEOUT, hard=HARD_TIMEOUT, cookie=new_cookie)

        # Delete old flows and release old VIPs
        if old_cookie:
            self._delete_by_cookie(datapath, old_cookie)
            self.active_flows.pop(old_cookie, None)

        if old_src_vip:
            self.release_vip(old_src_vip)
        if old_dst_vip:
            self.release_vip(old_dst_vip)

        # Update indices
        self.active_flows[new_cookie] = {
            'src_real': src_real, 'dst_real': dst_real,
            'src_vip': new_src_vip, 'dst_vip': new_dst_vip,
            'switch': datapath.id, 'created': time.time(),
            'last_seen': time.time(), 'in_port': in_port, 'out_port': out_port
        }
        self.flow_index[key] = new_cookie

        console.print(f"[yellow]Morph complete on s{datapath.id}[/yellow]: "
                      f"{src_real}: {old_src_vip} → {new_src_vip}, "
                      f"{dst_real}: {old_dst_vip} → {new_dst_vip}")

# =============================================================================
# PHASE 4: Attack detector (unchanged)
# =============================================================================
class AttackDetector:
    def __init__(self):
        self.syn_tracker = {}
        self.icmp_tracker = {}
        self.port_scanner = {}
        self.window_size = 10
        self.last_cleanup = time.time()
        self.SYN_THRESHOLD = 50
        self.ICMP_THRESHOLD = 100
        self.PORT_SCAN_THRESHOLD = 20

    def track_syn(self, src_ip):
        self.syn_tracker[src_ip] = self.syn_tracker.get(src_ip, 0) + 1
        return self.syn_tracker[src_ip] > self.SYN_THRESHOLD

    def track_icmp(self, src_ip):
        self.icmp_tracker[src_ip] = self.icmp_tracker.get(src_ip, 0) + 1
        return self.icmp_tracker[src_ip] > self.ICMP_THRESHOLD

    def track_port_scan(self, src_ip, dst_port):
        self.port_scanner.setdefault(src_ip, set()).add(dst_port)
        return len(self.port_scanner[src_ip]) > self.PORT_SCAN_THRESHOLD

    def cleanup(self):
        now = time.time()
        if now - self.last_cleanup > self.window_size:
            self.syn_tracker.clear()
            self.icmp_tracker.clear()
            self.port_scanner.clear()
            self.last_cleanup = now

# =============================================================================
# MAIN CONTROLLER
# =============================================================================
class StatefulMTDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(StatefulMTDController, self).__init__(*args, **kwargs)
        self.phase = PHASE
        self.morph_strategy = MORPH_STRATEGY
        self.switches = {}
        self.monitor = TrafficMonitor()
        self.vip = IPVirtualization()
        self.detector = AttackDetector()
        self._datapaths = {}
        self._shuffle_mutex = threading.Lock()

        self._print_banner()

        if self.phase >= 3 and self.morph_strategy == 'time':
            hub.spawn(self._mtd_loop)

    def _print_banner(self):
        morph_desc = "Reply-Triggered" if self.morph_strategy == 'reply' else "Time-Based"
        banner = f"""
╔══════════════════════════════════════════════════════════╗
║  STATEFUL SDN MOVING TARGET DEFENSE SYSTEM              ║
║  Phase {self.phase}: {self._get_phase_name()}
║  Morph Strategy: {morph_desc:<35} ║
║  OpenFlow 1.3 | Ryu Framework                           ║
╚══════════════════════════════════════════════════════════╝
        """
        console.print(banner, style="bold cyan")

    def _get_phase_name(self):
        return {
            0: "Baseline Learning Switch          ",
            1: "Traffic Visibility Layer           ",
            2: "IP Virtualization                  ",
            3: "Controlled IP Shuffling            ",
            4: "Attack-Triggered MTD               "
        }.get(self.phase, "Unknown Phase")

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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        if dpid not in self.switches:
            return

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        in_port = msg.match.get('in_port')

        # Phase 0 baseline
        if self.phase == 0:
            self.switches[dpid].handle_packet(msg, pkt, eth)
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        # ARP untouched
        if arp_pkt:
            self.switches[dpid].handle_packet(msg, pkt, eth)
            return

        # Track host attachment
        if ipv4_pkt:
            self.monitor.update_host(eth.src, ipv4_pkt.src, dpid, in_port)

        # Phase 1 logging
        if self.phase >= 1 and ipv4_pkt:
            proto = "TCP" if tcp_pkt else "UDP" if udp_pkt else "ICMP" if icmp_pkt else "IP"
            self.monitor.log_flow(eth.src, eth.dst, ipv4_pkt.src, ipv4_pkt.dst, proto, dpid)

        # Phase 2: virtualization + reply-triggered morph
        if self.phase >= 2 and ipv4_pkt:
            out_port = self.switches[dpid].handle_packet(msg, pkt, eth)
            if out_port == datapath.ofproto.OFPP_FLOOD:
                return

            # Only install on stable host access port (edge-only)
            host = self.monitor.host_table.get(eth.src)
            is_stable_access = False
            if host and host['switch'] == dpid and host['port'] == in_port:
                if time.time() - host['last_seen'] >= HOST_DEBOUNCE:
                    is_stable_access = True
            if not is_stable_access:
                return

            # If we don't have a flow yet for this pair on this switch, install it
            key = (dpid, ipv4_pkt.src, ipv4_pkt.dst)
            if key not in self.vip.flow_index:
                self.vip.install_edge_pair(datapath, in_port, out_port, ipv4_pkt.src, ipv4_pkt.dst)

            # Reply-triggered morph: when an ICMP Echo Reply (type=0) is seen
            if self.morph_strategy == 'reply' and icmp_pkt and icmp_pkt.type == 0:
                # Morph immediately for this pair on this switch
                with self._shuffle_mutex:
                    self.vip.morph_pair_now(datapath, ipv4_pkt.dst, ipv4_pkt.src)  # reply src=dst_real, dst=src_vip path; real pair is (request src, request dst)

            return

        # Phase 4 detectors (optional)
        if self.phase >= 4 and ipv4_pkt:
            triggered = False
            if tcp_pkt and (tcp_pkt.bits & 0x02):
                triggered = triggered or self.detector.track_syn(ipv4_pkt.src)
            if icmp_pkt:
                triggered = triggered or self.detector.track_icmp(ipv4_pkt.src)
            if tcp_pkt:
                triggered = triggered or self.detector.track_port_scan(ipv4_pkt.src, tcp_pkt.dst_port)
            if triggered:
                with self._shuffle_mutex:
                    # Could call global or targeted morph here if desired
                    pass
            self.detector.cleanup()

        # Fallback baseline
        self.switches[dpid].handle_packet(msg, pkt, eth)

    def _mtd_loop(self):
        # Only used if MORPH_STRATEGY=time
        while True:
            hub.sleep(DEFAULT_SHUFFLE_INTERVAL)
            console.print(f"\n[yellow]⏰ Scheduled shuffle (interval: {DEFAULT_SHUFFLE_INTERVAL}s)[/yellow]\n")
            # Optional: implement time-based morph if needed

# Entry point
if __name__ == '__main__':
    from ryu.cmd import manager
    import sys
    sys.argv = ['ryu-manager', __file__]
    manager.main()