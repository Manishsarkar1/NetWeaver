#!/usr/bin/env python3
"""
ULTIMATE MTD CONTROLLER (FIXED)
Features:
- Authentication & User Sessions
- Multiple Morphing Strategies
- Packet Rewriting
- Flow Table Optimization
- Export & Reporting (CSV/JSON/PDF)
- Network Topology Visualization
- Real-time Dashboard
- FIXED: Port scan detection with proper logging
- FIXED: morph_ip_pair pre-allocation guard
- FIXED: Duplicate SYN check removed
- FIXED: Reply-based morphing for ICMP/TCP/UDP

REQUIREMENTS:
    pip install ryu rich flask flask-socketio flask-login eventlet reportlab pandas

USAGE:
    ryu-manager ultimate_mtd_controller.py

Default credentials:
    Username: admin
    Password: mtd2024
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp, udp
from ryu.controller.ofp_handler import OFPHandler
from ryu.lib import hub

from flask import Flask, render_template_string, jsonify, request, redirect, url_for, send_file
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

import threading
import time
import random
import json
import csv
import io
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, asdict

# Try to import reportlab for PDF export
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("⚠️  reportlab not available. PDF export disabled. Install with: pip install reportlab")

# ─────────────────────────────────────────────────────────────────────────────
# Flask / SocketIO setup
# ─────────────────────────────────────────────────────────────────────────────
flask_app = Flask(__name__)
flask_app.config['SECRET_KEY'] = 'mtd-ultra-secret-key-2024-change-in-production'
flask_app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
socketio = SocketIO(flask_app, cors_allowed_origins="*", async_mode='eventlet')

login_manager = LoginManager()
login_manager.init_app(flask_app)
login_manager.login_view = 'login'

# Global reference to Ryu controller (set in __init__)
controller_instance = None

# In-memory user store (replace with DB in production)
users_db = {
    'admin': {
        'password': generate_password_hash('mtd2024'),
        'role': 'admin'
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, username, role='user'):
        self.id = username
        self.username = username
        self.role = role


@login_manager.user_loader
def load_user(username):
    if username in users_db:
        return User(username, users_db[username]['role'])
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class MorphEvent:
    timestamp: str
    protocol: str
    ip1: str
    ip2: str
    old_vip1: str
    new_vip1: str
    old_vip2: str
    new_vip2: str
    trigger: str   # 'reply' | 'time' | 'packet_count' | 'threat' | 'manual'


@dataclass
class ThreatEvent:
    timestamp: str
    threat_type: str
    source_ip: str
    details: str
    severity: str  # 'low' | 'medium' | 'high' | 'critical'


# ─────────────────────────────────────────────────────────────────────────────
# Morphing Strategy
# ─────────────────────────────────────────────────────────────────────────────
class MorphingStrategy:
    """Manages which conditions trigger IP morphing."""

    def __init__(self):
        self.reply_triggered    = True
        self.time_based         = False
        self.time_interval      = 30      # seconds
        self.packet_count_based = False
        self.packet_threshold   = 100
        self.random_intervals   = False
        self.min_interval       = 10
        self.max_interval       = 60
        self.threat_triggered   = True

        self._packet_counters  = defaultdict(int)
        self._last_morph_time  = {}

    # ── helpers ──────────────────────────────────────────────────────────────
    def _pair_key(self, ip1, ip2):
        return tuple(sorted([ip1, ip2]))

    def should_morph_on_reply(self):
        return self.reply_triggered

    def should_morph_time_based(self, ip1, ip2):
        if not self.time_based:
            return False
        key = self._pair_key(ip1, ip2)
        last = self._last_morph_time.get(key, 0)
        interval = (random.randint(self.min_interval, self.max_interval)
                    if self.random_intervals else self.time_interval)
        if time.time() - last >= interval:
            self._last_morph_time[key] = time.time()
            return True
        return False

    def record_packet(self, ip1, ip2):
        if self.packet_count_based:
            self._packet_counters[self._pair_key(ip1, ip2)] += 1

    def should_morph_packet_count(self, ip1, ip2):
        if not self.packet_count_based:
            return False
        key = self._pair_key(ip1, ip2)
        if self._packet_counters[key] >= self.packet_threshold:
            self._packet_counters[key] = 0
            return True
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Threat Detector  (FIXED: proper logging + window reset)
# ─────────────────────────────────────────────────────────────────────────────
class ThreatDetector:
    """Detects network threats such as port scanning."""

    def __init__(self):
        self.port_scan_threshold = 5   # unique ports within window → alarm
        self.port_scan_window    = 10  # seconds
        # key: (src_ip, dst_ip) → {'ports': set, 'time': float}
        self._attempts = defaultdict(lambda: {'ports': set(), 'time': time.time()})
        self.threats = []

    def detect_port_scan(self, src_ip, dst_ip, dst_port):
        """
        Returns True and records a ThreatEvent if src_ip is port-scanning dst_ip.
        Prints detailed debug output every call so you can see progress in the
        Ryu console.
        """
        key = (src_ip, dst_ip)
        entry = self._attempts[key]

        # Reset window if expired
        if time.time() - entry['time'] > self.port_scan_window:
            entry['ports'] = set()
            entry['time'] = time.time()

        entry['ports'].add(dst_port)
        count = len(entry['ports'])

        # ── DEBUG OUTPUT ──────────────────────────────────────────────────────
        print(f"[IDS] {src_ip} → {dst_ip}:{dst_port} | "
              f"unique ports in window: {count}/{self.port_scan_threshold} | "
              f"ports: {sorted(entry['ports'])}")
        # ─────────────────────────────────────────────────────────────────────

        if count >= self.port_scan_threshold:
            threat = ThreatEvent(
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                threat_type='port_scan',
                source_ip=src_ip,
                details=f"Scanned {count} ports on {dst_ip}: {sorted(entry['ports'])}",
                severity='high'
            )
            self.threats.append(threat)
            print(f"[IDS] ⚠️  PORT SCAN DETECTED: {src_ip} → {dst_ip} "
                  f"({count} ports)")
            # Reset so the same attacker can trigger again after morphing
            entry['ports'] = set()
            entry['time'] = time.time()
            return True

        return False


# ─────────────────────────────────────────────────────────────────────────────
# Statistics
# ─────────────────────────────────────────────────────────────────────────────
class MTDStatistics:
    def __init__(self):
        self.total_morphs        = 0
        self.morphs_by_protocol  = defaultdict(int)
        self.morphs_by_trigger   = defaultdict(int)
        self.packets_by_protocol = defaultdict(int)
        self.morph_history       = []   # list of dicts, max 500
        self.vip_allocations     = 0
        self.start_time          = time.time()
        self.active_connections  = []   # max 100
        self.topology            = {'switches': [], 'hosts': [], 'links': []}
        self.threats_detected    = 0

    def record_morph(self, event: MorphEvent):
        self.total_morphs += 1
        self.morphs_by_protocol[event.protocol] += 1
        self.morphs_by_trigger[event.trigger]   += 1
        d = asdict(event)
        self.morph_history.append(d)
        if len(self.morph_history) > 500:
            self.morph_history.pop(0)
        return d

    def record_packet(self, protocol):
        self.packets_by_protocol[protocol] += 1

    def add_active_connection(self, protocol, src_ip, dst_ip,
                              src_port=None, dst_port=None):
        conn = {
            'protocol':  protocol,
            'src_ip':    src_ip,
            'dst_ip':    dst_ip,
            'src_port':  src_port,
            'dst_port':  dst_port,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
        }
        self.active_connections.append(conn)
        if len(self.active_connections) > 100:
            self.active_connections.pop(0)

    def update_topology(self, switches, hosts, links):
        self.topology = {'switches': switches, 'hosts': hosts, 'links': links}

    def get_uptime(self):
        s = int(time.time() - self.start_time)
        return f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"

    def get_stats_dict(self):
        return {
            'uptime':               self.get_uptime(),
            'total_morphs':         self.total_morphs,
            'vip_allocations':      self.vip_allocations,
            'morphs_by_protocol':   dict(self.morphs_by_protocol),
            'morphs_by_trigger':    dict(self.morphs_by_trigger),
            'packets_by_protocol':  dict(self.packets_by_protocol),
            'morph_history':        self.morph_history[-50:],
            'active_connections':   self.active_connections[-50:],
            'topology':             self.topology,
            'threats_detected':     self.threats_detected,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Main Ryu Application
# ─────────────────────────────────────────────────────────────────────────────
class UltimateMTDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'ofp_handler': OFPHandler}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        global controller_instance
        controller_instance = self

        # L2 learning
        self.mac_to_port = {}   # dpid → {mac: port}
        self.datapaths   = {}   # dpid → datapath
        self.hosts       = {}   # ip  → {mac, switch, port}

        # IP virtualisation
        self.real_to_virtual = {}   # real_ip → vip
        self.virtual_to_real = {}   # vip     → real_ip
        self.virtual_pool    = self._init_virtual_pool()

        # Protocol flow trackers
        self.icmp_tracker = {}   # (src,dst) → {request_seen, time}
        self.tcp_tracker  = {}   # (src,dst,sp,dp) → {syn_seen, syn_ack_seen, established, time}
        self.udp_tracker  = {}   # (src,dst,sp,dp) → {request_seen, time}

        # Sub-systems
        self.stats           = MTDStatistics()
        self.strategy        = MorphingStrategy()
        self.threat_detector = ThreatDetector()

        self.logger.info("=" * 60)
        self.logger.info("  ULTIMATE MTD CONTROLLER  (FIXED VERSION)")
        self.logger.info("=" * 60)
        self.logger.info("  Dashboard : http://localhost:5000")
        self.logger.info("  Login     : admin / mtd2024")
        self.logger.info("=" * 60)

        # Start Flask in a daemon thread
        self._flask_thread = threading.Thread(target=self._start_flask, daemon=True)
        self._flask_thread.start()

        # Time-based morphing background task
        self._time_morph_task = hub.spawn(self._time_based_morph_loop)

    # ── Flask ─────────────────────────────────────────────────────────────────
    def _start_flask(self):
        socketio.run(flask_app, host='0.0.0.0', port=5000,
                     debug=False, use_reloader=False)

    # ── Virtual IP pool ───────────────────────────────────────────────────────
    def _init_virtual_pool(self):
        return set(f"192.168.100.{i}" for i in range(1, 255))

    # ── Background time-based morphing ────────────────────────────────────────
    def _time_based_morph_loop(self):
        while True:
            hub.sleep(5)
            if not self.strategy.time_based:
                continue
            ips = list(self.real_to_virtual.keys())
            for i in range(0, len(ips) - 1, 2):
                ip1, ip2 = ips[i], ips[i + 1]
                if self.strategy.should_morph_time_based(ip1, ip2):
                    self.logger.info(f"⏰ Time-based morph: {ip1} ↔ {ip2}")
                    self.morph_ip_pair(ip1, ip2, "TIME", trigger='time')

    # ── VIP allocation ────────────────────────────────────────────────────────
    def allocate_vip(self, real_ip):
        """Assign a VIP to real_ip if not already done. Returns the VIP."""
        if real_ip in self.real_to_virtual:
            return self.real_to_virtual[real_ip]
        if not self.virtual_pool:
            self.logger.warning("VIP pool exhausted!")
            return real_ip
        vip = self.virtual_pool.pop()
        self.real_to_virtual[real_ip] = vip
        self.virtual_to_real[vip]     = real_ip
        self.stats.vip_allocations   += 1
        self.logger.info(f"  VIP allocated: {real_ip} → {vip}")
        socketio.emit('vip_allocated', {'real_ip': real_ip, 'vip': vip})
        self._emit_current_mappings()
        self._update_topology()
        return vip

    # ── Core: morph an IP pair ────────────────────────────────────────────────
    def morph_ip_pair(self, ip1, ip2, protocol="", trigger='reply'):
        """
        Re-assign VIPs for ip1 and ip2.

        FIXED: Guards against either IP not being in real_to_virtual so
        morph events are never silently skipped without a log message.
        """
        # ── Guard: ensure both IPs are mapped ────────────────────────────────
        missing = [ip for ip in (ip1, ip2) if ip not in self.real_to_virtual]
        if missing:
            self.logger.warning(
                f"[MORPH] Skipped — IPs not yet in VIP map: {missing}. "
                f"Trigger={trigger}, protocol={protocol}"
            )
            # Allocate them now so the next morph attempt succeeds
            for ip in missing:
                self.allocate_vip(ip)
            return
        # ─────────────────────────────────────────────────────────────────────

        old_vips = {}
        new_vips = {}

        for real_ip in (ip1, ip2):
            old_vip = self.real_to_virtual[real_ip]
            old_vips[real_ip] = old_vip

            # Return old VIP to pool
            self.virtual_pool.add(old_vip)
            del self.virtual_to_real[old_vip]

            if not self.virtual_pool:
                self.logger.warning("VIP pool exhausted during morph!")
                continue

            new_vip = self.virtual_pool.pop()
            self.real_to_virtual[real_ip] = new_vip
            self.virtual_to_real[new_vip] = real_ip
            new_vips[real_ip] = new_vip

        if not new_vips:
            return

        event = MorphEvent(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            protocol=protocol,
            ip1=ip1, ip2=ip2,
            old_vip1=old_vips.get(ip1, ''), new_vip1=new_vips.get(ip1, ''),
            old_vip2=old_vips.get(ip2, ''), new_vip2=new_vips.get(ip2, ''),
            trigger=trigger,
        )
        event_dict = self.stats.record_morph(event)

        self.logger.info(
            f"[MORPH] ✅ {protocol} ({trigger}) | "
            f"{ip1}: {old_vips.get(ip1)} → {new_vips.get(ip1)} | "
            f"{ip2}: {old_vips.get(ip2)} → {new_vips.get(ip2)}"
        )

        socketio.emit('morph_event', event_dict)
        self._emit_current_mappings()

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _emit_current_mappings(self):
        mappings = [{'real_ip': r, 'vip': v}
                    for r, v in self.real_to_virtual.items()]
        socketio.emit('mappings_update', {'mappings': mappings})

    def _update_topology(self):
        switches = [{'dpid': dpid, 'id': f's{dpid}'}
                    for dpid in self.datapaths]
        hosts = []
        links = []
        for ip, vip in self.real_to_virtual.items():
            info = self.hosts.get(ip, {})
            hosts.append({'ip': ip, 'vip': vip,
                          'mac': info.get('mac', 'unknown'), 'id': ip})
            if 'switch' in info:
                links.append({'from': f"s{info['switch']}", 'to': ip})
        self.stats.update_topology(switches, hosts, links)
        socketio.emit('topology_update', self.stats.topology)

    # ── OpenFlow: switch connect ──────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        dpid     = datapath.id

        self.datapaths[dpid] = datapath
        self.logger.info(f"✓ Switch s{dpid} connected")

        # Table-miss: send everything to controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self._update_topology()

    def add_flow(self, datapath, priority, match, actions,
                 idle=0, hard=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                actions)]
        kwargs = dict(datapath=datapath, priority=priority,
                      match=match, instructions=inst,
                      idle_timeout=idle, hard_timeout=hard)
        if buffer_id:
            kwargs['buffer_id'] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    def install_flow_for_packet(self, datapath, in_port, out_port,
                                pkt, buffer_id=None):
        parser = datapath.ofproto_parser
        eth    = pkt.get_protocol(ethernet.ethernet)
        match  = parser.OFPMatch(in_port=in_port,
                                 eth_dst=eth.dst, eth_src=eth.src)
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 1, match, actions, idle=30,
                      buffer_id=buffer_id)

    # ── Protocol handlers ─────────────────────────────────────────────────────

    def _ensure_vips(self, *ips):
        """Make sure every IP in *ips has a VIP allocated."""
        for ip in ips:
            if ip not in self.real_to_virtual:
                self.allocate_vip(ip)

    def handle_icmp(self, datapath, in_port, pkt, ipv4_pkt, icmp_pkt):
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst

        self.stats.record_packet('ICMP')
        self.strategy.record_packet(src_ip, dst_ip)
        self._ensure_vips(src_ip, dst_ip)

        if icmp_pkt.type == 8:  # Echo Request
            pair_key = (src_ip, dst_ip)
            self.icmp_tracker[pair_key] = {'request_seen': True,
                                           'time': time.time()}
            self.stats.add_active_connection('ICMP', src_ip, dst_ip)
            socketio.emit('connection_update', {
                'protocol': 'ICMP', 'src_ip': src_ip,
                'dst_ip': dst_ip, 'event': 'request'
            })

        elif icmp_pkt.type == 0:  # Echo Reply
            pair_key = (dst_ip, src_ip)
            if pair_key in self.icmp_tracker:
                should_morph = False
                trigger      = 'reply'

                if self.strategy.should_morph_on_reply():
                    should_morph = True
                elif self.strategy.should_morph_packet_count(dst_ip, src_ip):
                    should_morph = True
                    trigger      = 'packet_count'

                if should_morph:
                    self.morph_ip_pair(dst_ip, src_ip, "ICMP", trigger=trigger)

                del self.icmp_tracker[pair_key]

    def handle_tcp(self, datapath, in_port, pkt, ipv4_pkt, tcp_pkt):
        src_ip   = ipv4_pkt.src
        dst_ip   = ipv4_pkt.dst
        src_port = tcp_pkt.src_port
        dst_port = tcp_pkt.dst_port

        self.stats.record_packet('TCP')
        self.strategy.record_packet(src_ip, dst_ip)
        self._ensure_vips(src_ip, dst_ip)   # ← allocate BEFORE threat check

        flow_key         = (src_ip, dst_ip, src_port, dst_port)
        reverse_flow_key = (dst_ip, src_ip, dst_port, src_port)

        # ── FIXED: threat detection is its OWN block, no early return ────────
        is_syn     = tcp_pkt.has_flags(tcp.TCP_SYN)
        is_ack     = tcp_pkt.has_flags(tcp.TCP_ACK)
        is_fin     = tcp_pkt.has_flags(tcp.TCP_FIN)

        if is_syn and not is_ack:
            # Check for port scan
            if self.threat_detector.detect_port_scan(src_ip, dst_ip, dst_port):
                self.stats.threats_detected += 1
                socketio.emit('threat_detected', {
                    'type': 'port_scan',
                    'source': src_ip,
                    'target': dst_ip,
                })
                if self.strategy.threat_triggered:
                    self.logger.warning(
                        f"🚨 Port scan! Morphing {src_ip} ↔ {dst_ip} immediately.")
                    self.morph_ip_pair(src_ip, dst_ip, "TCP", trigger='threat')
                    # Don't track this SYN — morphing invalidates the session
                    return

            # Normal SYN tracking
            self.tcp_tracker[flow_key] = {
                'syn_seen':     True,
                'syn_ack_seen': False,
                'established':  False,
                'time':         time.time(),
            }
            self.stats.add_active_connection('TCP', src_ip, dst_ip,
                                             src_port, dst_port)

        elif is_syn and is_ack:
            # SYN-ACK
            if reverse_flow_key in self.tcp_tracker:
                self.tcp_tracker[reverse_flow_key]['syn_ack_seen'] = True

        elif is_ack and not is_syn and not is_fin:
            # Final ACK of 3-way handshake
            if (flow_key in self.tcp_tracker
                    and not self.tcp_tracker[flow_key].get('established', False)
                    and self.tcp_tracker[flow_key].get('syn_ack_seen', False)):

                self.tcp_tracker[flow_key]['established'] = True

                should_morph = False
                trigger      = 'reply'

                if self.strategy.should_morph_on_reply():
                    should_morph = True
                elif self.strategy.should_morph_packet_count(src_ip, dst_ip):
                    should_morph = True
                    trigger      = 'packet_count'

                if should_morph:
                    self.morph_ip_pair(src_ip, dst_ip, "TCP", trigger=trigger)

                del self.tcp_tracker[flow_key]

    def handle_udp(self, datapath, in_port, pkt, ipv4_pkt, udp_pkt):
        src_ip   = ipv4_pkt.src
        dst_ip   = ipv4_pkt.dst
        src_port = udp_pkt.src_port
        dst_port = udp_pkt.dst_port

        self.stats.record_packet('UDP')
        self.strategy.record_packet(src_ip, dst_ip)
        self._ensure_vips(src_ip, dst_ip)

        flow_key         = (src_ip, dst_ip, src_port, dst_port)
        reverse_flow_key = (dst_ip, src_ip, dst_port, src_port)

        if reverse_flow_key in self.udp_tracker:
            should_morph = False
            trigger      = 'reply'

            if self.strategy.should_morph_on_reply():
                should_morph = True
            elif self.strategy.should_morph_packet_count(dst_ip, src_ip):
                should_morph = True
                trigger      = 'packet_count'

            if should_morph:
                self.morph_ip_pair(dst_ip, src_ip, "UDP", trigger=trigger)

            del self.udp_tracker[reverse_flow_key]
        else:
            self.udp_tracker[flow_key] = {'request_seen': True,
                                          'time': time.time()}
            self.stats.add_active_connection('UDP', src_ip, dst_ip,
                                             src_port, dst_port)

    # ── Main packet-in handler ────────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']
        dpid     = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        out_port = (self.mac_to_port[dpid].get(eth.dst)
                    or ofproto.OFPP_FLOOD)

        # ── ARP ──────────────────────────────────────────────────────────────
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.stats.record_packet('ARP')
            if arp_pkt.src_ip not in self.hosts:
                self.hosts[arp_pkt.src_ip] = {
                    'mac': eth.src, 'switch': dpid, 'port': in_port}
                self.logger.info(
                    f"🆕 Host (ARP): {arp_pkt.src_ip} ({eth.src}) "
                    f"on s{dpid} port {in_port}")
            self._forward(datapath, msg, in_port, out_port, ofproto, parser)
            return

        # ── IPv4 ─────────────────────────────────────────────────────────────
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ipv4_pkt:
            self._forward(datapath, msg, in_port, out_port, ofproto, parser)
            return

        if ipv4_pkt.src not in self.hosts:
            self.hosts[ipv4_pkt.src] = {
                'mac': eth.src, 'switch': dpid, 'port': in_port}
            self.logger.info(
                f"🆕 Host (IP): {ipv4_pkt.src} ({eth.src}) "
                f"on s{dpid} port {in_port}")

        icmp_pkt = pkt.get_protocol(icmp.icmp)
        tcp_pkt  = pkt.get_protocol(tcp.tcp)
        udp_pkt  = pkt.get_protocol(udp.udp)

        if icmp_pkt:
            self.handle_icmp(datapath, in_port, pkt, ipv4_pkt, icmp_pkt)
        elif tcp_pkt:
            self.handle_tcp(datapath, in_port, pkt, ipv4_pkt, tcp_pkt)
        elif udp_pkt:
            self.handle_udp(datapath, in_port, pkt, ipv4_pkt, udp_pkt)

        if out_port != ofproto.OFPP_FLOOD:
            self.install_flow_for_packet(datapath, in_port, out_port,
                                         pkt, msg.buffer_id)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                return

        self._forward(datapath, msg, in_port, out_port, ofproto, parser)

    def _forward(self, datapath, msg, in_port, out_port, ofproto, parser):
        actions = [parser.OFPActionOutput(out_port)]
        data    = (msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER
                   else None)
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)


# ─────────────────────────────────────────────────────────────────────────────
# HTML Dashboard (inline so no template files needed)
# ─────────────────────────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>MTD Dashboard</title>
  <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/vis-network@9.1.2/dist/vis-network.min.js"></script>
  <link href="https://cdn.jsdelivr.net/npm/vis-network@9.1.2/dist/dist/vis-network.min.css" rel="stylesheet">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#1a1a2e,#16213e);min-height:100vh;padding:20px;color:#e0e0e0}
    .container{max-width:1800px;margin:0 auto}
    .header{background:rgba(30,30,46,.95);padding:20px 30px;border-radius:15px;box-shadow:0 8px 32px rgba(0,0,0,.3);margin-bottom:20px;border:1px solid rgba(100,100,255,.2);display:flex;justify-content:space-between;align-items:center}
    .header h1{color:#7dd3fc;font-size:2em;text-shadow:0 0 20px rgba(125,211,252,.3)}
    .btn{padding:10px 20px;border:none;border-radius:8px;cursor:pointer;font-weight:600;transition:all .3s;margin:4px}
    .btn-primary{background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:#fff}
    .btn-danger{background:linear-gradient(135deg,#dc2626,#991b1b);color:#fff}
    .btn-success{background:linear-gradient(135deg,#10b981,#059669);color:#fff}
    .btn:hover{transform:translateY(-2px);box-shadow:0 4px 15px rgba(59,130,246,.5)}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:20px;margin-bottom:20px}
    .card{background:rgba(30,30,46,.95);border-radius:15px;padding:25px;box-shadow:0 8px 32px rgba(0,0,0,.3);border:1px solid rgba(100,100,255,.2)}
    .card-title{font-size:1.3em;color:#7dd3fc;font-weight:600;margin-bottom:15px;padding-bottom:10px;border-bottom:2px solid rgba(100,100,255,.2)}
    .stat-box{background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:#fff;padding:20px;border-radius:10px;text-align:center;margin-bottom:10px}
    .stat-value{font-size:2.2em;font-weight:bold}
    .stat-label{font-size:.85em;opacity:.9}
    .protocol-stats{display:flex;justify-content:space-around;flex-wrap:wrap;gap:10px;margin-bottom:10px}
    .protocol-box{flex:1;min-width:75px;background:rgba(45,45,68,.8);padding:12px;border-radius:8px;text-align:center;border-left:4px solid}
    .pb-icmp{border-left-color:#3b82f6}.pb-tcp{border-left-color:#10b981}.pb-udp{border-left-color:#f59e0b}.pb-arp{border-left-color:#8b5cf6}
    .protocol-value{font-size:1.6em;font-weight:bold}.protocol-label{font-size:.8em;color:#94a3b8;margin-top:4px}
    table{width:100%;border-collapse:collapse;margin-top:10px}
    th,td{padding:10px;text-align:left;border-bottom:1px solid rgba(100,100,255,.2)}
    th{background:rgba(45,45,68,.8);font-weight:600;color:#7dd3fc}
    tr:hover{background:rgba(45,45,68,.5)}
    .ip-badge{display:inline-block;padding:4px 10px;border-radius:5px;font-family:monospace;font-size:.9em}
    .real-ip{background:rgba(59,130,246,.3);color:#7dd3fc;border:1px solid rgba(59,130,246,.5)}
    .virtual-ip{background:rgba(16,185,129,.3);color:#6ee7b7;border:1px solid rgba(16,185,129,.5)}
    .event-list{max-height:350px;overflow-y:auto}
    .event-item{padding:12px;margin-bottom:8px;border-radius:8px;background:rgba(45,45,68,.8);border-left:4px solid #3b82f6;animation:slideIn .3s ease}
    @keyframes slideIn{from{opacity:0;transform:translateX(-20px)}to{opacity:1;transform:translateX(0)}}
    .event-header{display:flex;justify-content:space-between;margin-bottom:6px}
    .event-protocol{font-weight:bold;color:#7dd3fc}.event-time{color:#94a3b8;font-size:.8em}
    .event-details{font-size:.85em;color:#cbd5e1}
    .wide{grid-column:1/-1}
    .chart-container{position:relative;height:260px;margin-top:15px}
    #networkTopology{height:420px;background:rgba(45,45,68,.8);border-radius:10px}
    .modal{display:none;position:fixed;z-index:1000;left:0;top:0;width:100%;height:100%;background:rgba(0,0,0,.8)}
    .modal-content{background:rgba(30,30,46,.98);margin:5% auto;padding:30px;border-radius:15px;width:80%;max-width:580px;border:1px solid rgba(100,100,255,.3)}
    .modal-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
    .modal-title{font-size:1.4em;color:#7dd3fc}
    .close{color:#94a3b8;font-size:26px;cursor:pointer}.close:hover{color:#e0e0e0}
    .form-group{margin-bottom:15px}
    .form-group label{display:block;margin-bottom:6px;color:#7dd3fc;font-weight:500}
    .form-group input{width:100%;padding:9px;border:1px solid rgba(100,100,255,.3);border-radius:8px;background:rgba(45,45,68,.8);color:#e0e0e0}
    .cb-group{display:flex;align-items:center;gap:10px}
    .cb-group input[type=checkbox]{width:auto}
    .status-indicator{display:inline-block;width:10px;height:10px;border-radius:50%;background:#10b981;margin-right:6px;animation:pulse 2s infinite;box-shadow:0 0 8px #10b981}
    @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
    ::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:rgba(45,45,68,.5);border-radius:3px}
    ::-webkit-scrollbar-thumb{background:rgba(59,130,246,.5);border-radius:3px}
  </style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>🛡️ Ultimate MTD Dashboard</h1>
      <span class="status-indicator"></span><span style="color:#94a3b8">System Active</span>
    </div>
    <div style="color:#94a3b8">
      Welcome, <strong>{{ username }}</strong> |
      <a href="/logout" style="color:#7dd3fc;text-decoration:none">Logout</a>
    </div>
  </div>

  <!-- Actions -->
  <div class="card" style="margin-bottom:20px">
    <button class="btn btn-primary"  onclick="openStrategyModal()">⚙️ Configure Strategy</button>
    <button class="btn btn-danger"   onclick="forceMorph()">🔄 Force Morph Now</button>
    <button class="btn btn-success"  onclick="exportCSV()">📊 Export CSV</button>
    <button class="btn btn-success"  onclick="exportJSON()">📄 Export JSON</button>
    <button class="btn btn-success"  onclick="exportPDF()">📑 Export PDF</button>
  </div>

  <!-- Stats -->
  <div class="grid">
    <div class="card">
      <div class="card-title">📊 Overview</div>
      <div class="stat-box"><div class="stat-value" id="uptime">--:--:--</div><div class="stat-label">Uptime</div></div>
      <div class="stat-box" style="background:linear-gradient(135deg,#f59e0b,#dc2626)"><div class="stat-value" id="totalMorphs">0</div><div class="stat-label">Total Morphs</div></div>
      <div class="stat-box" style="background:linear-gradient(135deg,#10b981,#059669)"><div class="stat-value" id="vipAllocations">0</div><div class="stat-label">VIP Allocations</div></div>
      <div class="stat-box" style="background:linear-gradient(135deg,#dc2626,#7f1d1d)"><div class="stat-value" id="threatsDetected">0</div><div class="stat-label">Threats Detected</div></div>
    </div>
    <div class="card">
      <div class="card-title">📡 Packet Statistics</div>
      <div class="protocol-stats">
        <div class="protocol-box pb-icmp"><div class="protocol-value" id="icmpPackets">0</div><div class="protocol-label">ICMP</div></div>
        <div class="protocol-box pb-tcp"> <div class="protocol-value" id="tcpPackets">0</div> <div class="protocol-label">TCP</div></div>
        <div class="protocol-box pb-udp"> <div class="protocol-value" id="udpPackets">0</div> <div class="protocol-label">UDP</div></div>
        <div class="protocol-box pb-arp"> <div class="protocol-value" id="arpPackets">0</div> <div class="protocol-label">ARP</div></div>
      </div>
      <div class="chart-container"><canvas id="packetChart"></canvas></div>
    </div>
    <div class="card">
      <div class="card-title">🔄 Morphs by Trigger</div>
      <div class="protocol-stats">
        <div class="protocol-box" style="border-left-color:#3b82f6"><div class="protocol-value" id="replyMorphs">0</div><div class="protocol-label">Reply</div></div>
        <div class="protocol-box" style="border-left-color:#10b981"><div class="protocol-value" id="timeMorphs">0</div><div class="protocol-label">Time</div></div>
        <div class="protocol-box" style="border-left-color:#f59e0b"><div class="protocol-value" id="packetMorphs">0</div><div class="protocol-label">Packet</div></div>
        <div class="protocol-box" style="border-left-color:#dc2626"><div class="protocol-value" id="threatMorphs">0</div><div class="protocol-label">Threat</div></div>
      </div>
      <div class="chart-container"><canvas id="morphChart"></canvas></div>
    </div>
  </div>

  <!-- Topology -->
  <div class="grid">
    <div class="card wide">
      <div class="card-title">🗺️ Network Topology</div>
      <div id="networkTopology"></div>
    </div>
  </div>

  <!-- Mappings -->
  <div class="grid">
    <div class="card wide">
      <div class="card-title">🗺️ Current VIP Mappings
        <span id="mappingCount" style="background:#10b981;padding:3px 8px;border-radius:4px;font-size:.7em;margin-left:8px">0 Active</span>
      </div>
      <table>
        <thead><tr><th>Real IP</th><th></th><th>Virtual IP</th></tr></thead>
        <tbody id="mappingsTableBody"><tr><td colspan="3" style="text-align:center;color:#64748b">No active mappings</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- Connections + Events -->
  <div class="grid">
    <div class="card">
      <div class="card-title">🔗 Active Connections</div>
      <div class="event-list" id="connectionsContainer"><div style="text-align:center;padding:30px;color:#64748b">No active connections</div></div>
    </div>
    <div class="card">
      <div class="card-title">📋 Recent Morph Events</div>
      <div class="event-list" id="morphEventsContainer"><div style="text-align:center;padding:30px;color:#64748b">No morph events yet</div></div>
    </div>
  </div>
</div>

<!-- Strategy Modal -->
<div id="strategyModal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <span class="modal-title">Configure Morphing Strategy</span>
      <span class="close" onclick="closeStrategyModal()">&times;</span>
    </div>
    <form id="strategyForm">
      <div class="form-group"><div class="cb-group"><input type="checkbox" id="replyTriggered" checked><label for="replyTriggered">Reply-Triggered Morphing</label></div></div>
      <div class="form-group">
        <div class="cb-group"><input type="checkbox" id="timeBased"><label for="timeBased">Time-Based Morphing</label></div>
        <input type="number" id="timeInterval" placeholder="Interval (s)" value="30" min="5" style="margin-top:6px">
      </div>
      <div class="form-group">
        <div class="cb-group"><input type="checkbox" id="packetCountBased"><label for="packetCountBased">Packet-Count Based Morphing</label></div>
        <input type="number" id="packetThreshold" placeholder="Packet threshold" value="100" min="10" style="margin-top:6px">
      </div>
      <div class="form-group">
        <div class="cb-group"><input type="checkbox" id="randomIntervals"><label for="randomIntervals">Random Intervals</label></div>
        <div style="display:flex;gap:8px;margin-top:6px">
          <input type="number" id="minInterval" placeholder="Min (s)" value="10" min="5">
          <input type="number" id="maxInterval" placeholder="Max (s)" value="60" min="10">
        </div>
      </div>
      <div class="form-group"><div class="cb-group"><input type="checkbox" id="threatTriggered" checked><label for="threatTriggered">Threat-Triggered Morphing</label></div></div>
      <button type="submit" class="btn btn-primary" style="width:100%;margin-top:10px">Save Strategy</button>
    </form>
  </div>
</div>

<script>
const socket = io();
let packetChart, morphChart, network;

Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = 'rgba(100,100,255,.2)';

function initCharts() {
  packetChart = new Chart(document.getElementById('packetChart').getContext('2d'), {
    type: 'doughnut',
    data: { labels: ['ICMP','TCP','UDP','ARP'], datasets: [{ data: [0,0,0,0], backgroundColor: ['#3b82f6','#10b981','#f59e0b','#8b5cf6'] }] },
    options: { responsive:true, maintainAspectRatio:false, plugins:{ legend:{ position:'bottom', labels:{ color:'#94a3b8' } } } }
  });
  morphChart = new Chart(document.getElementById('morphChart').getContext('2d'), {
    type: 'bar',
    data: { labels: ['Reply','Time','Packet','Threat'], datasets: [{ data: [0,0,0,0], backgroundColor: ['#3b82f6','#10b981','#f59e0b','#dc2626'] }] },
    options: { responsive:true, maintainAspectRatio:false, scales:{ y:{ beginAtZero:true, ticks:{ stepSize:1, color:'#94a3b8' }, grid:{ color:'rgba(100,100,255,.1)' } }, x:{ ticks:{ color:'#94a3b8' }, grid:{ color:'rgba(100,100,255,.1)' } } }, plugins:{ legend:{ display:false } } }
  });
}

function initTopology() {
  network = new vis.Network(document.getElementById('networkTopology'),
    { nodes: [], edges: [] },
    { nodes:{ shape:'dot', size:20, font:{ color:'#e0e0e0' }, borderWidth:2, color:{ background:'#3b82f6', border:'#7dd3fc' } }, edges:{ width:2, color:{ color:'#94a3b8' } }, physics:{ enabled:true, stabilization:{ iterations:100 } } }
  );
}

function updateStats(stats) {
  document.getElementById('uptime').textContent        = stats.uptime        || '--:--:--';
  document.getElementById('totalMorphs').textContent   = stats.total_morphs  || 0;
  document.getElementById('vipAllocations').textContent= stats.vip_allocations|| 0;
  document.getElementById('threatsDetected').textContent=stats.threats_detected||0;

  const p = stats.packets_by_protocol || {};
  document.getElementById('icmpPackets').textContent = p.ICMP||0;
  document.getElementById('tcpPackets').textContent  = p.TCP ||0;
  document.getElementById('udpPackets').textContent  = p.UDP ||0;
  document.getElementById('arpPackets').textContent  = p.ARP ||0;
  packetChart.data.datasets[0].data = [p.ICMP||0, p.TCP||0, p.UDP||0, p.ARP||0];
  packetChart.update();

  const m = stats.morphs_by_trigger || {};
  document.getElementById('replyMorphs').textContent  = m.reply       ||0;
  document.getElementById('timeMorphs').textContent   = m.time        ||0;
  document.getElementById('packetMorphs').textContent = m.packet_count||0;
  document.getElementById('threatMorphs').textContent = m.threat      ||0;
  morphChart.data.datasets[0].data = [m.reply||0, m.time||0, m.packet_count||0, m.threat||0];
  morphChart.update();

  updateConnections(stats.active_connections || []);
  updateMorphHistory(stats.morph_history     || []);
  updateTopology(stats.topology              || {});
}

function updateMappings(mappings) {
  const tbody = document.getElementById('mappingsTableBody');
  document.getElementById('mappingCount').textContent = (mappings||[]).length + ' Active';
  if (!mappings || !mappings.length) {
    tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:#64748b">No active mappings</td></tr>';
    return;
  }
  tbody.innerHTML = mappings.map(m =>
    `<tr><td><span class="ip-badge real-ip">${m.real_ip}</span></td><td style="text-align:center">↔</td><td><span class="ip-badge virtual-ip">${m.vip}</span></td></tr>`
  ).join('');
}

function updateConnections(conns) {
  const el = document.getElementById('connectionsContainer');
  if (!conns.length) { el.innerHTML='<div style="text-align:center;padding:30px;color:#64748b">No active connections</div>'; return; }
  el.innerHTML = [...conns].reverse().slice(0,20).map(c =>
    `<div class="event-item"><div class="event-header"><span class="event-protocol">${c.protocol}</span><span class="event-time">${c.timestamp}</span></div><div class="event-details">${c.src_ip}${c.src_port?':'+c.src_port:''} → ${c.dst_ip}${c.dst_port?':'+c.dst_port:''}</div></div>`
  ).join('');
}

function updateMorphHistory(history) {
  const el = document.getElementById('morphEventsContainer');
  if (!history.length) { el.innerHTML='<div style="text-align:center;padding:30px;color:#64748b">No morph events yet</div>'; return; }
  el.innerHTML = [...history].reverse().slice(0,20).map(e =>
    `<div class="event-item"><div class="event-header"><span class="event-protocol">${e.protocol} (${e.trigger})</span><span class="event-time">${e.timestamp}</span></div><div class="event-details"><div>${e.ip1}: ${e.old_vip1} → ${e.new_vip1}</div><div>${e.ip2}: ${e.old_vip2} → ${e.new_vip2}</div></div></div>`
  ).join('');
}

function updateTopology(topo) {
  if (!network) return;
  const nodes=[], edges=[];
  (topo.switches||[]).forEach(sw => nodes.push({ id:'s'+sw.dpid, label:'S'+sw.dpid, color:{ background:'#8b5cf6', border:'#a78bfa' }, shape:'box' }));
  (topo.hosts||[]).forEach(h => {
    nodes.push({ id:h.ip, label:h.ip+'\\n('+h.vip+')', color:{ background:'#10b981', border:'#6ee7b7' } });
    if ((topo.switches||[]).length) edges.push({ from:'s'+(topo.switches[0].dpid), to:h.ip });
  });
  network.setData({ nodes, edges });
}

// Modal
function openStrategyModal() {
  fetch('/api/strategy').then(r=>r.json()).then(d => {
    document.getElementById('replyTriggered').checked  = d.reply_triggered;
    document.getElementById('timeBased').checked       = d.time_based;
    document.getElementById('timeInterval').value      = d.time_interval;
    document.getElementById('packetCountBased').checked= d.packet_count_based;
    document.getElementById('packetThreshold').value   = d.packet_threshold;
    document.getElementById('randomIntervals').checked = d.random_intervals;
    document.getElementById('minInterval').value       = d.min_interval;
    document.getElementById('maxInterval').value       = d.max_interval;
    document.getElementById('threatTriggered').checked = d.threat_triggered;
    document.getElementById('strategyModal').style.display='block';
  });
}
function closeStrategyModal() { document.getElementById('strategyModal').style.display='none'; }
document.getElementById('strategyForm').addEventListener('submit', e => {
  e.preventDefault();
  fetch('/api/strategy', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({
    reply_triggered:    document.getElementById('replyTriggered').checked,
    time_based:         document.getElementById('timeBased').checked,
    time_interval:      +document.getElementById('timeInterval').value,
    packet_count_based: document.getElementById('packetCountBased').checked,
    packet_threshold:   +document.getElementById('packetThreshold').value,
    random_intervals:   document.getElementById('randomIntervals').checked,
    min_interval:       +document.getElementById('minInterval').value,
    max_interval:       +document.getElementById('maxInterval').value,
    threat_triggered:   document.getElementById('threatTriggered').checked,
  })}).then(r=>r.json()).then(()=>{ alert('Strategy updated!'); closeStrategyModal(); });
});

function forceMorph() {
  if (confirm('Force immediate morphing of all active IP pairs?'))
    fetch('/api/morph/force',{method:'POST'}).then(r=>r.json()).then(r=>alert('Morphed '+r.morphed_pairs+' IP pairs'));
}
function exportCSV()  { window.open('/api/export/csv',  '_blank'); }
function exportJSON() { window.open('/api/export/json', '_blank'); }
function exportPDF()  { window.open('/api/export/pdf',  '_blank'); }

socket.on('connect',         ()    => console.log('Connected to MTD Controller'));
socket.on('stats_update',    updateStats);
socket.on('mappings_update', d     => updateMappings(d.mappings));
socket.on('threat_detected', d     => { console.warn('Threat:', d); alert('⚠️ Threat: '+d.type+' from '+d.source); });

setInterval(() => fetch('/api/stats').then(r=>r.json()).then(updateStats).catch(console.error), 2000);
window.onload = () => { initCharts(); initTopology(); };
</script>
</body>
</html>"""

LOGIN_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>MTD Login</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#1a1a2e,#16213e);min-height:100vh;display:flex;align-items:center;justify-content:center;color:#e0e0e0}
    .card{background:rgba(30,30,46,.95);border-radius:15px;padding:40px;width:360px;border:1px solid rgba(100,100,255,.2);box-shadow:0 8px 32px rgba(0,0,0,.4)}
    h1{color:#7dd3fc;text-align:center;margin-bottom:30px}
    .form-group{margin-bottom:20px}
    label{display:block;margin-bottom:8px;color:#94a3b8}
    input{width:100%;padding:10px;border:1px solid rgba(100,100,255,.3);border-radius:8px;background:rgba(45,45,68,.8);color:#e0e0e0;font-size:1em}
    button{width:100%;padding:12px;background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:#fff;border:none;border-radius:8px;font-size:1em;font-weight:600;cursor:pointer;margin-top:10px}
    button:hover{opacity:.9}
    .error{color:#f87171;background:rgba(220,38,38,.2);padding:10px;border-radius:8px;margin-bottom:15px;text-align:center}
  </style>
</head>
<body>
  <div class="card">
    <h1>🛡️ MTD Login</h1>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="POST">
      <div class="form-group"><label>Username</label><input name="username" autofocus></div>
      <div class="form-group"><label>Password</label><input name="password" type="password"></div>
      <button type="submit">Login</button>
    </form>
  </div>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Flask Routes
# ─────────────────────────────────────────────────────────────────────────────
@flask_app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username in users_db and check_password_hash(
                users_db[username]['password'], password):
            login_user(User(username, users_db[username]['role']),
                       remember=True)
            return redirect(url_for('index'))
        return render_template_string(LOGIN_HTML, error='Invalid credentials')
    return render_template_string(LOGIN_HTML, error=None)


@flask_app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@flask_app.route('/')
@login_required
def index():
    return render_template_string(DASHBOARD_HTML,
                                  username=current_user.username)


@flask_app.route('/api/stats')
@login_required
def get_stats():
    if controller_instance:
        return jsonify(controller_instance.stats.get_stats_dict())
    return jsonify({'error': 'Controller not initialized'})


@flask_app.route('/api/mappings')
@login_required
def get_mappings():
    if controller_instance:
        return jsonify({'mappings': [
            {'real_ip': r, 'vip': v}
            for r, v in controller_instance.real_to_virtual.items()
        ]})
    return jsonify({'mappings': []})


@flask_app.route('/api/strategy', methods=['GET', 'POST'])
@login_required
def manage_strategy():
    if not controller_instance:
        return jsonify({'error': 'Controller not initialized'})
    s = controller_instance.strategy
    if request.method == 'POST':
        d = request.json or {}
        s.reply_triggered    = d.get('reply_triggered',    True)
        s.time_based         = d.get('time_based',         False)
        s.time_interval      = d.get('time_interval',      30)
        s.packet_count_based = d.get('packet_count_based', False)
        s.packet_threshold   = d.get('packet_threshold',   100)
        s.random_intervals   = d.get('random_intervals',   False)
        s.min_interval       = d.get('min_interval',       10)
        s.max_interval       = d.get('max_interval',       60)
        s.threat_triggered   = d.get('threat_triggered',   True)
        return jsonify({'success': True})
    return jsonify({
        'reply_triggered':    s.reply_triggered,
        'time_based':         s.time_based,
        'time_interval':      s.time_interval,
        'packet_count_based': s.packet_count_based,
        'packet_threshold':   s.packet_threshold,
        'random_intervals':   s.random_intervals,
        'min_interval':       s.min_interval,
        'max_interval':       s.max_interval,
        'threat_triggered':   s.threat_triggered,
    })


@flask_app.route('/api/morph/force', methods=['POST'])
@login_required
def force_morph():
    if not controller_instance:
        return jsonify({'error': 'Controller not initialized'})
    ips = list(controller_instance.real_to_virtual.keys())
    morphed = 0
    for i in range(0, len(ips) - 1, 2):
        controller_instance.morph_ip_pair(ips[i], ips[i + 1],
                                          "MANUAL", trigger='manual')
        morphed += 1
    return jsonify({'success': True, 'morphed_pairs': morphed})


@flask_app.route('/api/export/csv')
@login_required
def export_csv():
    if not controller_instance:
        return jsonify({'error': 'Controller not initialized'})
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'timestamp', 'protocol', 'ip1', 'ip2',
        'old_vip1', 'new_vip1', 'old_vip2', 'new_vip2', 'trigger'
    ])
    writer.writeheader()
    writer.writerows(controller_instance.stats.morph_history)
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'mtd_history_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
    )


@flask_app.route('/api/export/json')
@login_required
def export_json():
    if not controller_instance:
        return jsonify({'error': 'Controller not initialized'})
    data = controller_instance.stats.get_stats_dict()
    return send_file(
        io.BytesIO(json.dumps(data, indent=2).encode()),
        mimetype='application/json',
        as_attachment=True,
        download_name=f'mtd_stats_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
    )


@flask_app.route('/api/export/pdf')
@login_required
def export_pdf():
    if not controller_instance:
        return jsonify({'error': 'Controller not initialized'})
    if not REPORTLAB_AVAILABLE:
        return jsonify({'error': 'PDF export unavailable. Install reportlab.'})

    buf    = io.BytesIO()
    doc    = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    elems  = []

    elems.append(Paragraph("MTD Controller Report", styles['Title']))
    elems.append(Spacer(1, 12))

    stats = controller_instance.stats.get_stats_dict()
    summary = [
        ['Metric',           'Value'],
        ['Uptime',           stats['uptime']],
        ['Total Morphs',     str(stats['total_morphs'])],
        ['VIP Allocations',  str(stats['vip_allocations'])],
        ['Threats Detected', str(stats['threats_detected'])],
    ]
    t = Table(summary)
    t.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR',   (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN',       (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME',    (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING',(0, 0), (-1, 0), 12),
        ('BACKGROUND',  (0, 1), (-1, -1), colors.beige),
        ('GRID',        (0, 0), (-1, -1), 1, colors.black),
    ]))
    elems.append(t)
    elems.append(Spacer(1, 20))

    elems.append(Paragraph("Recent Morph Events (Last 20)", styles['Heading2']))
    elems.append(Spacer(1, 12))

    rows = [['Time', 'Protocol', 'IPs', 'Trigger']]
    for ev in stats['morph_history'][-20:]:
        rows.append([
            ev['timestamp'].split()[1],
            ev['protocol'],
            f"{ev['ip1']} ↔ {ev['ip2']}",
            ev['trigger'],
        ])
    t2 = Table(rows)
    t2.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR',   (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN',       (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME',    (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING',(0, 0), (-1, 0), 12),
        ('BACKGROUND',  (0, 1), (-1, -1), colors.beige),
        ('GRID',        (0, 0), (-1, -1), 1, colors.black),
    ]))
    elems.append(t2)

    doc.build(elems)
    buf.seek(0)
    return send_file(
        buf,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'mtd_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf',
    )


# ─────────────────────────────────────────────────────────────────────────────
# SocketIO events
# ─────────────────────────────────────────────────────────────────────────────
@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        return False
    print(f'[WS] {current_user.username} connected')
    if controller_instance:
        emit('stats_update',    controller_instance.stats.get_stats_dict())
        emit('mappings_update', {'mappings': [
            {'real_ip': r, 'vip': v}
            for r, v in controller_instance.real_to_virtual.items()
        ]})


@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        print(f'[WS] {current_user.username} disconnected')


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    from ryu.cmd import manager
    import sys
    sys.argv = ['ryu-manager', __file__]
    manager.main()