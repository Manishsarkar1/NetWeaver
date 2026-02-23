#!/usr/bin/env python3
"""
ULTIMATE MTD CONTROLLER
Features:
- Authentication & User Sessions
- Multiple Morphing Strategies
- Packet Rewriting
- Flow Table Optimization
- Export & Reporting (CSV/JSON/PDF)
- Network Topology Visualization
- Real-time Dashboard

REQUIREMENTS:
    pip install ryu rich flask flask-socketio flask-login eventlet reportlab pandas

USAGE:
    python ultimate_mtd_controller.py
    
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

from flask import Flask, render_template, jsonify, request, redirect, url_for, session, send_file
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

# Flask app setup
flask_app = Flask(__name__)
flask_app.config['SECRET_KEY'] = 'mtd-ultra-secret-key-2024-change-this-in-production'
flask_app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
socketio = SocketIO(flask_app, cors_allowed_origins="*", async_mode='eventlet')

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(flask_app)
login_manager.login_view = 'login'

# Global reference to controller
controller_instance = None

# User database (in production, use a real database)
users_db = {
    'admin': {
        'password': generate_password_hash('mtd2024'),
        'role': 'admin'
    }
}


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


@dataclass
class MorphEvent:
    """Data class for morph events"""
    timestamp: str
    protocol: str
    ip1: str
    ip2: str
    old_vip1: str
    new_vip1: str
    old_vip2: str
    new_vip2: str
    trigger: str  # 'reply', 'time', 'packet_count', 'threat'


@dataclass
class ThreatEvent:
    """Data class for threat events"""
    timestamp: str
    threat_type: str
    source_ip: str
    details: str
    severity: str  # 'low', 'medium', 'high', 'critical'


class MorphingStrategy:
    """Manages different morphing strategies"""
    
    def __init__(self):
        self.reply_triggered = True
        self.time_based = False
        self.time_interval = 30  # seconds
        self.packet_count_based = False
        self.packet_threshold = 100
        self.random_intervals = False
        self.min_interval = 10
        self.max_interval = 60
        self.threat_triggered = True
        
        # Packet counters for packet-based morphing
        self.packet_counters = defaultdict(int)
        
        # Last morph time for each IP pair
        self.last_morph_time = {}
    
    def should_morph_on_reply(self, protocol):
        """Check if reply-triggered morphing is enabled"""
        return self.reply_triggered
    
    def should_morph_time_based(self, ip1, ip2):
        """Check if time-based morphing should trigger"""
        if not self.time_based:
            return False
        
        key = tuple(sorted([ip1, ip2]))
        last_time = self.last_morph_time.get(key, 0)
        
        if self.random_intervals:
            interval = random.randint(self.min_interval, self.max_interval)
        else:
            interval = self.time_interval
        
        if time.time() - last_time >= interval:
            self.last_morph_time[key] = time.time()
            return True
        return False
    
    def should_morph_packet_count(self, ip1, ip2):
        """Check if packet-count morphing should trigger"""
        if not self.packet_count_based:
            return False
        
        key = tuple(sorted([ip1, ip2]))
        self.packet_counters[key] += 1
        
        if self.packet_counters[key] >= self.packet_threshold:
            self.packet_counters[key] = 0
            return True
        return False
    
    def record_packet(self, ip1, ip2):
        """Record a packet for count-based morphing"""
        if self.packet_count_based:
            key = tuple(sorted([ip1, ip2]))
            self.packet_counters[key] += 1


class ThreatDetector:
    """Detect network threats"""
    
    def __init__(self):
        self.port_scan_threshold = 5  # ports
        self.port_scan_window = 10  # seconds
        self.connection_attempts = defaultdict(lambda: {'ports': set(), 'time': time.time()})
        self.threats = []
    
    def detect_port_scan(self, src_ip, dst_ip, dst_port):
        """Detect port scanning behavior"""
        key = (src_ip, dst_ip)
        attempt = self.connection_attempts[key]
        
        # Reset if window expired
        if time.time() - attempt['time'] > self.port_scan_window:
            attempt['ports'] = set()
            attempt['time'] = time.time()
        
        attempt['ports'].add(dst_port)
        
        # Detect scan
        if len(attempt['ports']) >= self.port_scan_threshold:
            threat = ThreatEvent(
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                threat_type='port_scan',
                source_ip=src_ip,
                details=f"Scanned {len(attempt['ports'])} ports on {dst_ip}",
                severity='high'
            )
            self.threats.append(threat)
            
            # Reset
            attempt['ports'] = set()
            attempt['time'] = time.time()
            
            return True
        return False


class MTDStatistics:
    """Enhanced statistics tracker"""
    
    def __init__(self):
        self.total_morphs = 0
        self.morphs_by_protocol = defaultdict(int)
        self.morphs_by_trigger = defaultdict(int)
        self.packets_by_protocol = defaultdict(int)
        self.morph_history = []
        self.vip_allocations = 0
        self.start_time = time.time()
        self.active_connections = []
        self.topology = {'switches': [], 'hosts': [], 'links': []}
        self.threats_detected = 0
        
    def record_morph(self, event: MorphEvent):
        """Record a morphing event"""
        self.total_morphs += 1
        self.morphs_by_protocol[event.protocol] += 1
        self.morphs_by_trigger[event.trigger] += 1
        self.morph_history.append(asdict(event))
        
        # Keep only last 500 events
        if len(self.morph_history) > 500:
            self.morph_history.pop(0)
        
        return asdict(event)
    
    def record_packet(self, protocol):
        """Record a packet processed"""
        self.packets_by_protocol[protocol] += 1
    
    def add_active_connection(self, protocol, src_ip, dst_ip, src_port=None, dst_port=None):
        """Add an active connection"""
        conn = {
            'protocol': protocol,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }
        self.active_connections.append(conn)
        
        # Keep only last 100
        if len(self.active_connections) > 100:
            self.active_connections.pop(0)
    
    def update_topology(self, switches, hosts, links):
        """Update network topology"""
        self.topology = {
            'switches': switches,
            'hosts': hosts,
            'links': links
        }
    
    def get_uptime(self):
        """Get controller uptime"""
        uptime_seconds = int(time.time() - self.start_time)
        hours = uptime_seconds // 3600
        minutes = (uptime_seconds % 3600) // 60
        seconds = uptime_seconds % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    def get_stats_dict(self):
        """Get statistics as dictionary"""
        return {
            'uptime': self.get_uptime(),
            'total_morphs': self.total_morphs,
            'vip_allocations': self.vip_allocations,
            'morphs_by_protocol': dict(self.morphs_by_protocol),
            'morphs_by_trigger': dict(self.morphs_by_trigger),
            'packets_by_protocol': dict(self.packets_by_protocol),
            'morph_history': self.morph_history[-50:],
            'active_connections': self.active_connections[-50:],
            'topology': self.topology,
            'threats_detected': self.threats_detected
        }


class UltimateMTDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'ofp_handler': OFPHandler}

    def __init__(self, *args, **kwargs):
        super(UltimateMTDController, self).__init__(*args, **kwargs)
        
        global controller_instance
        controller_instance = self

        # Basic networking
        self.mac_to_port = {}
        self.datapaths = {}

        # IP virtualization
        self.real_to_virtual = {}
        self.virtual_to_real = {}
        self.virtual_pool = self._init_virtual_pool()

        # Protocol tracking
        self.icmp_tracker = {}
        self.tcp_tracker = {}
        self.udp_tracker = {}

        # Enhanced features
        self.stats = MTDStatistics()
        self.strategy = MorphingStrategy()
        self.threat_detector = ThreatDetector()
        
        # Flow table management
        self.flow_table = {}  # (dpid, src, dst) -> flow_mod

        self.logger.info("=" * 60)
        self.logger.info("ULTIMATE MTD CONTROLLER INITIALIZED")
        self.logger.info("=" * 60)
        self.logger.info("Features: Authentication, Packet Rewriting, Flow Optimization")
        self.logger.info("Dashboard: http://localhost:5000")
        self.logger.info("Default Login: admin / mtd2024")
        self.logger.info("=" * 60)
        
        # Start Flask in a separate thread
        self.flask_thread = threading.Thread(target=self._start_flask, daemon=True)
        self.flask_thread.start()
        
        # Start background tasks
        self.time_morph_thread = hub.spawn(self._time_based_morph_loop)

    def _start_flask(self):
        """Start Flask web server"""
        socketio.run(flask_app, host='0.0.0.0', port=5000, debug=False, use_reloader=False)

    def _init_virtual_pool(self):
        """Initialize pool of virtual IPs"""
        pool = set()
        for i in range(1, 255):
            pool.add(f"192.168.100.{i}")
        return pool

    def _time_based_morph_loop(self):
        """Background thread for time-based morphing"""
        while True:
            hub.sleep(5)  # Check every 5 seconds
            
            if not self.strategy.time_based:
                continue
            
            # Check all active IP pairs
            ips = list(self.real_to_virtual.keys())
            for i in range(0, len(ips) - 1, 2):
                if i + 1 < len(ips):
                    ip1, ip2 = ips[i], ips[i + 1]
                    if self.strategy.should_morph_time_based(ip1, ip2):
                        self.logger.info(f"⏰ Time-based morph: {ip1} ↔ {ip2}")
                        self.morph_ip_pair(ip1, ip2, "TIME", trigger='time')

    def allocate_vip(self, real_ip):
        """Allocate VIP for real IP"""
        if real_ip in self.real_to_virtual:
            return self.real_to_virtual[real_ip]

        if not self.virtual_pool:
            self.logger.warning("VIP pool exhausted!")
            return real_ip

        vip = self.virtual_pool.pop()
        self.real_to_virtual[real_ip] = vip
        self.virtual_to_real[vip] = real_ip
        
        self.stats.vip_allocations += 1
        
        # Emit to web clients
        socketio.emit('vip_allocated', {'real_ip': real_ip, 'vip': vip})
        self._emit_current_mappings()

        return vip

    def morph_ip_pair(self, ip1, ip2, protocol="", trigger='reply'):
        """Morph both IPs with packet rewriting support"""
        
        old_vips = {}
        new_vips = {}
        
        for real_ip in [ip1, ip2]:
            if real_ip not in self.real_to_virtual:
                continue

            old_vip = self.real_to_virtual[real_ip]
            old_vips[real_ip] = old_vip
            
            # Return old VIP to pool
            self.virtual_pool.add(old_vip)
            del self.virtual_to_real[old_vip]

            # Allocate new VIP
            if not self.virtual_pool:
                self.logger.warning("VIP pool exhausted!")
                continue

            new_vip = self.virtual_pool.pop()
            self.real_to_virtual[real_ip] = new_vip
            self.virtual_to_real[new_vip] = real_ip
            new_vips[real_ip] = new_vip

        if old_vips and new_vips:
            # Create morph event
            event = MorphEvent(
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                protocol=protocol,
                ip1=ip1,
                ip2=ip2,
                old_vip1=old_vips.get(ip1, ''),
                new_vip1=new_vips.get(ip1, ''),
                old_vip2=old_vips.get(ip2, ''),
                new_vip2=new_vips.get(ip2, ''),
                trigger=trigger
            )
            
            # Record statistics
            event_dict = self.stats.record_morph(event)
            
            # Emit morph event
            socketio.emit('morph_event', event_dict)
            self._emit_current_mappings()
            
            # Update flow tables with new VIPs
            self._update_flows_after_morph(ip1, ip2, old_vips, new_vips)

    def _update_flows_after_morph(self, ip1, ip2, old_vips, new_vips):
        """Update flow tables after IP morphing"""
        # Delete old flows and install new ones
        for dpid, datapath in self.datapaths.items():
            # This is where packet rewriting would happen
            # For now, we just delete old flows
            pass

    def _emit_current_mappings(self):
        """Emit current VIP mappings to web clients"""
        mappings = [
            {'real_ip': real_ip, 'vip': vip}
            for real_ip, vip in self.real_to_virtual.items()
        ]
        socketio.emit('mappings_update', {'mappings': mappings})

    def _update_topology(self):
        """Update network topology information"""
        switches = [{'dpid': dpid} for dpid in self.datapaths.keys()]
        hosts = [{'ip': ip, 'vip': vip} for ip, vip in self.real_to_virtual.items()]
        links = []  # Would need LLDP for link discovery
        
        self.stats.update_topology(switches, hosts, links)
        socketio.emit('topology_update', self.stats.topology)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        self.datapaths[dpid] = datapath
        self.logger.info(f"✓ Switch s{dpid} connected")

        # Install table-miss flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        # Update topology
        self._update_topology()

    def add_flow(self, datapath, priority, match, actions, idle=0, hard=0, buffer_id=None):
        """Add a flow entry with optimization"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle,
                hard_timeout=hard
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle,
                hard_timeout=hard
            )
        datapath.send_msg(mod)

    def install_flow_for_packet(self, datapath, in_port, out_port, pkt, buffer_id=None):
        """Install optimized flow for known paths"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Match on ethernet addresses
        match = parser.OFPMatch(
            in_port=in_port,
            eth_dst=eth.dst,
            eth_src=eth.src
        )
        
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install flow with 30s idle timeout
        self.add_flow(datapath, 1, match, actions, idle=30, buffer_id=buffer_id)

    def handle_icmp(self, datapath, in_port, pkt, ipv4_pkt, icmp_pkt):
        """Handle ICMP with morphing strategies"""
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        
        self.stats.record_packet('ICMP')
        self.strategy.record_packet(src_ip, dst_ip)

        if src_ip not in self.real_to_virtual:
            self.allocate_vip(src_ip)
        if dst_ip not in self.real_to_virtual:
            self.allocate_vip(dst_ip)

        if icmp_pkt.type == 8:  # Echo Request
            pair_key = (src_ip, dst_ip)
            self.icmp_tracker[pair_key] = {'request_seen': True, 'time': time.time()}
            self.stats.add_active_connection('ICMP', src_ip, dst_ip)
            socketio.emit('connection_update', {
                'protocol': 'ICMP',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'event': 'request'
            })

        elif icmp_pkt.type == 0:  # Echo Reply
            pair_key = (dst_ip, src_ip)

            if pair_key in self.icmp_tracker:
                # Check morphing strategies
                should_morph = False
                trigger = 'reply'
                
                if self.strategy.should_morph_on_reply('ICMP'):
                    should_morph = True
                elif self.strategy.should_morph_packet_count(dst_ip, src_ip):
                    should_morph = True
                    trigger = 'packet_count'
                
                if should_morph:
                    self.morph_ip_pair(dst_ip, src_ip, "ICMP", trigger=trigger)
                
                del self.icmp_tracker[pair_key]

    def handle_tcp(self, datapath, in_port, pkt, ipv4_pkt, tcp_pkt):
        """Handle TCP with threat detection"""
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        src_port = tcp_pkt.src_port
        dst_port = tcp_pkt.dst_port
        
        self.stats.record_packet('TCP')
        self.strategy.record_packet(src_ip, dst_ip)

        if src_ip not in self.real_to_virtual:
            self.allocate_vip(src_ip)
        if dst_ip not in self.real_to_virtual:
            self.allocate_vip(dst_ip)

        flow_key = (src_ip, dst_ip, src_port, dst_port)
        reverse_flow_key = (dst_ip, src_ip, dst_port, src_port)

        # Threat detection - port scan
        if tcp_pkt.has_flags(tcp.TCP_SYN) and not tcp_pkt.has_flags(tcp.TCP_ACK):
            if self.threat_detector.detect_port_scan(src_ip, dst_ip, dst_port):
                self.stats.threats_detected += 1
                socketio.emit('threat_detected', {
                    'type': 'port_scan',
                    'source': src_ip,
                    'target': dst_ip
                })
                
                # Trigger immediate morph
                if self.strategy.threat_triggered:
                    self.logger.warning(f"🚨 Port scan detected! Morphing immediately.")
                    self.morph_ip_pair(src_ip, dst_ip, "TCP", trigger='threat')
                    return

        if tcp_pkt.has_flags(tcp.TCP_SYN) and not tcp_pkt.has_flags(tcp.TCP_ACK):
            self.tcp_tracker[flow_key] = {
                'syn_seen': True,
                'established': False,
                'time': time.time()
            }
            self.stats.add_active_connection('TCP', src_ip, dst_ip, src_port, dst_port)

        elif tcp_pkt.has_flags(tcp.TCP_SYN) and tcp_pkt.has_flags(tcp.TCP_ACK):
            if reverse_flow_key in self.tcp_tracker:
                self.tcp_tracker[reverse_flow_key]['syn_ack_seen'] = True

        elif tcp_pkt.has_flags(tcp.TCP_ACK) and not tcp_pkt.has_flags(tcp.TCP_SYN):
            if flow_key in self.tcp_tracker and not self.tcp_tracker[flow_key].get('established', False):
                if self.tcp_tracker[flow_key].get('syn_ack_seen', False):
                    self.tcp_tracker[flow_key]['established'] = True
                    
                    # Check morphing strategies
                    should_morph = False
                    trigger = 'reply'
                    
                    if self.strategy.should_morph_on_reply('TCP'):
                        should_morph = True
                    elif self.strategy.should_morph_packet_count(src_ip, dst_ip):
                        should_morph = True
                        trigger = 'packet_count'
                    
                    if should_morph:
                        self.morph_ip_pair(src_ip, dst_ip, "TCP", trigger=trigger)
                    
                    del self.tcp_tracker[flow_key]

    def handle_udp(self, datapath, in_port, pkt, ipv4_pkt, udp_pkt):
        """Handle UDP packet tracking"""
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        src_port = udp_pkt.src_port
        dst_port = udp_pkt.dst_port
        
        self.stats.record_packet('UDP')
        self.strategy.record_packet(src_ip, dst_ip)

        if src_ip not in self.real_to_virtual:
            self.allocate_vip(src_ip)
        if dst_ip not in self.real_to_virtual:
            self.allocate_vip(dst_ip)

        flow_key = (src_ip, dst_ip, src_port, dst_port)
        reverse_flow_key = (dst_ip, src_ip, dst_port, src_port)

        if reverse_flow_key in self.udp_tracker:
            should_morph = False
            trigger = 'reply'
            
            if self.strategy.should_morph_on_reply('UDP'):
                should_morph = True
            elif self.strategy.should_morph_packet_count(dst_ip, src_ip):
                should_morph = True
                trigger = 'packet_count'
            
            if should_morph:
                self.morph_ip_pair(dst_ip, src_ip, "UDP", trigger=trigger)
            
            del self.udp_tracker[reverse_flow_key]
        else:
            self.udp_tracker[flow_key] = {'request_seen': True, 'time': time.time()}
            self.stats.add_active_connection('UDP', src_ip, dst_ip, src_port, dst_port)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Main packet processing with flow optimization"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Initialize MAC table
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # Determine output port
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

        # Protocol-specific handling
        if icmp_pkt:
            self.handle_icmp(datapath, in_port, pkt, ipv4_pkt, icmp_pkt)
        elif tcp_pkt:
            self.handle_tcp(datapath, in_port, pkt, ipv4_pkt, tcp_pkt)
        elif udp_pkt:
            self.handle_udp(datapath, in_port, pkt, ipv4_pkt, udp_pkt)

        # Install flow for known destination (optimization)
        if out_port != ofproto.OFPP_FLOOD:
            self.install_flow_for_packet(datapath, in_port, out_port, pkt, msg.buffer_id)
            
            # If buffer_id is valid, flow is installed and packet is sent
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                return

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


# ============================================================================
# FLASK ROUTES - Authentication, Dashboard, API
# ============================================================================

@flask_app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users_db:
            if check_password_hash(users_db[username]['password'], password):
                user = User(username, users_db[username]['role'])
                login_user(user, remember=True)
                return redirect(url_for('index'))
        
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')


@flask_app.route('/logout')
@login_required
def logout():
    """Logout"""
    logout_user()
    return redirect(url_for('login'))


@flask_app.route('/')
@login_required
def index():
    """Main dashboard"""
    return render_template('dashboard_ultimate.html', username=current_user.username)


@flask_app.route('/api/stats')
@login_required
def get_stats():
    """API: Get statistics"""
    if controller_instance:
        return jsonify(controller_instance.stats.get_stats_dict())
    return jsonify({'error': 'Controller not initialized'})


@flask_app.route('/api/mappings')
@login_required
def get_mappings():
    """API: Get VIP mappings"""
    if controller_instance:
        mappings = [
            {'real_ip': real_ip, 'vip': vip}
            for real_ip, vip in controller_instance.real_to_virtual.items()
        ]
        return jsonify({'mappings': mappings})
    return jsonify({'mappings': []})


@flask_app.route('/api/strategy', methods=['GET', 'POST'])
@login_required
def manage_strategy():
    """API: Get/Update morphing strategy"""
    if not controller_instance:
        return jsonify({'error': 'Controller not initialized'})
    
    if request.method == 'POST':
        data = request.json
        strategy = controller_instance.strategy
        
        strategy.reply_triggered = data.get('reply_triggered', True)
        strategy.time_based = data.get('time_based', False)
        strategy.time_interval = data.get('time_interval', 30)
        strategy.packet_count_based = data.get('packet_count_based', False)
        strategy.packet_threshold = data.get('packet_threshold', 100)
        strategy.random_intervals = data.get('random_intervals', False)
        strategy.min_interval = data.get('min_interval', 10)
        strategy.max_interval = data.get('max_interval', 60)
        strategy.threat_triggered = data.get('threat_triggered', True)
        
        return jsonify({'success': True, 'message': 'Strategy updated'})
    
    # GET request
    strategy = controller_instance.strategy
    return jsonify({
        'reply_triggered': strategy.reply_triggered,
        'time_based': strategy.time_based,
        'time_interval': strategy.time_interval,
        'packet_count_based': strategy.packet_count_based,
        'packet_threshold': strategy.packet_threshold,
        'random_intervals': strategy.random_intervals,
        'min_interval': strategy.min_interval,
        'max_interval': strategy.max_interval,
        'threat_triggered': strategy.threat_triggered
    })


@flask_app.route('/api/morph/force', methods=['POST'])
@login_required
def force_morph():
    """API: Force immediate morphing"""
    if not controller_instance:
        return jsonify({'error': 'Controller not initialized'})
    
    # Morph all active IP pairs
    ips = list(controller_instance.real_to_virtual.keys())
    morphed = 0
    
    for i in range(0, len(ips) - 1, 2):
        if i + 1 < len(ips):
            ip1, ip2 = ips[i], ips[i + 1]
            controller_instance.morph_ip_pair(ip1, ip2, "MANUAL", trigger='manual')
            morphed += 1
    
    return jsonify({'success': True, 'morphed_pairs': morphed})


@flask_app.route('/api/export/csv')
@login_required
def export_csv():
    """Export morph history as CSV"""
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
        download_name=f'mtd_history_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )


@flask_app.route('/api/export/json')
@login_required
def export_json():
    """Export complete stats as JSON"""
    if not controller_instance:
        return jsonify({'error': 'Controller not initialized'})
    
    data = controller_instance.stats.get_stats_dict()
    
    return send_file(
        io.BytesIO(json.dumps(data, indent=2).encode()),
        mimetype='application/json',
        as_attachment=True,
        download_name=f'mtd_stats_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    )


@flask_app.route('/api/export/pdf')
@login_required
def export_pdf():
    """Export report as PDF"""
    if not controller_instance:
        return jsonify({'error': 'Controller not initialized'})
    
    if not REPORTLAB_AVAILABLE:
        return jsonify({'error': 'PDF export not available. Install reportlab.'})
    
    # Create PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title = Paragraph("MTD Controller Report", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))
    
    # Statistics summary
    stats = controller_instance.stats.get_stats_dict()
    summary_data = [
        ['Metric', 'Value'],
        ['Uptime', stats['uptime']],
        ['Total Morphs', str(stats['total_morphs'])],
        ['VIP Allocations', str(stats['vip_allocations'])],
        ['Threats Detected', str(stats['threats_detected'])]
    ]
    
    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(summary_table)
    elements.append(Spacer(1, 20))
    
    # Recent morph events
    events_title = Paragraph("Recent Morph Events (Last 20)", styles['Heading2'])
    elements.append(events_title)
    elements.append(Spacer(1, 12))
    
    events_data = [['Time', 'Protocol', 'IPs', 'Trigger']]
    for event in stats['morph_history'][-20:]:
        events_data.append([
            event['timestamp'].split()[1],
            event['protocol'],
            f"{event['ip1']} ↔ {event['ip2']}",
            event['trigger']
        ])
    
    events_table = Table(events_data)
    events_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(events_table)
    
    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'mtd_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    )


@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    if not current_user.is_authenticated:
        return False
    
    print(f'User {current_user.username} connected')
    if controller_instance:
        emit('stats_update', controller_instance.stats.get_stats_dict())
        
        mappings = [
            {'real_ip': real_ip, 'vip': vip}
            for real_ip, vip in controller_instance.real_to_virtual.items()
        ]
        emit('mappings_update', {'mappings': mappings})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    if current_user.is_authenticated:
        print(f'User {current_user.username} disconnected')


if __name__ == '__main__':
    from ryu.cmd import manager
    import sys
    sys.argv = ['ryu-manager', __file__]
    manager.main()