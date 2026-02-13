
#!/usr/bin/env python3
"""
MTD CONTROLLER WITH WEB DASHBOARD
Real-time monitoring via web interface

REQUIREMENTS:
    pip install ryu rich flask flask-socketio eventlet

USAGE:
    ryu-manager mtd_web_dashboard.py
    
    Then open: http://localhost:5000
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp, udp
from ryu.controller.ofp_handler import OFPHandler
from ryu.lib import hub

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import threading
import time
from datetime import datetime
from collections import defaultdict
import json

# Flask app setup
flask_app = Flask(__name__)
flask_app.config['SECRET_KEY'] = 'mtd-secret-key-2024'
socketio = SocketIO(flask_app, cors_allowed_origins="*", async_mode='eventlet')

# Global reference to controller (set when controller starts)
controller_instance = None


class MTDStatistics:
    """Statistics tracker for MTD operations"""
    
    def __init__(self):
        self.total_morphs = 0
        self.morphs_by_protocol = defaultdict(int)
        self.packets_by_protocol = defaultdict(int)
        self.morph_history = []
        self.vip_allocations = 0
        self.start_time = time.time()
        self.active_connections = []
        
    def record_morph(self, protocol, ip1, ip2, old_vip1, new_vip1, old_vip2, new_vip2):
        """Record a morphing event"""
        self.total_morphs += 1
        self.morphs_by_protocol[protocol] += 1
        event = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'protocol': protocol,
            'ip1': ip1,
            'ip2': ip2,
            'old_vip1': old_vip1,
            'new_vip1': new_vip1,
            'old_vip2': old_vip2,
            'new_vip2': new_vip2
        }
        self.morph_history.append(event)
        
        # Keep only last 100 events
        if len(self.morph_history) > 100:
            self.morph_history.pop(0)
        
        return event
    
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
        
        # Remove duplicates
        self.active_connections = [c for c in self.active_connections 
                                   if not (c['src_ip'] == src_ip and c['dst_ip'] == dst_ip)]
        
        self.active_connections.append(conn)
        
        # Keep only last 50
        if len(self.active_connections) > 50:
            self.active_connections.pop(0)
    
    def get_uptime(self):
        """Get controller uptime"""
        uptime_seconds = int(time.time() - self.start_time)
        hours = uptime_seconds // 3600
        minutes = (uptime_seconds % 3600) // 60
        seconds = uptime_seconds % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    def get_stats_dict(self):
        """Get statistics as dictionary for JSON"""
        return {
            'uptime': self.get_uptime(),
            'total_morphs': self.total_morphs,
            'vip_allocations': self.vip_allocations,
            'morphs_by_protocol': dict(self.morphs_by_protocol),
            'packets_by_protocol': dict(self.packets_by_protocol),
            'morph_history': self.morph_history[-20:],  # Last 20 events
            'active_connections': self.active_connections[-20:]  # Last 20 connections
        }


class MTDWebController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'ofp_handler': OFPHandler}

    def __init__(self, *args, **kwargs):
        super(MTDWebController, self).__init__(*args, **kwargs)
        
        global controller_instance
        controller_instance = self

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

        self.logger.info("MTD Controller with Web Dashboard initialized")
        self.logger.info("Access dashboard at: http://localhost:5000")
        
        # Start Flask in a separate thread
        self.flask_thread = threading.Thread(target=self._start_flask)
        self.flask_thread.daemon = True
        self.flask_thread.start()

    def _start_flask(self):
        """Start Flask web server"""
        socketio.run(flask_app, host='0.0.0.0', port=5000, debug=False, use_reloader=False)

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
            self.logger.warning("VIP pool exhausted!")
            return real_ip

        vip = self.virtual_pool.pop()
        self.real_to_virtual[real_ip] = vip
        self.virtual_to_real[vip] = real_ip
        
        self.stats.vip_allocations += 1
        
        # Emit to web clients
        socketio.emit('vip_allocated', {
            'real_ip': real_ip,
            'vip': vip
        })
        
        # Update mappings
        self._emit_current_mappings()

        return vip

    def morph_ip_pair(self, ip1, ip2, protocol=""):
        """Morph both IPs after successful communication"""
        
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
            # Record statistics
            event = self.stats.record_morph(
                protocol, 
                ip1, ip2,
                old_vips.get(ip1, ''),
                new_vips.get(ip1, ''),
                old_vips.get(ip2, ''),
                new_vips.get(ip2, '')
            )
            
            # Emit morph event to web clients
            socketio.emit('morph_event', event)
            
            # Update current mappings
            self._emit_current_mappings()

    def _emit_current_mappings(self):
        """Emit current VIP mappings to web clients"""
        mappings = [
            {'real_ip': real_ip, 'vip': vip}
            for real_ip, vip in self.real_to_virtual.items()
        ]
        socketio.emit('mappings_update', {'mappings': mappings})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info(f"Switch s{datapath.id} connected")

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
        
        self.stats.record_packet('ICMP')

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
            
            self.stats.add_active_connection('TCP', src_ip, dst_ip, src_port, dst_port)
            socketio.emit('connection_update', {
                'protocol': 'TCP',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'event': 'SYN'
            })

        elif tcp_pkt.has_flags(tcp.TCP_SYN) and tcp_pkt.has_flags(tcp.TCP_ACK):
            if reverse_flow_key in self.tcp_tracker:
                self.tcp_tracker[reverse_flow_key]['syn_ack_seen'] = True

        elif tcp_pkt.has_flags(tcp.TCP_ACK) and not tcp_pkt.has_flags(tcp.TCP_SYN):
            if flow_key in self.tcp_tracker and not self.tcp_tracker[flow_key].get('established', False):
                if self.tcp_tracker[flow_key].get('syn_ack_seen', False):
                    self.tcp_tracker[flow_key]['established'] = True
                    self.morph_ip_pair(src_ip, dst_ip, "TCP")
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
            self.morph_ip_pair(dst_ip, src_ip, "UDP")
            del self.udp_tracker[reverse_flow_key]
        else:
            self.udp_tracker[flow_key] = {'request_seen': True, 'time': time.time()}
            
            self.stats.add_active_connection('UDP', src_ip, dst_ip, src_port, dst_port)
            socketio.emit('connection_update', {
                'protocol': 'UDP',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'event': 'request'
            })

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


# Flask Routes
@flask_app.route('/')
def index():
    """Serve the dashboard HTML"""
    return render_template('dashboard.html')

@flask_app.route('/api/stats')
def get_stats():
    """API endpoint for statistics"""
    if controller_instance:
        return jsonify(controller_instance.stats.get_stats_dict())
    return jsonify({'error': 'Controller not initialized'})

@flask_app.route('/api/mappings')
def get_mappings():
    """API endpoint for current VIP mappings"""
    if controller_instance:
        mappings = [
            {'real_ip': real_ip, 'vip': vip}
            for real_ip, vip in controller_instance.real_to_virtual.items()
        ]
        return jsonify({'mappings': mappings})
    return jsonify({'mappings': []})

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')
    if controller_instance:
        # Send current state to new client
        emit('stats_update', controller_instance.stats.get_stats_dict())
        
        mappings = [
            {'real_ip': real_ip, 'vip': vip}
            for real_ip, vip in controller_instance.real_to_virtual.items()
        ]
        emit('mappings_update', {'mappings': mappings})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')


if __name__ == '__main__':
    from ryu.cmd import manager
    import sys
    sys.argv = ['ryu-manager', __file__]
    manager.main()