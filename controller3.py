#!/usr/bin/env python3
"""
VANTA SDN CONTROLLER - Network Morphing Defense System (OpenFlow 1.3)
A complete OpenFlow 1.3 SDN controller built from scratch
No frameworks - pure Python socket programming

INSTALLATION:
    pip install click

USAGE:
    python3 controller.py
    
    In another terminal:
    sudo mn --controller=remote,ip=127.0.0.1,port=6633 --switch ovs,failmode=standalone --topo=single,3
"""

import socket
import struct
import threading
import time
import random
import select
import click
from collections import defaultdict
from datetime import datetime

# ============================================================================
# OpenFlow 1.3 Protocol Constants & Message Structures
# ============================================================================

# OpenFlow version
OFP_VERSION = 0x04  # OpenFlow 1.3

# OpenFlow message types
OFPT_HELLO = 0
OFPT_ERROR = 1
OFPT_ECHO_REQUEST = 2
OFPT_ECHO_REPLY = 3
OFPT_EXPERIMENTER = 4
OFPT_FEATURES_REQUEST = 5
OFPT_FEATURES_REPLY = 6
OFPT_GET_CONFIG_REQUEST = 7
OFPT_GET_CONFIG_REPLY = 8
OFPT_SET_CONFIG = 9
OFPT_PACKET_IN = 10
OFPT_FLOW_REMOVED = 11
OFPT_PORT_STATUS = 12
OFPT_PACKET_OUT = 13
OFPT_FLOW_MOD = 14
OFPT_GROUP_MOD = 15
OFPT_PORT_MOD = 16
OFPT_TABLE_MOD = 17

# Flow mod commands
OFPFC_ADD = 0
OFPFC_MODIFY = 1
OFPFC_MODIFY_STRICT = 2
OFPFC_DELETE = 3
OFPFC_DELETE_STRICT = 4

# Packet in reasons
OFPR_NO_MATCH = 0
OFPR_ACTION = 1
OFPR_INVALID_TTL = 2

# Port numbers (OpenFlow 1.3)
OFPP_MAX = 0xffffff00
OFPP_IN_PORT = 0xfffffff8
OFPP_TABLE = 0xfffffff9
OFPP_NORMAL = 0xfffffffa
OFPP_FLOOD = 0xfffffffb
OFPP_ALL = 0xfffffffc
OFPP_CONTROLLER = 0xfffffffd
OFPP_LOCAL = 0xfffffffe
OFPP_ANY = 0xffffffff

# Buffer IDs
OFP_NO_BUFFER = 0xffffffff

# Match types
OFPMT_OXM = 1  # OpenFlow Extensible Match

# OXM (OpenFlow Extensible Match) Classes
OFPXMC_OPENFLOW_BASIC = 0x8000

# OXM Field Types (OpenFlow Basic)
OFPXMT_OFB_IN_PORT = 0
OFPXMT_OFB_ETH_DST = 3
OFPXMT_OFB_ETH_SRC = 4
OFPXMT_OFB_ETH_TYPE = 5
OFPXMT_OFB_IPV4_SRC = 11
OFPXMT_OFB_IPV4_DST = 12

# Ethernet types
ETH_TYPE_IP = 0x0800
ETH_TYPE_ARP = 0x0806

# IP protocols
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

# Instruction types (OpenFlow 1.3)
OFPIT_GOTO_TABLE = 1
OFPIT_WRITE_METADATA = 2
OFPIT_WRITE_ACTIONS = 3
OFPIT_APPLY_ACTIONS = 4
OFPIT_CLEAR_ACTIONS = 5

# Action types
OFPAT_OUTPUT = 0
OFPAT_COPY_TTL_OUT = 11
OFPAT_COPY_TTL_IN = 12
OFPAT_SET_MPLS_TTL = 15
OFPAT_DEC_MPLS_TTL = 16
OFPAT_PUSH_VLAN = 17
OFPAT_POP_VLAN = 18
OFPAT_PUSH_MPLS = 19
OFPAT_POP_MPLS = 20
OFPAT_SET_QUEUE = 21
OFPAT_GROUP = 22
OFPAT_SET_NW_TTL = 23
OFPAT_DEC_NW_TTL = 24
OFPAT_SET_FIELD = 25

# Flow mod flags
OFPFF_SEND_FLOW_REM = 1 << 0
OFPFF_CHECK_OVERLAP = 1 << 1


# ============================================================================
# Core Controller Class - OpenFlow 1.3 Implementation
# ============================================================================

class VantaController:
    """
    Main SDN Controller implementing network morphing defense with OpenFlow 1.3
    """
    
    def __init__(self, host='0.0.0.0', port=6633):
        self.host = host
        self.port = port
        self.server_socket = None
        self.switches = {}  # datapath_id -> socket
        self.running = False
        
        # Learning switch tables
        self.mac_to_port = {}  # dpid -> {mac -> port}
        
        # Network morphing state
        self.real_to_virtual = {}  # Real IP -> Virtual IP
        self.virtual_to_real = {}  # Virtual IP -> Real IP
        self.morph_counter = 0
        self.last_morph_time = time.time()
        self.morph_interval = 10  # seconds
        
        # Attack detection
        self.packet_stats = defaultdict(lambda: defaultdict(int))
        self.arp_stats = defaultdict(int)
        self.attack_detected = False
        self.honeypot_ip = "10.0.0.99"
        
        # Flow tracking
        self.flow_count = 0
        self.total_packets = 0
        
        # Logging
        self.log_lock = threading.Lock()
        
    def log(self, message, level="INFO"):
        """Thread-safe logging with timestamps and colors"""
        with self.log_lock:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            # Color mapping for different log levels
            if level == "SYS":
                colored_level = click.style(level, fg='cyan', bold=True)
                colored_msg = click.style(message, fg='cyan')
            elif level == "CONN":
                colored_level = click.style(level, fg='green', bold=True)
                colored_msg = click.style(message, fg='green')
            elif level == "HAND":
                colored_level = click.style(level, fg='blue', bold=True)
                colored_msg = click.style(message, fg='blue')
            elif level == "SWITCH":
                colored_level = click.style(level, fg='magenta', bold=True)
                colored_msg = click.style(message, fg='magenta', bold=True)
            elif level == "LEARN":
                colored_level = click.style(level, fg='yellow', bold=True)
                colored_msg = click.style(message, fg='yellow')
            elif level == "FLOW":
                colored_level = click.style(level, fg='green', bold=True)
                colored_msg = click.style(message, fg='white')
            elif level == "FLOOD":
                colored_level = click.style(level, fg='white', bold=True)
                colored_msg = click.style(message, fg='white', dim=True)
            elif level == "MORPH":
                colored_level = click.style(level, fg='magenta', bold=True)
                colored_msg = click.style(message, fg='magenta', bold=True)
            elif level == "ATTACK":
                colored_level = click.style(level, fg='red', bold=True, blink=True)
                colored_msg = click.style(message, fg='red', bold=True)
            elif level == "ERROR":
                colored_level = click.style(level, fg='red', bold=True)
                colored_msg = click.style(message, fg='red')
            elif level == "WARN":
                colored_level = click.style(level, fg='yellow', bold=True)
                colored_msg = click.style(message, fg='yellow', dim=True)
            elif level == "DEBUG":
                colored_level = click.style(level, fg='white', dim=True)
                colored_msg = click.style(message, fg='white', dim=True)
            else:
                colored_level = click.style(level, fg='white')
                colored_msg = message
            
            # Format timestamp
            colored_timestamp = click.style(f"[{timestamp}]", fg='bright_black')
            
            print(f"{colored_timestamp} [{colored_level}] {colored_msg}")
    
    def start(self):
        """Start the controller TCP server"""
        click.clear()
        click.secho("=" * 70, fg='cyan', bold=True)
        click.secho("VANTA SDN CONTROLLER - Network Morphing Defense System", fg='cyan', bold=True)
        click.secho("OpenFlow 1.3 Edition", fg='bright_cyan')
        click.secho("=" * 70, fg='cyan', bold=True)
        print()
        
        # Create TCP socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        
        self.log(f"Controller listening on {self.host}:{self.port} (OpenFlow 1.3)", "SYS")
        
        # Start background threads
        threading.Thread(target=self.network_morpher, daemon=True).start()
        threading.Thread(target=self.dashboard, daemon=True).start()
        
        # Accept connections
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                self.log(f"New connection from {address}", "CONN")
                threading.Thread(target=self.handle_switch, 
                               args=(client_socket, address), 
                               daemon=True).start()
            except Exception as e:
                if self.running:
                    self.log(f"Accept error: {e}", "ERROR")
    
    def handle_switch(self, sock, address):
        """Handle communication with a single switch"""
        dpid = None
        
        try:
            # Perform OpenFlow handshake
            dpid = self.openflow_handshake(sock)
            if dpid:
                self.switches[dpid] = sock
                self.mac_to_port[dpid] = {}
                self.log(f"Switch {dpid:016x} connected successfully", "SWITCH")
                
                # Handle messages from this switch
                while self.running:
                    header = self.recv_exact(sock, 8)
                    if not header:
                        break
                    
                    version, msg_type, length, xid = struct.unpack('!BBHI', header)
                    
                    if length > 8:
                        body = self.recv_exact(sock, length - 8)
                        if not body:
                            break
                    else:
                        body = b''
                    
                    # Route message to appropriate handler
                    if msg_type == OFPT_ECHO_REQUEST:
                        self.handle_echo_request(sock, xid)
                    elif msg_type == OFPT_PACKET_IN:
                        self.handle_packet_in(sock, dpid, body, xid)
                        
        except Exception as e:
            self.log(f"Switch handler error: {e}", "ERROR")
        finally:
            if dpid and dpid in self.switches:
                del self.switches[dpid]
                self.log(f"Switch {dpid:016x} disconnected", "SWITCH")
            sock.close()
    
    def recv_exact(self, sock, length):
        """Receive exact number of bytes"""
        data = b''
        while len(data) < length:
            try:
                chunk = sock.recv(length - len(data))
                if not chunk:
                    # Connection closed
                    return None
                data += chunk
            except socket.timeout:
                self.log(f"recv timeout after {len(data)}/{length} bytes", "DEBUG")
                return None
            except Exception as e:
                self.log(f"recv error: {e}", "DEBUG")
                return None
        return data
    
    # ========================================================================
    # OpenFlow 1.3 Handshake Implementation
    # ========================================================================
    
    def openflow_handshake(self, sock):
        """
        Perform OpenFlow 1.3 handshake with switch
        """
        try:
            self.log(">>> Starting OpenFlow 1.3 handshake...", "HAND")
            sock.settimeout(30.0)  # Increase timeout to 30 seconds
            
            # Step 1: Receive HELLO from switch
            self.log(">>> Waiting for HELLO...", "HAND")
            header = self.recv_exact(sock, 8)
            if not header:
                self.log("!!! Failed to receive HELLO - connection closed", "ERROR")
                return None
            
            if len(header) < 8:
                self.log(f"!!! Incomplete HELLO header: got {len(header)} bytes, need 8", "ERROR")
                return None
            
            version, msg_type, length, xid = struct.unpack('!BBHI', header)
            self.log(f">>> Received message: type={msg_type}, length={length}, version=0x{version:02x}", "HAND")
            
            # Read any HELLO body (version bitmaps in OF1.3)
            if length > 8:
                hello_body = self.recv_exact(sock, length - 8)
            
            if msg_type != OFPT_HELLO:
                self.log(f"!!! Expected HELLO, got type {msg_type}", "ERROR")
                return None
            
            self.log(f"✓ Received HELLO from switch (version 0x{version:02x})", "HAND")
            
            # Step 2: Send HELLO reply (use OpenFlow 1.3 - widely supported)
            # Even if switch supports 1.6, we'll negotiate down to 1.3
            reply_version = OFP_VERSION  # Always use 1.3 (0x04)
            hello_msg = struct.pack('!BBHI', reply_version, OFPT_HELLO, 8, 1)
            sock.send(hello_msg)
            self.log(f"✓ Sent HELLO reply (OpenFlow 1.3 - negotiating down from 0x{version:02x})", "HAND")
            
            # Step 3: Send FEATURES_REQUEST
            features_req = struct.pack('!BBHI', OFP_VERSION, OFPT_FEATURES_REQUEST, 8, 2)
            sock.send(features_req)
            self.log("✓ Sent FEATURES_REQUEST", "HAND")
            
            # Step 4: Receive FEATURES_REPLY
            header = self.recv_exact(sock, 8)
            if not header:
                self.log("!!! Failed to receive FEATURES_REPLY", "ERROR")
                return None
            
            version, msg_type, length, xid = struct.unpack('!BBHI', header)
            self.log(f">>> Received message: type={msg_type}, length={length}", "HAND")
            
            if msg_type != OFPT_FEATURES_REPLY:
                self.log(f"!!! Expected FEATURES_REPLY, got {msg_type}", "ERROR")
                return None
            
            body = self.recv_exact(sock, length - 8)
            if not body or len(body) < 8:
                self.log(f"!!! FEATURES_REPLY body too short: {len(body) if body else 0} bytes", "ERROR")
                return None
            
            # Extract datapath ID (first 8 bytes - consistent across OF versions)
            dpid = struct.unpack('!Q', body[0:8])[0]
            
            # Parse remaining fields based on available data
            n_buffers = 256  # default
            n_tables = 254   # default
            capabilities = 0 # default
            
            if len(body) >= 12:
                n_buffers = struct.unpack('!I', body[8:12])[0]
            if len(body) >= 13:
                n_tables = struct.unpack('!B', body[12:13])[0]
            if len(body) >= 24:
                # OpenFlow 1.3+ structure
                try:
                    capabilities = struct.unpack('!I', body[16:20])[0]
                except:
                    pass
            
            self.log(f"✓ Switch DPID: {dpid:016x}", "HAND")
            self.log(f"  Buffers: {n_buffers}, Tables: {n_tables}, Capabilities: 0x{capabilities:08x}", "HAND")
            
            # Step 5: Send SET_CONFIG
            config_msg = struct.pack('!BBHIHH', 
                                    OFP_VERSION, OFPT_SET_CONFIG, 12, 3,
                                    0,  # flags
                                    0xffff)  # miss_send_len (send full packet)
            sock.send(config_msg)
            self.log("✓ Sent SET_CONFIG", "HAND")
            
            # Step 6: Install table-miss flow entry (OpenFlow 1.3 requirement)
            self.install_table_miss_flow(sock)
            
            # Step 7: Also install a simple flood-all rule as backup
            self.install_flood_all_rule(sock)
            
            self.log(f"✓✓✓ HANDSHAKE COMPLETE - Switch {dpid:016x} ready! ✓✓✓", "HAND")
            return dpid
            
        except Exception as e:
            self.log(f"Handshake error: {e}", "ERROR")
            import traceback
            traceback.print_exc()
            return None
    
    def install_table_miss_flow(self, sock):
        """
        Install table-miss flow entry (required in OpenFlow 1.3)
        This catches all unmatched packets and sends them to controller
        """
        try:
            self.log("Installing table-miss flow entry...", "FLOW")
            
            # Match: empty (matches all packets)
            match = self.build_match_ofp13([])
            
            # Instruction: APPLY_ACTIONS with OUTPUT to CONTROLLER
            action = struct.pack('!HHIHH6x',
                                OFPAT_OUTPUT,  # type
                                16,            # len
                                OFPP_CONTROLLER,  # port
                                0xffff,        # max_len (send full packet)
                                0)             # padding
            
            instruction = struct.pack('!HH',
                                     OFPIT_APPLY_ACTIONS,  # type
                                     8 + len(action))       # len
            instruction += action
            
            # Build FLOW_MOD
            flow_mod = struct.pack('!BBHI', OFP_VERSION, OFPT_FLOW_MOD, 0, 4)  # length filled later
            flow_mod += struct.pack('!QQBBBHHIHHI2x',
                                   0,  # cookie (8 bytes Q)
                                   0,  # cookie_mask (8 bytes Q)
                                   0,  # table_id (1 byte B)
                                   OFPFC_ADD,  # command (1 byte B)
                                   0,  # auxiliary_id (1 byte B)
                                   0,  # pad (2 bytes H)
                                   0,  # idle_timeout (2 bytes H)
                                   0,  # hard_timeout (2 bytes H)
                                   0,  # priority (2 bytes H)
                                   OFP_NO_BUFFER,  # buffer_id (4 bytes I)
                                   OFPP_ANY,  # out_port (4 bytes I)
                                   0,  # out_group (4 bytes I)
                                   0)  # flags (2 bytes H)
                                   # 2x = 2 bytes padding
            flow_mod += match
            flow_mod += instruction
            
            # Update length
            flow_mod = struct.pack('!BBHI', OFP_VERSION, OFPT_FLOW_MOD, len(flow_mod), 4) + flow_mod[8:]
            
            sock.send(flow_mod)
            self.log("✓ Table-miss flow entry installed successfully!", "FLOW")
            self.log(f"  Match: ALL packets, Action: Send to CONTROLLER", "FLOW")
            
        except Exception as e:
            self.log(f"✗ Failed to install table-miss flow: {e}", "ERROR")
            import traceback
            traceback.print_exc()
    
    def install_flood_all_rule(self, sock):
        """
        Install a backup rule that floods all ARP packets
        This helps with initial connectivity
        """
        try:
            self.log("Installing ARP flood rule as backup...", "FLOW")
            
            # Match: ARP packets only
            match = self.build_match_ofp13([('eth_type', ETH_TYPE_ARP)])
            
            # Action: OUTPUT to FLOOD
            action = struct.pack('!HHIHH6x',
                                OFPAT_OUTPUT,
                                16,
                                OFPP_FLOOD,
                                0xffff,
                                0)
            
            instruction = struct.pack('!HH',
                                     OFPIT_APPLY_ACTIONS,
                                     8 + len(action))
            instruction += action
            
            # Build FLOW_MOD with priority 10 (higher than table-miss)
            flow_mod = struct.pack('!BBHI', OFP_VERSION, OFPT_FLOW_MOD, 0, 5)
            flow_mod += struct.pack('!QQBBBHHIHHI2x',
                                   0, 0, 0,  # cookie, cookie_mask, table_id
                                   OFPFC_ADD, 0, 0,  # command, auxiliary_id, pad
                                   0, 0,  # idle_timeout, hard_timeout
                                   10,  # priority (higher than table-miss)
                                   OFP_NO_BUFFER,  # buffer_id
                                   OFPP_ANY,  # out_port
                                   0,  # out_group
                                   0)  # flags
            flow_mod += match
            flow_mod += instruction
            
            flow_mod = struct.pack('!BBHI', OFP_VERSION, OFPT_FLOW_MOD, len(flow_mod), 5) + flow_mod[8:]
            
            sock.send(flow_mod)
            self.log("✓ ARP flood rule installed", "FLOW")
            
        except Exception as e:
            self.log(f"Failed to install ARP flood rule: {e}", "WARN")
    
    def handle_echo_request(self, sock, xid):
        """Respond to echo requests (keepalive)"""
        echo_reply = struct.pack('!BBHI', OFP_VERSION, OFPT_ECHO_REPLY, 8, xid)
        sock.send(echo_reply)
    
    # ========================================================================
    # OpenFlow 1.3 Match Builder
    # ========================================================================
    
    def build_match_ofp13(self, match_fields):
        """
        Build OpenFlow 1.3 OXM match structure
        match_fields: list of (field_type, value) tuples
        """
        oxm_fields = b''
        
        for field_type, value in match_fields:
            if field_type == 'in_port':
                # IN_PORT: 4 bytes
                oxm_fields += struct.pack('!HBB', 
                                         OFPXMC_OPENFLOW_BASIC << 7 | OFPXMT_OFB_IN_PORT,
                                         4,  # length
                                         0)  # no mask
                oxm_fields += struct.pack('!I', value)
                
            elif field_type == 'eth_dst':
                # ETH_DST: 6 bytes
                oxm_fields += struct.pack('!HBB',
                                         OFPXMC_OPENFLOW_BASIC << 7 | OFPXMT_OFB_ETH_DST,
                                         6,
                                         0)
                oxm_fields += value  # 6-byte MAC address
                
            elif field_type == 'eth_src':
                # ETH_SRC: 6 bytes
                oxm_fields += struct.pack('!HBB',
                                         OFPXMC_OPENFLOW_BASIC << 7 | OFPXMT_OFB_ETH_SRC,
                                         6,
                                         0)
                oxm_fields += value
                
            elif field_type == 'eth_type':
                # ETH_TYPE: 2 bytes
                oxm_fields += struct.pack('!HBB',
                                         OFPXMC_OPENFLOW_BASIC << 7 | OFPXMT_OFB_ETH_TYPE,
                                         2,
                                         0)
                oxm_fields += struct.pack('!H', value)
        
        # Build match header
        match_len = 4 + len(oxm_fields)
        padding_len = (8 - (match_len % 8)) % 8  # Align to 8 bytes
        
        match = struct.pack('!HH',
                           OFPMT_OXM,  # type
                           match_len)   # length
        match += oxm_fields
        match += b'\x00' * padding_len
        
        return match
    
    # ========================================================================
    # Packet-In Handler - Learning Switch Logic
    # ========================================================================
    
    def handle_packet_in(self, sock, dpid, body, xid):
        """
        Handle OpenFlow 1.3 PACKET_IN messages
        """
        try:
            self.total_packets += 1
            
            # Parse OpenFlow 1.3 Packet-In structure
            if len(body) < 24:
                return
            
            buffer_id, total_len, reason, table_id = struct.unpack('!IHBB', body[0:8])
            cookie = struct.unpack('!Q', body[8:16])[0]
            
            # Parse match (variable length)
            match_type, match_len = struct.unpack('!HH', body[16:20])
            match_data = body[20:20+match_len-4]  # -4 for header
            
            # Parse in_port from match
            in_port = self.parse_in_port_from_match(match_data)
            if in_port is None:
                in_port = 1  # Default
            
            # Find start of Ethernet frame (after match + padding)
            match_end = 16 + match_len
            padding = (8 - (match_len % 8)) % 8
            eth_start = match_end + padding + 2  # +2 for padding field
            
            ethernet_frame = body[eth_start:]
            
            if len(ethernet_frame) < 14:
                return
            
            # Parse Ethernet header
            dst_mac = ethernet_frame[0:6]
            src_mac = ethernet_frame[6:12]
            eth_type = struct.unpack('!H', ethernet_frame[12:14])[0]
            
            dst_mac_str = ':'.join(f'{b:02x}' for b in dst_mac)
            src_mac_str = ':'.join(f'{b:02x}' for b in src_mac)
            
            # Learn the source MAC address
            if src_mac_str not in self.mac_to_port[dpid]:
                self.mac_to_port[dpid][src_mac_str] = in_port
                self.log(f"Learned: {src_mac_str} -> Port {in_port}", "LEARN")
            
            # Attack detection
            if eth_type == ETH_TYPE_ARP:
                self.detect_arp_flood(src_mac_str)
            elif eth_type == ETH_TYPE_IP and len(ethernet_frame) >= 34:
                self.detect_port_scan(ethernet_frame)
            
            # Determine output port
            out_port = self.mac_to_port[dpid].get(dst_mac_str)
            
            if out_port is not None:
                # Destination known - install flow rule
                self.install_flow_ofp13(sock, dpid, in_port, out_port, 
                                       src_mac, dst_mac, eth_type, buffer_id, xid)
            else:
                # Destination unknown - flood packet
                self.flood_packet_ofp13(sock, in_port, buffer_id, ethernet_frame, xid)
                
        except Exception as e:
            self.log(f"Packet-In error: {e}", "ERROR")
            import traceback
            traceback.print_exc()
    
    def parse_in_port_from_match(self, match_data):
        """Extract in_port from OXM match data"""
        try:
            offset = 0
            while offset < len(match_data):
                if offset + 4 > len(match_data):
                    break
                    
                oxm_header = struct.unpack('!I', match_data[offset:offset+4])[0]
                oxm_class = (oxm_header >> 16) & 0xFFFF
                oxm_field = (oxm_header >> 9) & 0x7F
                oxm_length = oxm_header & 0xFF
                
                if oxm_field == OFPXMT_OFB_IN_PORT and oxm_length == 4:
                    in_port = struct.unpack('!I', match_data[offset+4:offset+8])[0]
                    return in_port
                
                offset += 4 + oxm_length
        except:
            pass
        return None
    
    # ========================================================================
    # Flow Control - OpenFlow 1.3
    # ========================================================================
    
    def install_flow_ofp13(self, sock, dpid, in_port, out_port, src_mac, dst_mac, 
                          eth_type, buffer_id, xid):
        """
        Install a flow rule using OpenFlow 1.3
        """
        try:
            # Build match
            match_fields = [
                ('in_port', in_port),
                ('eth_src', src_mac),
                ('eth_dst', dst_mac),
                ('eth_type', eth_type)
            ]
            match = self.build_match_ofp13(match_fields)
            
            # Build action: OUTPUT to specific port
            action = struct.pack('!HHIHH6x',
                                OFPAT_OUTPUT,
                                16,
                                out_port,
                                0xffff,  # max_len
                                0)       # padding
            
            # Build instruction: APPLY_ACTIONS
            instruction = struct.pack('!HH',
                                     OFPIT_APPLY_ACTIONS,
                                     8 + len(action))
            instruction += action
            
            # Build FLOW_MOD message
            flow_mod = struct.pack('!BBHI', OFP_VERSION, OFPT_FLOW_MOD, 0, xid)
            flow_mod += struct.pack('!QQBBBHHIHHI2x',
                                   0,  # cookie (8 bytes)
                                   0,  # cookie_mask (8 bytes)
                                   0,  # table_id (1 byte)
                                   OFPFC_ADD,  # command (1 byte)
                                   0,  # auxiliary_id (1 byte)
                                   0,  # pad (2 bytes)
                                   10,  # idle_timeout (2 bytes)
                                   30,  # hard_timeout (2 bytes)
                                   100,  # priority (2 bytes)
                                   buffer_id,  # buffer_id (4 bytes)
                                   OFPP_ANY,  # out_port (4 bytes)
                                   0,  # out_group (4 bytes)
                                   OFPFF_SEND_FLOW_REM)  # flags (2 bytes)
                                   # 2x = 2 bytes padding
            flow_mod += match
            flow_mod += instruction
            
            # Update length
            flow_mod = struct.pack('!BBHI', OFP_VERSION, OFPT_FLOW_MOD, len(flow_mod), xid) + flow_mod[8:]
            
            sock.send(flow_mod)
            self.flow_count += 1
            
            src_mac_str = ':'.join(f'{b:02x}' for b in src_mac)
            dst_mac_str = ':'.join(f'{b:02x}' for b in dst_mac)
            self.log(f"Flow installed: {src_mac_str} -> {dst_mac_str} via port {out_port}", "FLOW")
            
        except Exception as e:
            self.log(f"Flow install error: {e}", "ERROR")
            import traceback
            traceback.print_exc()
    
    def flood_packet_ofp13(self, sock, in_port, buffer_id, packet_data, xid):
        """
        Flood packet using OpenFlow 1.3 PACKET_OUT
        """
        try:
            # Build action: OUTPUT to FLOOD
            action = struct.pack('!HHIHH6x',
                                OFPAT_OUTPUT,
                                16,
                                OFPP_FLOOD,
                                0xffff,
                                0)
            
            # Build PACKET_OUT message
            packet_out = struct.pack('!BBHI', OFP_VERSION, OFPT_PACKET_OUT, 0, xid)
            packet_out += struct.pack('!IIH6x',
                                     buffer_id,
                                     in_port,
                                     len(action))  # actions_len
            packet_out += action
            
            if buffer_id == OFP_NO_BUFFER:
                packet_out += packet_data
            
            # Update length
            packet_out = struct.pack('!BBHI', OFP_VERSION, OFPT_PACKET_OUT, len(packet_out), xid) + packet_out[8:]
            
            sock.send(packet_out)
            self.log(f"Packet flooded from port {in_port}", "FLOOD")
            
        except Exception as e:
            self.log(f"Flood error: {e}", "ERROR")
    
    # ========================================================================
    # Network Morphing - Virtual IP Management
    # ========================================================================
    
    def network_morpher(self):
        """
        Background thread that morphs the network topology
        """
        self.log("Network morpher started", "MORPH")
        
        while self.running:
            time.sleep(1)
            
            should_morph = (time.time() - self.last_morph_time >= self.morph_interval)
            
            if self.attack_detected:
                self.log("ATTACK DETECTED - TRIGGERING EMERGENCY MORPH!", "ATTACK")
                should_morph = True
                self.attack_detected = False
            
            if should_morph:
                self.perform_network_morph()
                self.last_morph_time = time.time()
    
    def perform_network_morph(self):
        """
        Morph the network by reassigning virtual IPs
        """
        self.morph_counter += 1
        
        click.secho("=" * 70, fg='magenta', bold=True)
        click.secho(f"🔄 NETWORK MORPH #{self.morph_counter} - Reconfiguring topology", fg='magenta', bold=True)
        
        real_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        
        old_mappings = self.real_to_virtual.copy()
        self.real_to_virtual.clear()
        self.virtual_to_real.clear()
        
        for real_ip in real_ips:
            virtual_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            self.real_to_virtual[real_ip] = virtual_ip
            self.virtual_to_real[virtual_ip] = real_ip
            
            old_vip = old_mappings.get(real_ip, "none")
            
            click.secho(f"  {real_ip} ", nl=False, fg='white')
            click.secho("→", nl=False, fg='bright_black')
            click.secho(f" {virtual_ip} ", nl=False, fg='cyan', bold=True)
            click.secho(f"(was {old_vip})", fg='bright_black', dim=True)
        
        click.secho(f"✓ Morph complete - {len(self.real_to_virtual)} hosts remapped", fg='green', bold=True)
        click.secho("=" * 70, fg='magenta', bold=True)
    
    # ========================================================================
    # Attack Detection
    # ========================================================================
    
    def detect_port_scan(self, ethernet_frame):
        """Detect port scanning behavior"""
        try:
            if len(ethernet_frame) < 34:
                return
            
            ip_header = ethernet_frame[14:34]
            src_ip = socket.inet_ntoa(ip_header[12:16])
            protocol = ip_header[9]
            
            if protocol in [IP_PROTO_TCP, IP_PROTO_UDP] and len(ethernet_frame) >= 38:
                dst_port = struct.unpack('!H', ethernet_frame[36:38])[0]
                self.packet_stats[src_ip][dst_port] += 1
                
                if len(self.packet_stats[src_ip]) > 10:
                    self.log(f"PORT SCAN DETECTED from {src_ip} ({len(self.packet_stats[src_ip])} ports)", "ATTACK")
                    self.attack_detected = True
                    self.packet_stats[src_ip].clear()
                    
        except Exception as e:
            pass
    
    def detect_arp_flood(self, src_mac):
        """Detect ARP flooding attacks"""
        self.arp_stats[src_mac] += 1
        
        if self.arp_stats[src_mac] > 50:
            self.log(f"ARP FLOOD DETECTED from {src_mac} ({self.arp_stats[src_mac]} requests)", "ATTACK")
            self.attack_detected = True
            self.arp_stats[src_mac] = 0
    
    # ========================================================================
    # Dashboard - Live Statistics Display
    # ========================================================================
    
    def dashboard(self):
        """Live terminal dashboard"""
        time.sleep(2)
        
        while self.running:
            time.sleep(5)
            
            print()
            click.secho("=" * 70, fg='cyan', bold=True)
            click.secho("VANTA CONTROLLER DASHBOARD (OpenFlow 1.3)".center(70), fg='cyan', bold=True)
            click.secho("=" * 70, fg='cyan', bold=True)
            
            # Status indicators with colors
            switch_count = len(self.switches)
            if switch_count > 0:
                click.secho(f"Active Switches      : ", nl=False, fg='white')
                click.secho(f"{switch_count}", fg='green', bold=True)
            else:
                click.secho(f"Active Switches      : ", nl=False, fg='white')
                click.secho(f"{switch_count}", fg='red', bold=True)
            
            click.secho(f"Total Packets        : ", nl=False, fg='white')
            click.secho(f"{self.total_packets}", fg='yellow', bold=True)
            
            click.secho(f"Flow Rules Installed : ", nl=False, fg='white')
            click.secho(f"{self.flow_count}", fg='green', bold=True)
            
            click.secho(f"Network Morphs       : ", nl=False, fg='white')
            click.secho(f"{self.morph_counter}", fg='magenta', bold=True)
            
            next_morph = int(self.morph_interval - (time.time() - self.last_morph_time))
            click.secho(f"Next Morph In        : ", nl=False, fg='white')
            if next_morph <= 3:
                click.secho(f"{next_morph}s", fg='red', bold=True)
            else:
                click.secho(f"{next_morph}s", fg='cyan')
            
            click.secho("-" * 70, fg='bright_black')
            click.secho("MAC Learning Table:", fg='yellow', bold=True)
            
            if not any(self.mac_to_port.values()):
                click.secho("  (empty)", fg='bright_black', dim=True)
            else:
                for dpid, mac_table in self.mac_to_port.items():
                    click.secho(f"  Switch {dpid:016x}:", fg='magenta')
                    for mac, port in mac_table.items():
                        click.secho(f"    {mac} ", nl=False, fg='white')
                        click.secho("→", nl=False, fg='bright_black')
                        click.secho(f" Port {port}", fg='green')
            
            click.secho("-" * 70, fg='bright_black')
            click.secho("Virtual IP Mappings:", fg='magenta', bold=True)
            
            if not self.real_to_virtual:
                click.secho("  (none)", fg='bright_black', dim=True)
            else:
                for real_ip, virtual_ip in self.real_to_virtual.items():
                    click.secho(f"  {real_ip} ", nl=False, fg='white')
                    click.secho("↔", nl=False, fg='bright_black')
                    click.secho(f" {virtual_ip}", fg='cyan')
            
            click.secho("=" * 70, fg='cyan', bold=True)
            print()
    
    def stop(self):
        """Gracefully stop the controller"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.log("Controller stopped", "SYS")


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    controller = VantaController(host='0.0.0.0', port=6633)
    
    try:
        controller.start()
    except KeyboardInterrupt:
        print("\n\nShutting down controller...")
        controller.stop()
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        controller.stop()