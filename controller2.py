#!/usr/bin/env python3
"""
VANTA SDN CONTROLLER - Network Morphing Defense System
A complete OpenFlow 1.0/1.3 SDN controller built from scratch
No frameworks - pure Python socket programming
"""

import socket
import struct
import threading
import time
import random
import select
from collections import defaultdict
from datetime import datetime

# ============================================================================
# PHASE 1: OpenFlow Protocol Constants & Message Structures
# ============================================================================

# OpenFlow versions
OFP_VERSION_1_0 = 0x01
OFP_VERSION_1_3 = 0x04

# OpenFlow message types
OFPT_HELLO = 0
OFPT_ERROR = 1
OFPT_ECHO_REQUEST = 2
OFPT_ECHO_REPLY = 3
OFPT_FEATURES_REQUEST = 5
OFPT_FEATURES_REPLY = 6
OFPT_GET_CONFIG_REQUEST = 7
OFPT_GET_CONFIG_REPLY = 8
OFPT_SET_CONFIG = 9
OFPT_PACKET_IN = 10
OFPT_FLOW_MOD = 14
OFPT_PACKET_OUT = 13

# Flow mod commands
OFPFC_ADD = 0
OFPFC_MODIFY = 1
OFPFC_DELETE = 2

# Packet out/in buffer
OFP_NO_BUFFER = 0xffffffff

# Port numbers
OFPP_FLOOD = 0xfffb
OFPP_CONTROLLER = 0xfffd

# Flow mod flags
OFPFF_SEND_FLOW_REM = 1 << 0

# Match wildcards (OpenFlow 1.0)
OFPFW_IN_PORT = 1 << 0
OFPFW_DL_SRC = 1 << 2
OFPFW_DL_DST = 1 << 3
OFPFW_DL_TYPE = 1 << 4
OFPFW_NW_PROTO = 1 << 5
OFPFW_NW_SRC_MASK = 0x3f << 8
OFPFW_NW_DST_MASK = 0x3f << 14

# Ethernet types
ETH_TYPE_IP = 0x0800
ETH_TYPE_ARP = 0x0806

# IP protocols
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

# Action types
OFPAT_OUTPUT = 0
OFPAT_SET_NW_SRC = 6  # Set source IP
OFPAT_SET_NW_DST = 7  # Set destination IP


# ============================================================================
# PHASE 1: Core Controller Class - TCP Server & OpenFlow Handshake
# ============================================================================

class VantaController:
    """
    Main SDN Controller implementing network morphing defense
    """
    
    def __init__(self, host='0.0.0.0', port=6633):
        self.host = host
        self.port = port
        self.server_socket = None
        self.switches = {}  # datapath_id -> socket
        self.running = False
        
        # PHASE 2: Learning switch tables
        self.mac_to_port = {}  # dpid -> {mac -> port}
        
        # PHASE 4: Network morphing state
        self.real_to_virtual = {}  # Real IP -> Virtual IP
        self.virtual_to_real = {}  # Virtual IP -> Real IP
        self.morph_counter = 0
        self.last_morph_time = time.time()
        self.morph_interval = 10  # seconds
        
        # PHASE 5: Attack detection
        self.packet_stats = defaultdict(lambda: defaultdict(int))  # src_ip -> {dst_port -> count}
        self.arp_stats = defaultdict(int)  # src_mac -> count
        self.attack_detected = False
        self.honeypot_ip = "10.0.0.99"
        
        # Flow tracking
        self.flow_count = 0
        self.total_packets = 0
        
        # Logging
        self.log_lock = threading.Lock()
        
    def log(self, message, level="INFO"):
        """Thread-safe logging with timestamps"""
        with self.log_lock:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"[{timestamp}] [{level}] {message}")
    
    def start(self):
        """Start the controller TCP server"""
        self.log("=" * 70, "SYS")
        self.log("VANTA SDN CONTROLLER - Network Morphing Defense System", "SYS")
        self.log("=" * 70, "SYS")
        
        # Create TCP socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        
        self.log(f"Controller listening on {self.host}:{self.port}", "SYS")
        
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
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    # ========================================================================
    # PHASE 1: OpenFlow Handshake Implementation
    # ========================================================================
    
    def openflow_handshake(self, sock):
        """
        Perform OpenFlow handshake with switch:
        1. Receive HELLO from switch
        2. Send HELLO reply
        3. Send FEATURES_REQUEST
        4. Receive FEATURES_REPLY
        5. Send SET_CONFIG
        """
        try:
            self.log(">>> Waiting for HELLO from switch...", "HAND")
            
            # Set timeout so we don't hang forever
            sock.settimeout(10.0)
            
            # Step 1: Receive HELLO
            header = self.recv_exact(sock, 8)
            if not header:
                self.log("!!! Failed to receive HELLO - connection closed", "ERROR")
                return None
            
            version, msg_type, length, xid = struct.unpack('!BBHI', header)
            
            self.log(f">>> Received message: type={msg_type}, length={length}, version={version}", "HAND")
            
            if msg_type != OFPT_HELLO:
                self.log(f"!!! Expected HELLO (0), got message type {msg_type}", "ERROR")
                return None
            
            self.log(f"✓ Received HELLO (OpenFlow v{version})", "HAND")
            
            # Step 2: Send HELLO reply (use version 1.0 for compatibility)
            hello_msg = struct.pack('!BBHI', OFP_VERSION_1_0, OFPT_HELLO, 8, 1)
            sock.send(hello_msg)
            self.log("✓ Sent HELLO reply", "HAND")
            
            # Step 3: Send FEATURES_REQUEST
            features_req = struct.pack('!BBHI', OFP_VERSION_1_0, OFPT_FEATURES_REQUEST, 8, 2)
            sock.send(features_req)
            self.log("✓ Sent FEATURES_REQUEST", "HAND")
            
            # Step 4: Receive FEATURES_REPLY
            self.log(">>> Waiting for FEATURES_REPLY...", "HAND")
            header = self.recv_exact(sock, 8)
            if not header:
                self.log("!!! Failed to receive FEATURES_REPLY - connection closed", "ERROR")
                return None
            
            version, msg_type, length, xid = struct.unpack('!BBHI', header)
            self.log(f">>> Received message: type={msg_type}, length={length}", "HAND")
            
            if msg_type != OFPT_FEATURES_REPLY:
                self.log(f"!!! Expected FEATURES_REPLY (6), got {msg_type}", "ERROR")
                return None
            
            body = self.recv_exact(sock, length - 8)
            if not body or len(body) < 24:
                self.log(f"!!! FEATURES_REPLY body too short: {len(body) if body else 0} bytes", "ERROR")
                return None
            
            # Extract datapath ID (switch unique identifier)
            dpid = struct.unpack('!Q', body[0:8])[0]
            self.log(f"✓ Switch DPID: {dpid:016x}", "HAND")
            
            # Step 5: Send SET_CONFIG (send full packets to controller)
            config_msg = struct.pack('!BBHIHH', 
                                    OFP_VERSION_1_0, OFPT_SET_CONFIG, 12, 3,
                                    0,  # flags
                                    0xffff)  # miss_send_len (send full packet)
            sock.send(config_msg)
            self.log("✓ Sent SET_CONFIG", "HAND")
            self.log(f"✓✓✓ HANDSHAKE COMPLETE - Switch {dpid:016x} ready! ✓✓✓", "HAND")
            
            return dpid
            
        except Exception as e:
            self.log(f"Handshake error: {e}", "ERROR")
            return None
    
    def handle_echo_request(self, sock, xid):
        """Respond to echo requests (keepalive)"""
        echo_reply = struct.pack('!BBHI', OFP_VERSION_1_0, OFPT_ECHO_REPLY, 8, xid)
        sock.send(echo_reply)
    
    # ========================================================================
    # PHASE 2: Packet-In Handler - Learning Switch Logic
    # ========================================================================
    
    def handle_packet_in(self, sock, dpid, body, xid):
        """
        Handle incoming packets from switch:
        1. Parse packet metadata and Ethernet frame
        2. Learn source MAC -> port mapping
        3. Determine output action based on destination MAC
        """
        try:
            self.total_packets += 1
            
            # Parse OpenFlow 1.0 Packet-In structure
            if len(body) < 18:
                return
            
            buffer_id, total_len, in_port, reason = struct.unpack('!IHBB', body[0:8])
            ethernet_frame = body[10:]  # Skip padding
            
            if len(ethernet_frame) < 14:
                return
            
            # Parse Ethernet header
            dst_mac = ethernet_frame[0:6]
            src_mac = ethernet_frame[6:12]
            eth_type = struct.unpack('!H', ethernet_frame[12:14])[0]
            
            dst_mac_str = ':'.join(f'{b:02x}' for b in dst_mac)
            src_mac_str = ':'.join(f'{b:02x}' for b in src_mac)
            
            # PHASE 2: Learn the source MAC address
            if src_mac_str not in self.mac_to_port[dpid]:
                self.mac_to_port[dpid][src_mac_str] = in_port
                self.log(f"Learned: {src_mac_str} -> Port {in_port}", "LEARN")
            
            # PHASE 5: Attack detection
            if eth_type == ETH_TYPE_ARP:
                self.detect_arp_flood(src_mac_str)
            elif eth_type == ETH_TYPE_IP and len(ethernet_frame) >= 34:
                self.detect_port_scan(ethernet_frame)
            
            # Determine output port
            out_port = self.mac_to_port[dpid].get(dst_mac_str)
            
            if out_port is not None:
                # PHASE 3: Destination known - install flow rule
                self.install_flow(sock, dpid, in_port, out_port, 
                                src_mac, dst_mac, eth_type, buffer_id, xid)
            else:
                # PHASE 3: Destination unknown - flood packet
                self.flood_packet(sock, in_port, buffer_id, ethernet_frame, xid)
                
        except Exception as e:
            self.log(f"Packet-In error: {e}", "ERROR")
    
    # ========================================================================
    # PHASE 3: Flow Control - Install Rules & Flood Packets
    # ========================================================================
    
    def install_flow(self, sock, dpid, in_port, out_port, src_mac, dst_mac, 
                    eth_type, buffer_id, xid):
        """
        Install a flow rule in the switch to forward packets
        without controller involvement
        """
        try:
            # Build match structure (OpenFlow 1.0)
            wildcards = (OFPFW_DL_TYPE | OFPFW_NW_PROTO)  # Match on src/dst MAC and in_port
            
            match = struct.pack('!IHHBBH',
                               wildcards,  # wildcards
                               in_port,    # in_port
                               0, 0, 0, 0)  # padding
            
            match += src_mac  # dl_src (6 bytes)
            match += dst_mac  # dl_dst (6 bytes)
            match += struct.pack('!H', eth_type)  # dl_type
            match += struct.pack('!8xIIHHI', 0, 0, 0, 0, 0)  # padding and other fields
            
            # Build action: OUTPUT to specific port
            action = struct.pack('!HHH', 
                                OFPAT_OUTPUT,  # type
                                8,            # len
                                out_port)     # port
            
            # Build FLOW_MOD message
            flow_mod = struct.pack('!BBHI', OFP_VERSION_1_0, OFPT_FLOW_MOD, 
                                  72 + len(action), xid)
            flow_mod += match  # 40 bytes
            flow_mod += struct.pack('!QHHIHBBH',
                                   0,  # cookie
                                   OFPFC_ADD,  # command
                                   10,  # idle_timeout
                                   30,  # hard_timeout
                                   100,  # priority
                                   buffer_id,  # buffer_id
                                   OFPP_FLOOD,  # out_port
                                   OFPFF_SEND_FLOW_REM,  # flags
                                   )
            flow_mod += action
            
            sock.send(flow_mod)
            self.flow_count += 1
            
            src_mac_str = ':'.join(f'{b:02x}' for b in src_mac)
            dst_mac_str = ':'.join(f'{b:02x}' for b in dst_mac)
            self.log(f"Flow installed: {src_mac_str} -> {dst_mac_str} via port {out_port}", "FLOW")
            
        except Exception as e:
            self.log(f"Flow install error: {e}", "ERROR")
    
    def flood_packet(self, sock, in_port, buffer_id, packet_data, xid):
        """
        Flood packet to all ports (except input port)
        Used when destination is unknown
        """
        try:
            # Build action: OUTPUT to FLOOD
            action = struct.pack('!HHH',
                                OFPAT_OUTPUT,
                                8,
                                OFPP_FLOOD)
            
            # Build PACKET_OUT message
            if buffer_id != OFP_NO_BUFFER:
                # Packet is buffered in switch
                packet_out = struct.pack('!BBHI', OFP_VERSION_1_0, OFPT_PACKET_OUT,
                                        8 + 8 + len(action), xid)
                packet_out += struct.pack('!IHH',
                                         buffer_id,
                                         in_port,
                                         len(action))
                packet_out += action
            else:
                # Send full packet
                packet_out = struct.pack('!BBHI', OFP_VERSION_1_0, OFPT_PACKET_OUT,
                                        8 + 8 + len(action) + len(packet_data), xid)
                packet_out += struct.pack('!IHH',
                                         OFP_NO_BUFFER,
                                         in_port,
                                         len(action))
                packet_out += action
                packet_out += packet_data
            
            sock.send(packet_out)
            self.log(f"Packet flooded from port {in_port}", "FLOOD")
            
        except Exception as e:
            self.log(f"Flood error: {e}", "ERROR")
    
    # ========================================================================
    # PHASE 4: Network Morphing - Virtual IP Management
    # ========================================================================
    
    def network_morpher(self):
        """
        Background thread that morphs the network topology
        by changing virtual IP addresses every N seconds
        """
        self.log("Network morpher started", "MORPH")
        
        while self.running:
            time.sleep(1)
            
            # Check if it's time to morph or if attack detected
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
        self.log("=" * 70, "MORPH")
        self.log(f"NETWORK MORPH #{self.morph_counter} - Reconfiguring topology", "MORPH")
        
        # Generate new virtual IPs for known hosts
        # In a real scenario, these would be hosts discovered via ARP/DHCP
        real_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        
        old_mappings = self.real_to_virtual.copy()
        self.real_to_virtual.clear()
        self.virtual_to_real.clear()
        
        for real_ip in real_ips:
            # Generate random virtual IP in 192.168.x.x range
            virtual_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            self.real_to_virtual[real_ip] = virtual_ip
            self.virtual_to_real[virtual_ip] = real_ip
            
            old_vip = old_mappings.get(real_ip, "none")
            self.log(f"  {real_ip} -> {virtual_ip} (was {old_vip})", "MORPH")
        
        # In production, we'd push flow rules to rewrite packet headers
        # For now, we log the topology change
        self.log(f"Morph complete - {len(self.real_to_virtual)} hosts remapped", "MORPH")
        self.log("=" * 70, "MORPH")
    
    # ========================================================================
    # PHASE 5: Attack Detection
    # ========================================================================
    
    def detect_port_scan(self, ethernet_frame):
        """
        Detect port scanning behavior:
        - Many different destination ports from same source
        """
        try:
            if len(ethernet_frame) < 34:
                return
            
            # Extract IP header
            ip_header = ethernet_frame[14:34]
            src_ip = socket.inet_ntoa(ip_header[12:16])
            dst_ip = socket.inet_ntoa(ip_header[16:20])
            protocol = ip_header[9]
            
            # Check TCP/UDP
            if protocol in [IP_PROTO_TCP, IP_PROTO_UDP] and len(ethernet_frame) >= 38:
                # Extract destination port
                dst_port = struct.unpack('!H', ethernet_frame[36:38])[0]
                
                # Track port access patterns
                self.packet_stats[src_ip][dst_port] += 1
                
                # Trigger if accessing many different ports
                if len(self.packet_stats[src_ip]) > 10:
                    self.log(f"PORT SCAN DETECTED from {src_ip} ({len(self.packet_stats[src_ip])} ports)", "ATTACK")
                    self.attack_detected = True
                    self.packet_stats[src_ip].clear()
                    
        except Exception as e:
            pass  # Silently ignore parsing errors
    
    def detect_arp_flood(self, src_mac):
        """
        Detect ARP flooding attacks
        """
        self.arp_stats[src_mac] += 1
        
        # Trigger if too many ARPs from same source
        if self.arp_stats[src_mac] > 50:
            self.log(f"ARP FLOOD DETECTED from {src_mac} ({self.arp_stats[src_mac]} requests)", "ATTACK")
            self.attack_detected = True
            self.arp_stats[src_mac] = 0
    
    # ========================================================================
    # PHASE 6: Dashboard - Live Statistics Display
    # ========================================================================
    
    def dashboard(self):
        """
        Live terminal dashboard showing controller statistics
        """
        time.sleep(2)  # Let controller initialize
        
        while self.running:
            time.sleep(5)
            
            print("\n" + "=" * 70)
            print("VANTA CONTROLLER DASHBOARD".center(70))
            print("=" * 70)
            print(f"Active Switches      : {len(self.switches)}")
            print(f"Total Packets        : {self.total_packets}")
            print(f"Flow Rules Installed : {self.flow_count}")
            print(f"Network Morphs       : {self.morph_counter}")
            print(f"Next Morph In        : {int(self.morph_interval - (time.time() - self.last_morph_time))}s")
            print("-" * 70)
            print("MAC Learning Table:")
            for dpid, mac_table in self.mac_to_port.items():
                print(f"  Switch {dpid:016x}:")
                for mac, port in mac_table.items():
                    print(f"    {mac} -> Port {port}")
            print("-" * 70)
            print("Virtual IP Mappings:")
            for real_ip, virtual_ip in self.real_to_virtual.items():
                print(f"  {real_ip} <-> {virtual_ip}")
            print("=" * 70 + "\n")
    
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
        controller.stop()