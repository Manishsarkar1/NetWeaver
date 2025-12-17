#!/usr/bin/env python3
"""
MINIMAL WORKING OPENFLOW CONTROLLER
Tests basic connectivity - if this works, we can add MTD features
"""

import socket
import struct
import threading
import time

# OpenFlow 1.0 (simpler, more compatible)
OFP_VERSION = 0x01

# Message types
OFPT_HELLO = 0
OFPT_ECHO_REQUEST = 2
OFPT_ECHO_REPLY = 3
OFPT_FEATURES_REQUEST = 5
OFPT_PACKET_IN = 10
OFPT_PACKET_OUT = 13

# Constants
OFPP_FLOOD = 0xfffb

class SimpleController:
    def __init__(self):
        self.running = False
        self.switches = {}
        self.mac_to_port = {}  # MAC learning table
        
    def start(self):
        print("=" * 60)
        print("SIMPLE OPENFLOW CONTROLLER - Testing Connectivity")
        print("=" * 60)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', 6633))
        sock.listen(5)
        self.running = True
        
        print(f"[OK] Listening on 0.0.0.0:6633")
        print("[OK] Waiting for switches...\n")
        
        while self.running:
            try:
                client, addr = sock.accept()
                print(f"[CONN] New connection from {addr}")
                threading.Thread(target=self.handle_switch, args=(client, addr), daemon=True).start()
            except KeyboardInterrupt:
                break
    
    def handle_switch(self, sock, addr):
        try:
            # Simple handshake
            if not self.handshake(sock):
                print(f"[ERROR] Handshake failed with {addr}")
                sock.close()
                return
            
            print(f"[SUCCESS] Switch connected from {addr}")
            self.switches[addr] = sock
            self.mac_to_port[addr] = {}  # Per-switch MAC table
            
            # Handle messages
            while self.running:
                try:
                    # Read header
                    header = sock.recv(8)
                    if not header or len(header) < 8:
                        break
                    
                    version, msg_type, length, xid = struct.unpack('!BBHI', header)
                    
                    # Read body
                    if length > 8:
                        body = sock.recv(length - 8)
                    else:
                        body = b''
                    
                    # Handle messages
                    if msg_type == OFPT_ECHO_REQUEST:
                        # Reply to keepalive
                        reply = struct.pack('!BBHI', OFP_VERSION, OFPT_ECHO_REPLY, 8, xid)
                        sock.send(reply)
                        
                    elif msg_type == OFPT_PACKET_IN:
                        # Learn and forward
                        self.handle_packet_in(sock, addr, body, xid)
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[ERROR] Message handling: {e}")
                    break
                    
        except Exception as e:
            print(f"[ERROR] Switch handler: {e}")
        finally:
            if addr in self.switches:
                del self.switches[addr]
            sock.close()
            print(f"[DISC] Switch {addr} disconnected")
    
    def handshake(self, sock):
        """Perform OpenFlow handshake"""
        try:
            sock.settimeout(5.0)
            
            # Send HELLO
            hello = struct.pack('!BBHI', OFP_VERSION, OFPT_HELLO, 8, 0)
            sock.send(hello)
            print("  [>] Sent HELLO")
            
            # Receive HELLO
            data = sock.recv(8)
            if not data or len(data) < 8:
                print("  [X] No HELLO received")
                return False
            
            version, msg_type, length, xid = struct.unpack('!BBHI', data)
            
            if msg_type != OFPT_HELLO:
                print(f"  [X] Expected HELLO, got type {msg_type}")
                return False
            
            print(f"  [<] Received HELLO (OpenFlow {version})")
            
            # Send SET_CONFIG (OpenFlow 1.0 format)
            # struct ofp_switch_config: flags (16 bits), miss_send_len (16 bits)
            set_config = struct.pack('!BBHI',
                                    OFP_VERSION,           # version = 1
                                    9,                     # type = OFPT_SET_CONFIG
                                    12,                    # length = 8 (header) + 4 (body)
                                    2)                     # xid
            set_config += struct.pack('!HH',
                                     0,                    # flags = 0
                                     0xffff)               # miss_send_len = 65535
            sock.send(set_config)
            print(f"  [>] Sent SET_CONFIG (miss_send_len=65535)")
            
            # Small delay
            time.sleep(0.05)
            
            # Send FEATURES_REQUEST
            feat_req = struct.pack('!BBHI', OFP_VERSION, OFPT_FEATURES_REQUEST, 8, 1)
            sock.send(feat_req)
            print("  [>] Sent FEATURES_REQUEST")
            
            # Receive FEATURES_REPLY
            header = sock.recv(8)
            if not header:
                return False
            
            version, msg_type, length, xid = struct.unpack('!BBHI', header)
            body = sock.recv(length - 8) if length > 8 else b''
            
            print(f"  [<] Received FEATURES_REPLY (length={length})")
            
            # Extract DPID
            if len(body) >= 8:
                dpid = struct.unpack('!Q', body[0:8])[0]
                print(f"  [OK] Switch DPID: {dpid:016x}")
            
            sock.settimeout(None)
            return True
            
        except Exception as e:
            print(f"  [X] Handshake error: {e}")
            return False
    
    def handle_packet_in(self, sock, switch_addr, packet_in_body, xid):
        """Learn MAC addresses and forward intelligently"""
        try:
            # Parse PACKET_IN (OpenFlow 1.0 format)
            if len(packet_in_body) < 20:
                print(f"[ERROR] Packet-in too short: {len(packet_in_body)} bytes")
                return
            
            buffer_id = struct.unpack('!I', packet_in_body[0:4])[0]
            total_len = struct.unpack('!H', packet_in_body[4:6])[0]
            in_port = struct.unpack('!H', packet_in_body[6:8])[0]
            reason = struct.unpack('!B', packet_in_body[8:9])[0]
            
            # Ethernet frame starts at offset 10 (after 2 bytes padding)
            eth_frame = packet_in_body[10:]
            
            if len(eth_frame) < 14:
                print(f"[ERROR] Ethernet frame too short: {len(eth_frame)} bytes")
                return
            
            # Parse Ethernet header (first 14 bytes)
            dst_mac = ':'.join(f'{b:02x}' for b in eth_frame[0:6])    # Bytes 0-5: Destination MAC
            src_mac = ':'.join(f'{b:02x}' for b in eth_frame[6:12])   # Bytes 6-11: Source MAC
            eth_type = struct.unpack('!H', eth_frame[12:14])[0]       # Bytes 12-13: EtherType
            
            # Debug: Show first 20 bytes of packet
            if eth_type == 0x0806 or eth_type == 0x0800:  # ARP or IP
                print(f"[DEBUG] First 20 bytes: {eth_frame[:20].hex()}")
            
            # Learn source MAC
            if src_mac not in self.mac_to_port[switch_addr]:
                self.mac_to_port[switch_addr][src_mac] = in_port
                print(f"[LEARN] {src_mac} is on port {in_port} (EtherType: 0x{eth_type:04x})")
            
            # Determine output port
            if dst_mac in self.mac_to_port[switch_addr]:
                out_port = self.mac_to_port[switch_addr][dst_mac]
                print(f"[FORWARD] {src_mac} -> {dst_mac} via port {out_port}")
                self.send_packet_out(sock, buffer_id, in_port, out_port, eth_frame, xid)
            else:
                # Only log non-broadcast floods
                if dst_mac != "ff:ff:ff:ff:ff:ff":
                    print(f"[FLOOD] Unknown destination {dst_mac}")
                else:
                    print(f"[FLOOD-BCAST] Broadcasting from port {in_port}")
                self.send_packet_out(sock, buffer_id, in_port, OFPP_FLOOD, eth_frame, xid)
                
        except Exception as e:
            print(f"[ERROR] Packet-in handling: {e}")
            import traceback
            traceback.print_exc()
    
    def send_packet_out(self, sock, buffer_id, in_port, out_port, eth_frame, xid):
        """Send PACKET_OUT message"""
        try:
            # Action: OUTPUT to port
            action = struct.pack('!HHH', 0, 8, out_port)  # type=OUTPUT, len=8, port
            
            if buffer_id != 0xffffffff:
                # Packet is buffered in switch
                packet_out = struct.pack('!BBHI', OFP_VERSION, OFPT_PACKET_OUT,
                                        8 + 8 + len(action), xid)
                packet_out += struct.pack('!IHH', buffer_id, in_port, len(action))
                packet_out += action
                print(f"[SEND] Using buffered packet {buffer_id}, out_port={out_port}")
            else:
                # Send full packet
                packet_out = struct.pack('!BBHI', OFP_VERSION, OFPT_PACKET_OUT,
                                        8 + 8 + len(action) + len(eth_frame), xid)
                packet_out += struct.pack('!IHH', 0xffffffff, in_port, len(action))
                packet_out += action
                packet_out += eth_frame
                print(f"[SEND] Sending full packet ({len(eth_frame)} bytes), out_port={out_port}")
            
            sock.send(packet_out)
            
        except Exception as e:
            print(f"[ERROR] Send packet out: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    controller = SimpleController()
    try:
        controller.start()
    except KeyboardInterrupt:
        print("\n\n[EXIT] Controller stopped")
        controller.running = False