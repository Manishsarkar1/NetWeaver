#!/usr/bin/env python3

import socket
import struct
import threading

# OpenFlow 1.3
OFP_VERSION = 0x04

# Message types
OFPT_HELLO = 0
OFPT_FEATURES_REQUEST = 5
OFPT_FEATURES_REPLY = 6
OFPT_PACKET_IN = 10
OFPT_PACKET_OUT = 13
OFPT_FLOW_MOD = 14

# Ports
OFPP_CONTROLLER = 0xfffffffd
OFPP_FLOOD = 0xfffffffb
OFPCML_NO_BUFFER = 0xffff

# Flow mod commands
OFPFC_ADD = 0

class OF13Controller:
    def __init__(self):
        self.mac_table = {}
        self.running = True

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', 6633))
        sock.listen(5)

        print("[*] OpenFlow 1.3 Controller listening on 6633")

        while self.running:
            client, addr = sock.accept()
            print(f"[+] Switch connected from {addr}")
            threading.Thread(
                target=self.handle_switch,
                args=(client,),
                daemon=True
            ).start()

    def handle_switch(self, sock):
        try:
            self.handshake(sock)
            self.install_table_miss(sock)

            while True:
                header = sock.recv(8)
                if not header:
                    break

                version, msg_type, length, xid = struct.unpack('!BBHI', header)
                body = sock.recv(length - 8) if length > 8 else b''

                if msg_type == OFPT_PACKET_IN:
                    self.handle_packet_in(sock, body)

        except Exception as e:
            print("[!] Error:", e)
        finally:
            sock.close()
            print("[-] Switch disconnected")

    def handshake(self, sock):
        # Send HELLO
        sock.send(struct.pack('!BBHI', OFP_VERSION, OFPT_HELLO, 8, 0))

        # Receive HELLO
        sock.recv(8)

        # Send FEATURES_REQUEST
        sock.send(struct.pack('!BBHI', OFP_VERSION, OFPT_FEATURES_REQUEST, 8, 1))

        # Receive FEATURES_REPLY
        hdr = sock.recv(8)
        version, msg_type, length, xid = struct.unpack('!BBHI', hdr)
        sock.recv(length - 8)

        print("[OK] Handshake complete")

    def install_table_miss(self, sock):
        # Match = empty (match all)
        match = struct.pack('!HH', 1, 4)  # type=OXM, length=4

        # Action: output to controller
        action = struct.pack(
            '!HHIH',
            0, 16,
            OFPP_CONTROLLER,
            OFPCML_NO_BUFFER
        )

        # Instruction: apply actions
        instruction = struct.pack(
            '!HH',
            4, 8 + len(action)
        ) + action

        length = 48 + len(match) + len(instruction)

        flow_mod = struct.pack(
            '!BBHIQQHHHHL',
            OFP_VERSION,
            OFPT_FLOW_MOD,
            length,
            1,
            0,          # cookie
            0,          # cookie mask
            0,          # table_id
            OFPFC_ADD,
            0,          # idle timeout
            0,          # hard timeout
            0,          # priority
            0xffffffff  # buffer_id
        ) + match + instruction

        sock.send(flow_mod)
        print("[OK] Table-miss flow installed")

    def handle_packet_in(self, sock, data):
        in_port = struct.unpack('!I', data[8:12])[0]
        eth = data[16:]

        dst = eth[0:6]
        src = eth[6:12]

        self.mac_table[src] = in_port

        if dst in self.mac_table:
            out_port = self.mac_table[dst]
            self.install_flow(sock, src, dst, in_port, out_port)
            self.send_packet_out(sock, data, out_port)
        else:
            self.send_packet_out(sock, data, OFPP_FLOOD)

    def install_flow(self, sock, src, dst, in_port, out_port):
        # Match
        match = struct.pack('!HH', 1, 4)

        # OXM fields
        match += struct.pack(
            '!I6sI6sI4s',
            0x80001406, src,
            0x80001806, dst,
            0x80000c04, struct.pack('!I', in_port)
        )

        # Action
        action = struct.pack('!HHIH', 0, 16, out_port, 0)

        instruction = struct.pack('!HH', 4, 8 + len(action)) + action

        length = 48 + len(match) + len(instruction)

        flow_mod = struct.pack(
            '!BBHIQQHHHHL',
            OFP_VERSION,
            OFPT_FLOW_MOD,
            length,
            2,
            0, 0, 0,
            OFPFC_ADD,
            30, 0,
            100,
            0xffffffff
        ) + match + instruction

        sock.send(flow_mod)

    def send_packet_out(self, sock, data, out_port):
        buffer_id = struct.unpack('!I', data[0:4])[0]
        in_port = struct.unpack('!I', data[8:12])[0]
        packet = data[16:]

        action = struct.pack('!HHIH', 0, 16, out_port, 0)

        length = 24 + len(action) + (0 if buffer_id != 0xffffffff else len(packet))

        packet_out = struct.pack(
            '!BBHI',
            OFP_VERSION,
            OFPT_PACKET_OUT,
            length,
            0
        ) + struct.pack(
            '!IIH6x',
            buffer_id,
            in_port,
            len(action)
        ) + action

        if buffer_id == 0xffffffff:
            packet_out += packet

        sock.send(packet_out)

if __name__ == "__main__":
    OF13Controller().start()
