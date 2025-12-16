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

# Flow commands
OFPFC_ADD = 0

class Controller:
    def __init__(self):
        self.mac_table = {}

    def start(self):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', 6633))
        s.listen(5)
        print("[*] OF1.3 Controller listening on 6633")

        while True:
            c, addr = s.accept()
            print(f"[+] Switch connected {addr}")
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    def handle(self, sock):
        try:
            self.handshake(sock)
            self.install_table_miss(sock)

            while True:
                hdr = sock.recv(8)
                if not hdr:
                    break

                ver, mtype, length, xid = struct.unpack('!BBHI', hdr)
                body = sock.recv(length - 8)

                if mtype == OFPT_PACKET_IN:
                    self.packet_in(sock, body)

        except Exception as e:
            print("[!] Error:", e)
        finally:
            sock.close()
            print("[-] Switch disconnected")

    def handshake(self, sock):
        sock.send(struct.pack('!BBHI', OFP_VERSION, OFPT_HELLO, 8, 0))
        sock.recv(8)
        sock.send(struct.pack('!BBHI', OFP_VERSION, OFPT_FEATURES_REQUEST, 8, 1))
        hdr = sock.recv(8)
        _, _, length, _ = struct.unpack('!BBHI', hdr)
        sock.recv(length - 8)
        print("[OK] Handshake complete")

    def install_table_miss(self, sock):
        # Match (empty)
        match = struct.pack('!HH', 1, 4)

        # Action: output to controller
        action = struct.pack('!HHIH', 0, 16, OFPP_CONTROLLER, OFPCML_NO_BUFFER)

        instruction = struct.pack('!HH', 4, 8 + len(action)) + action

        length = 8 + 40 + len(match) + len(instruction)

        flow_mod = struct.pack(
            '!BBHIQQBBHHHIII',
            OFP_VERSION,
            OFPT_FLOW_MOD,
            length,
            1,
            0, 0,        # cookie, mask
            0,           # table
            OFPFC_ADD,
            0, 0,        # idle, hard timeout
            0,           # priority
            0xffffffff,  # buffer_id
            0,           # out_port
            0            # out_group
        ) + match + instruction

        sock.send(flow_mod)
        print("[OK] Table-miss installed")

    def packet_in(self, sock, data):
        in_port = struct.unpack('!I', data[8:12])[0]
        eth = data[16:]
        dst = eth[0:6]
        src = eth[6:12]

        self.mac_table[src] = in_port

        if dst in self.mac_table:
            out_port = self.mac_table[dst]
            self.send_packet_out(sock, data, out_port)
        else:
            self.send_packet_out(sock, data, OFPP_FLOOD)

    def send_packet_out(self, sock, data, out_port):
        buffer_id = struct.unpack('!I', data[0:4])[0]
        in_port = struct.unpack('!I', data[8:12])[0]
        packet = data[16:]

        action = struct.pack('!HHIH', 0, 16, out_port, 0)

        length = 24 + len(action) + (0 if buffer_id != 0xffffffff else len(packet))

        msg = struct.pack(
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
            msg += packet

        sock.send(msg)

if __name__ == "__main__":
    Controller().start()
