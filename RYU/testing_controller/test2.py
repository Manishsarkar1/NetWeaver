#!/usr/bin/env python3
import socket, struct, threading

OFP_VERSION = 0x04

OFPT_HELLO = 0
OFPT_ECHO_REQUEST = 2
OFPT_ECHO_REPLY = 3
OFPT_FEATURES_REQUEST = 5
OFPT_PACKET_IN = 10
OFPT_PACKET_OUT = 13
OFPT_FLOW_MOD = 14

OFPP_CONTROLLER = 0xfffffffd
OFPP_FLOOD = 0xfffffffb
OFPCML_NO_BUFFER = 0xffff
OFPFC_ADD = 0

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

class Controller:
    def __init__(self):
        self.mac = {}

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
                hdr = recv_exact(sock, 8)
                if not hdr:
                    break

                ver, mtype, length, xid = struct.unpack('!BBHI', hdr)
                body = recv_exact(sock, length - 8)

                if mtype == OFPT_ECHO_REQUEST:
                    sock.send(struct.pack('!BBHI', OFP_VERSION, OFPT_ECHO_REPLY, 8, xid))

                elif mtype == OFPT_PACKET_IN:
                    self.packet_in(sock, body)

        except Exception as e:
            print("[!] Error:", e)
        finally:
            sock.close()
            print("[-] Switch disconnected")

    def handshake(self, sock):
        sock.send(struct.pack('!BBHI', OFP_VERSION, OFPT_HELLO, 8, 0))
        recv_exact(sock, 8)

        sock.send(struct.pack('!BBHI', OFP_VERSION, OFPT_FEATURES_REQUEST, 8, 1))
        hdr = recv_exact(sock, 8)
        _, _, length, _ = struct.unpack('!BBHI', hdr)
        recv_exact(sock, length - 8)

        print("[OK] Handshake complete")

    def install_table_miss(self, sock):
        match = struct.pack('!HH', 1, 4)

        action = struct.pack('!HHIH', 0, 16, OFPP_CONTROLLER, OFPCML_NO_BUFFER)
        instr = struct.pack('!HH', 4, 8 + len(action)) + action

        length = 8 + 40 + len(match) + len(instr)

        flow = struct.pack(
            '!BBHIQQBBHHHIII',
            OFP_VERSION, OFPT_FLOW_MOD, length, 1,
            0, 0,
            0, OFPFC_ADD,
            0, 0, 0,
            0xffffffff, 0, 0
        ) + match + instr

        sock.send(flow)
        print("[OK] Table-miss installed")

    def packet_in(self, sock, data):
        buffer_id = struct.unpack('!I', data[0:4])[0]
        frame = data[-(len(data) - data.find(b'\xff\xff')):] if b'\xff\xff' in data else data[16:]

        dst = frame[0:6]
        src = frame[6:12]

        # brute-force in_port extraction (works for OVS)
        in_port = struct.unpack('!I', data[8:12])[0]

        self.mac[src] = in_port
        out = self.mac.get(dst, OFPP_FLOOD)

        self.packet_out(sock, buffer_id, in_port, out, frame)

    def packet_out(self, sock, buffer_id, in_port, out_port, frame):
        action = struct.pack('!HHIH', 0, 16, out_port, 0)
        length = 24 + len(action) + (0 if buffer_id != 0xffffffff else len(frame))

        msg = struct.pack(
            '!BBHI',
            OFP_VERSION, OFPT_PACKET_OUT, length, 0
        ) + struct.pack(
            '!IIH6x',
            buffer_id, in_port, len(action)
        ) + action

        if buffer_id == 0xffffffff:
            msg += frame

        sock.send(msg)

if __name__ == "__main__":
    Controller().start()
