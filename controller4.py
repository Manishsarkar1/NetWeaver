#!/usr/bin/env python3
import socket
import struct
import threading

OFPT_HELLO = 0
OFPT_ERROR = 1
OFPT_ECHO_REQUEST = 2
OFPT_ECHO_REPLY = 3
OFPT_FEATURES_REQUEST = 5
OFPT_FEATURES_REPLY = 6
OFPT_PACKET_IN = 10

def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def send_hello(sock):
    msg = struct.pack("!BBHI", 4, OFPT_HELLO, 8, 0)
    sock.sendall(msg)

def send_features_request(sock):
    msg = struct.pack("!BBHI", 4, OFPT_FEATURES_REQUEST, 8, 0)
    sock.sendall(msg)

def parse_header(header):
    version, msg_type, length, xid = struct.unpack("!BBHI", header)
    return version, msg_type, length, xid

def handle_switch(conn, addr):
    print(f"[+] Switch connected: {addr}")

    # Send initial HELLO
    send_hello(conn)

    while True:
        header = recv_exact(conn, 8)
        if not header:
            print("[-] Switch disconnected")
            return

        version, msg_type, length, xid = parse_header(header)
        body_len = length - 8

        body = recv_exact(conn, body_len) if body_len > 0 else b""

        if msg_type == OFPT_HELLO:
            print("[HELLO] Received HELLO")
            send_features_request(conn)

        elif msg_type == OFPT_FEATURES_REPLY:
            print("[FEATURES_REPLY] Received valid features reply")
            # Safe parsing of FEATURES_REPLY: minimum 24 bytes
            if len(body) >= 24:
                datapath_id = struct.unpack("!Q", body[:8])[0]
                print(f"Switch DPID: {datapath_id}")

        elif msg_type == OFPT_PACKET_IN:
            print("[PACKET_IN] Ignored")

        else:
            print(f"[INFO] Ignored message type {msg_type}")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 6633))
    server.listen(10)

    print("[SYSTEM] Controller listening on 0.0.0.0:6633")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_switch, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
