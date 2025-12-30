#!/usr/bin/env python3
# controller_fixed.py
# From-scratch OpenFlow 1.3 controller (no frameworks).
# Works with Mininet/OVS; uses MAC-based learning, short-lived flows for IP churn.

import asyncio
import struct
import time
from collections import defaultdict

OF_VERSION = 0x04           # OpenFlow 1.3
OFP_TCP_PORT = 6653

# Message types
OFPT_HELLO = 0
OFPT_ERROR = 1
OFPT_ECHO_REQUEST = 2
OFPT_ECHO_REPLY = 3
OFPT_FEATURES_REQUEST = 5
OFPT_FEATURES_REPLY = 6
OFPT_SET_CONFIG = 9
OFPT_PACKET_IN = 10
OFPT_PORT_STATUS = 12
OFPT_PACKET_OUT = 13
OFPT_FLOW_MOD = 14

# FlowMod commands
OFPFC_ADD = 0

# OXM (match fields)
OXM_CLASS_OPENFLOW_BASIC = 0x8000
OXM_OF_IN_PORT = 0x00
OXM_OF_ETH_DST = 0x03
OXM_OF_ETH_SRC = 0x04

# Instruction/Action types
OFPIT_APPLY_ACTIONS = 4
OFPAT_OUTPUT = 0

# Special ports (OpenFlow 1.3)
OFPP_MAX = 0xFFFF
OFPP_IN_PORT = OFPP_MAX - 1       # 0xFFFE
OFPP_TABLE = OFPP_MAX - 2         # 0xFFFD
OFPP_NORMAL = OFPP_MAX - 3        # 0xFFFC
OFPP_FLOOD = OFPP_MAX - 4         # 0xFFFB
OFPP_ALL = OFPP_MAX - 5           # 0xFFFA
OFPP_CONTROLLER = OFPP_MAX - 6    # 0xFFF9
OFPP_LOCAL = OFPP_MAX - 15        # 0xFFF0
OFPP_NONE = 0xFFFFFFFF

# Config
MISS_SEND_LEN = 0xFFFF
DEFAULT_IDLE_TIMEOUT = 30
DEFAULT_HARD_TIMEOUT = 0
DEFAULT_PRIORITY_LEARNED = 10
TABLE_MISS_PRIORITY = 0

def of_header(msg_type: int, payload_len: int, xid: int = 0) -> bytes:
    return struct.pack("!BBHI", OF_VERSION, msg_type, 8 + payload_len, xid)

def pack_hello() -> bytes:
    return of_header(OFPT_HELLO, 0)

def pack_echo_reply(payload: bytes) -> bytes:
    return of_header(OFPT_ECHO_REPLY, len(payload)) + payload

def pack_features_request() -> bytes:
    return of_header(OFPT_FEATURES_REQUEST, 0)

def pack_set_config(miss_len: int = MISS_SEND_LEN, flags: int = 0) -> bytes:
    payload = struct.pack("!HH", flags, miss_len)
    return of_header(OFPT_SET_CONFIG, len(payload)) + payload

def pack_output_action(port: int, max_len: int = 0) -> bytes:
    # ofp_action_output: type(2)=0, len(2)=16, port(4), max_len(2), pad(6)
    return struct.pack("!HHIH6x", OFPAT_OUTPUT, 16, port, max_len)

def pack_instruction_apply_actions(actions: bytes) -> bytes:
    length = 4 + len(actions)
    return struct.pack("!HH", OFPIT_APPLY_ACTIONS, length) + actions

def oxm_field(class_: int, field: int, hasmask: int, length: int) -> int:
    return (class_ << 16) | (field << 9) | (hasmask << 8) | length

def pack_oxm_in_port(port: int) -> bytes:
    return struct.pack("!II", oxm_field(OXM_CLASS_OPENFLOW_BASIC, OXM_OF_IN_PORT, 0, 4), port)

def pack_oxm_eth_src(mac: bytes) -> bytes:
    return struct.pack("!I6s", oxm_field(OXM_CLASS_OPENFLOW_BASIC, OXM_OF_ETH_SRC, 0, 6), mac)

def pack_oxm_eth_dst(mac: bytes) -> bytes:
    return struct.pack("!I6s", oxm_field(OXM_CLASS_OPENFLOW_BASIC, OXM_OF_ETH_DST, 0, 6), mac)

def pack_match(oxms: bytes) -> bytes:
    # ofp_match: type=1 (OXM), length=4+len(oxms), padded to 8
    mtype = 1
    length = 4 + len(oxms)
    pad_len = (8 - (length % 8)) % 8
    return struct.pack("!HH", mtype, length) + oxms + (b"\x00" * pad_len)

def pack_flow_mod_add(match: bytes, instructions: bytes,
                      priority: int = DEFAULT_PRIORITY_LEARNED,
                      idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
                      hard_timeout: int = DEFAULT_HARD_TIMEOUT) -> bytes:
    cookie = 0
    cookie_mask = 0
    table_id = 0
    command = OFPFC_ADD
    buffer_id = 0xFFFFFFFF
    out_port = 0xFFFFFFFF
    out_group = 0xFFFFFFFF
    flags = 0  # optionally send_flow_removed(1<<0)

    fm_fixed = struct.pack("!QQBBHHHIIIIHH",
                           cookie, cookie_mask, table_id, command,
                           idle_timeout, hard_timeout, priority,
                           buffer_id, out_port, out_group, flags, 0)
    payload = fm_fixed + match + instructions
    return of_header(OFPT_FLOW_MOD, len(payload)) + payload

def pack_table_miss_to_controller() -> bytes:
    match = pack_match(b"")
    actions = pack_output_action(OFPP_CONTROLLER, MISS_SEND_LEN)
    inst = pack_instruction_apply_actions(actions)
    return pack_flow_mod_add(match, inst, priority=TABLE_MISS_PRIORITY, idle_timeout=0, hard_timeout=0)

def pack_packet_out(buffer_id: int, in_port: int, out_port: int, data: bytes = b"") -> bytes:
    # ofp_packet_out: buffer_id(4) in_port(4) actions_len(2) pad(6) actions data
    actions = pack_output_action(out_port, 0)
    actions_len = len(actions)
    header = struct.pack("!IIH6x", buffer_id, in_port, actions_len)
    payload = header + actions + (data if buffer_id == 0xFFFFFFFF else b"")
    return of_header(OFPT_PACKET_OUT, len(payload)) + payload

def format_mac(mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac)

class DatapathState:
    def __init__(self, dpid: int):
        self.dpid = dpid
        self.mac_to_port = {}  # mac(bytes) -> port(int)
        self.port_last_seen = defaultdict(lambda: 0.0)
        self.connected_at = time.time()

    def learn(self, mac: bytes, in_port: int):
        self.mac_to_port[mac] = in_port
        self.port_last_seen[in_port] = time.time()

    def lookup(self, mac: bytes):
        return self.mac_to_port.get(mac)

class OFConnection(asyncio.Protocol):
    def __init__(self, controller):
        self.controller = controller
        self.transport = None
        self.buffer = b""
        self.dpid = None
        self.dp = None

    def connection_made(self, transport):
        self.transport = transport
        peer = transport.get_extra_info("peername")
        print(f"[+] New switch connection from {peer}")
        self.send(pack_hello())

    def connection_lost(self, exc):
        print(f"[-] Switch disconnected (dpid={self.dpid})")
        if self.dpid in self.controller.datapaths:
            del self.controller.datapaths[self.dpid]

    def send(self, msg: bytes):
        if self.transport:
            self.transport.write(msg)

    def data_received(self, data):
        self.buffer += data
        while True:
            if len(self.buffer) < 8:
                return
            version, msg_type, length, xid = struct.unpack("!BBHI", self.buffer[:8])
            if len(self.buffer) < length:
                return
            payload = self.buffer[8:length]
            self.buffer = self.buffer[length:]
            if version != OF_VERSION:
                print(f"[!] Unexpected OF version {version}, expected {OF_VERSION}")
                continue
            self.handle_message(msg_type, payload)

    def handle_message(self, msg_type: int, payload: bytes):
        if msg_type == OFPT_HELLO:
            self.send(pack_features_request())
            return

        if msg_type == OFPT_ECHO_REQUEST:
            self.send(pack_echo_reply(payload))
            return

        if msg_type == OFPT_FEATURES_REPLY:
            self.handle_features_reply(payload)
            return

        if msg_type == OFPT_PACKET_IN:
            self.handle_packet_in(payload)
            return

        if msg_type == OFPT_ERROR:
            print(f"[!] OFPT_ERROR (len={len(payload)})")
            return

        if msg_type == OFPT_PORT_STATUS:
            return

    def handle_features_reply(self, payload: bytes):
        # ofp_switch_features (1.3): 24 bytes header before port list
        if len(payload) < 24:
            print(f"[!] Malformed FEATURES_REPLY, length={len(payload)} raw={payload.hex()}")
            return
        dpid = struct.unpack("!Q", payload[0:8])[0]
        n_buffers = struct.unpack("!I", payload[8:12])[0]
        n_tables = payload[12]
        aux_id = payload[13]
        self.dpid = dpid
        self.dp = DatapathState(dpid)
        self.controller.datapaths[dpid] = self.dp
        print(f"[+] Features reply: dpid=0x{dpid:016x} buffers={n_buffers} tables={n_tables} aux={aux_id}")
        # Configure controller receive length and install table-miss
        self.send(pack_set_config(MISS_SEND_LEN, 0))
        self.send(pack_table_miss_to_controller())

    def handle_packet_in(self, payload: bytes):
        # ofp_packet_in (1.3):
        # 0..4:  buffer_id (I)
        # 4..6:  total_len (H)
        # 6:     reason (B)
        # 7:     table_id (B)
        # 8..16: cookie (Q)
        # 16..:  ofp_match (type,len + OXM TLVs), padded to 8, then 2 bytes pad, then data
        if len(payload) < 20:
            return

        buffer_id = struct.unpack("!I", payload[0:4])[0]
        total_len = struct.unpack("!H", payload[4:6])[0]
        reason = payload[6]
        table_id = payload[7]
        cookie = struct.unpack("!Q", payload[8:16])[0]

        mtype, mlen = struct.unpack("!HH", payload[16:20])
        if mtype != 1 or len(payload) < 20 + mlen:
            return
        match_bytes = payload[20:20 + mlen]

        # match padding to 8, then 2 bytes pad, then data
        pad_match_len = (8 - ((4 + len(match_bytes)) % 8)) % 8
        data_idx = 20 + mlen + pad_match_len + 2
        if len(payload) < data_idx:
            return
        frame = payload[data_idx:]

        # Extract IN_PORT from OXM TLVs
        in_port = None
        mbuf = match_bytes[4:]  # skip inner ofp_match header (type,len)
        i = 0
        while i + 4 <= len(mbuf):
            oxm_header = struct.unpack("!I", mbuf[i:i+4])[0]
            i += 4
            oxm_class = (oxm_header >> 16) & 0xFFFF
            field = (oxm_header >> 9) & 0x7F
            hasmask = (oxm_header >> 8) & 0x1
            length = oxm_header & 0xFF
            if i + length > len(mbuf):
                break
            value = mbuf[i:i+length]
            i += length
            if oxm_class == OXM_CLASS_OPENFLOW_BASIC and field == OXM_OF_IN_PORT and hasmask == 0 and length == 4:
                in_port = struct.unpack("!I", value)[0]
        if in_port is None:
            in_port = 0

        # Parse Ethernet header
        if len(frame) >= 14:
            dst = frame[0:6]
            src = frame[6:12]
            eth_type = struct.unpack("!H", frame[12:14])[0]
        else:
            dst = b"\x00" * 6
            src = b"\x00" * 6
            eth_type = 0

        if not self.dp:
            return

        # Learn source MAC
        self.dp.learn(src, in_port)

        # Forwarding decision
        out_port = self.dp.lookup(dst)
        mac_str = f"{format_mac(src)} -> {format_mac(dst)}"

        if out_port is None:
            print(f"[~] FLOOD (dpid=0x{self.dpid:016x}, in={in_port}): {mac_str}")
            # Forward current packet via PacketOut if we own the data
            self.send(pack_packet_out(buffer_id, in_port, OFPP_FLOOD, frame if buffer_id == 0xFFFFFFFF else b""))
        else:
            if out_port == in_port:
                return
            # Install MAC-based flows (short-lived for IP churn resilience)
            self.install_mac_flow(src, dst, out_port)
            self.install_mac_flow(dst, src, in_port)
            print(f"[>] FORWARD (dpid=0x{self.dpid:016x}, in={in_port} -> out={out_port}): {mac_str}")
            # Forward the triggering packet immediately
            self.send(pack_packet_out(buffer_id, in_port, out_port, frame if buffer_id == 0xFFFFFFFF else b""))

    def install_mac_flow(self, src: bytes, dst: bytes, out_port: int):
        oxms = pack_oxm_eth_src(src) + pack_oxm_eth_dst(dst)
        match = pack_match(oxms)
        actions = pack_output_action(out_port, 0)
        inst = pack_instruction_apply_actions(actions)
        fm = pack_flow_mod_add(
            match, inst,
            priority=DEFAULT_PRIORITY_LEARNED,
            idle_timeout=DEFAULT_IDLE_TIMEOUT,
            hard_timeout=DEFAULT_HARD_TIMEOUT
        )
        self.send(fm)
        print(f"[+] Flow add dpid=0x{self.dpid:016x} src={format_mac(src)} dst={format_mac(dst)} out={out_port} idle={DEFAULT_IDLE_TIMEOUT}s")

class MinimalController:
    def __init__(self):
        self.datapaths = {}

    async def start(self, host="0.0.0.0", port=OFP_TCP_PORT):
        loop = asyncio.get_running_loop()
        server = await loop.create_server(lambda: OFConnection(self), host, port)
        addr = server.sockets[0].getsockname()
        print(f"[+] Controller listening on {addr}")
        try:
            await server.serve_forever()
        except asyncio.CancelledError:
            pass

def main():
    asyncio.run(MinimalController().start())

if __name__ == "__main__":
    main()
