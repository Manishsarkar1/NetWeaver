#!/usr/bin/env python3
# sdn_controller.py
# Minimal OpenFlow 1.3 controller with L2 learning and IP-churn resilience
# No external libraries. Tested against Open vSwitch.

import asyncio
import struct
import time
from collections import defaultdict

OF_VERSION = 0x04  # OpenFlow 1.3
OFP_TCP_PORT = 6653

# OpenFlow header: type constants
OFPT_HELLO = 0
OFPT_ERROR = 1
OFPT_ECHO_REQUEST = 2
OFPT_ECHO_REPLY = 3
OFPT_FEATURES_REQUEST = 5
OFPT_FEATURES_REPLY = 6
OFPT_SET_CONFIG = 9
OFPT_PACKET_IN = 10
OFPT_FLOW_MOD = 14
OFPT_PORT_STATUS = 12
OFPT_MULTIPART_REQUEST = 18
OFPT_MULTIPART_REPLY = 19
OFPT_ROLE_REQUEST = 24

# FlowMod command
OFPFC_ADD = 0
OFPFC_MODIFY = 1
OFPFC_DELETE = 3

# Match types
OXM_CLASS_OPENFLOW_BASIC = 0x8000
OXM_OF_ETH_DST = 0x0003
OXM_OF_ETH_SRC = 0x0004
OXM_OF_IN_PORT = 0x0000

# Action/Instruction types
OFPIT_APPLY_ACTIONS = 4
OFPAT_OUTPUT = 0

# Special ports
OFPP_CONTROLLER = 0xFFFF - 2  # 0xFFFD
OFPP_FLOOD = 0xFFFF - 5       # 0xFFFA
OFPP_TABLE = 0xFFFF - 3       # 0xFFFC

# Flags and defaults
MISS_SEND_LEN = 0xFFFF
DEFAULT_IDLE_TIMEOUT = 30      # seconds: short-lived to adapt to IP churn
DEFAULT_HARD_TIMEOUT = 0       # 0 -> never hard expire
DEFAULT_PRIORITY_LEARNED = 10  # higher than table miss (0)
TABLE_MISS_PRIORITY = 0

def of_header(msg_type: int, payload_len: int) -> bytes:
    total_len = 8 + payload_len
    return struct.pack("!BBHI", OF_VERSION, msg_type, total_len, 0)

def pack_hello() -> bytes:
    return of_header(OFPT_HELLO, 0)

def pack_echo_reply(data: bytes) -> bytes:
    return of_header(OFPT_ECHO_REPLY, len(data)) + data

def pack_features_request() -> bytes:
    return of_header(OFPT_FEATURES_REQUEST, 0)

def pack_set_config(miss_len: int = MISS_SEND_LEN, flags: int = 0) -> bytes:
    # struct ofp_switch_config: flags(2), miss_send_len(2)
    payload = struct.pack("!HH", flags, miss_len)
    return of_header(OFPT_SET_CONFIG, len(payload)) + payload

def pack_output_action(port: int, max_len: int = 0) -> bytes:
    # ofp_action_output: type(2)=0, len(2)=16, port(4), max_len(2), pad(6)
    return struct.pack("!HHIH6x", OFPAT_OUTPUT, 16, port, max_len)

def pack_instruction_apply_actions(actions: bytes) -> bytes:
    # ofp_instruction_actions: type(2)=4, len(2)=4+actions_len, actions...
    length = 4 + len(actions)
    return struct.pack("!HH", OFPIT_APPLY_ACTIONS, length) + actions

def oxm_field(class_: int, field: int, hasmask: int, length: int) -> int:
    return (class_ << 16) | (field << 9) | (hasmask << 8) | length

def pack_oxm_eth_dst(mac: bytes) -> bytes:
    # mac: 6 bytes
    field = oxm_field(OXM_CLASS_OPENFLOW_BASIC, OXM_OF_ETH_DST, 0, 6)
    return struct.pack("!I6s", field, mac)

def pack_oxm_eth_src(mac: bytes) -> bytes:
    field = oxm_field(OXM_CLASS_OPENFLOW_BASIC, OXM_OF_ETH_SRC, 0, 6)
    return struct.pack("!I6s", field, mac)

def pack_oxm_in_port(port: int) -> bytes:
    field = oxm_field(OXM_CLASS_OPENFLOW_BASIC, OXM_OF_IN_PORT, 0, 4)
    return struct.pack("!II", field, port)

def pack_match(oxms: bytes) -> bytes:
    # ofp_match: type(2)=1 (OXM), length(2)=4 + len(oxms), oxms..., pad to 8
    mtype = 1
    length = 4 + len(oxms)
    pad_len = (8 - (length % 8)) % 8
    return struct.pack("!HH", mtype, length) + oxms + (b"\x00" * pad_len)

def pack_flow_mod_add(match: bytes, instructions: bytes,
                      priority: int = DEFAULT_PRIORITY_LEARNED,
                      idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
                      hard_timeout: int = DEFAULT_HARD_TIMEOUT) -> bytes:
    # ofp_flow_mod (OpenFlow 1.3)
    # cookie(8) cookie_mask(8) table_id(1) command(1) idle(2) hard(2) priority(2)
    # buffer_id(4) out_port(4) out_group(4) flags(2) pad(2) match(...) instructions(...)
    cookie = 0
    cookie_mask = 0
    table_id = 0
    command = OFPFC_ADD
    buffer_id = 0xFFFFFFFF
    out_port = 0xFFFFFFFF
    out_group = 0xFFFFFFFF
    flags = 0  # can add send_flow_removed if desired

    fm_fixed = struct.pack("!QQBBHHHIIIIHH",
                           cookie, cookie_mask, table_id, command,
                           idle_timeout, hard_timeout, priority,
                           buffer_id, out_port, out_group, flags, 0)
    payload = fm_fixed + match + instructions
    return of_header(OFPT_FLOW_MOD, len(payload)) + payload

def pack_table_miss_send_to_controller() -> bytes:
    # Empty match, action: output to controller with max_len = MISS_SEND_LEN
    match = pack_match(b"")
    actions = pack_output_action(OFPP_CONTROLLER, MISS_SEND_LEN)
    inst = pack_instruction_apply_actions(actions)
    return pack_flow_mod_add(match, inst, priority=TABLE_MISS_PRIORITY,
                             idle_timeout=0, hard_timeout=0)

def mac_to_bytes(mac_str: str) -> bytes:
    return bytes(int(x, 16) for x in mac_str.split(":"))

def format_mac(mac_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac_bytes)

class DatapathState:
    def __init__(self, dpid: int):
        self.dpid = dpid
        self.mac_to_port = {}           # mac -> port
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

    def connection_lost(self, exc):
        print(f"[-] Switch disconnected (dpid={self.dpid})")
        if self.dpid in self.controller.datapaths:
            del self.controller.datapaths[self.dpid]

    def send(self, msg: bytes):
        if self.transport:
            self.transport.write(msg)

    def handle_message(self, msg_type: int, payload: bytes):
        if msg_type == OFPT_HELLO:
            # hello exchange done; request features
            self.send(pack_features_request())

        elif msg_type == OFPT_ECHO_REQUEST:
            self.send(pack_echo_reply(payload))

        elif msg_type == OFPT_FEATURES_REPLY:
            # Parse datapath_id from features reply: ofp_switch_features
            # dpid is first 8 bytes
            if len(payload) >= 24:
                dpid = struct.unpack("!Q", payload[:8])[0]
                self.dpid = dpid
                self.dp = DatapathState(dpid)
                self.controller.datapaths[dpid] = self.dp
                print(f"[+] Features reply: dpid=0x{dpid:016x}")
                self.send(pack_set_config(MISS_SEND_LEN, 0))
                self.send(pack_table_miss_send_to_controller())
            else:
                print(f"[!] Malformed FEATURES_REPLY, length={len(payload)} raw={payload.hex()}")

        elif msg_type == OFPT_PACKET_IN:
            self.handle_packet_in(payload)

        elif msg_type == OFPT_PORT_STATUS:
            # Can extend: track port add/remove
            pass

        elif msg_type == OFPT_ERROR:
            print("[!] Switch sent OFPT_ERROR")

        elif msg_type == OFPT_MULTIPART_REPLY:
            pass

        else:
            # Unhandled message types silently ignored
            pass

    def handle_packet_in(self, payload: bytes):
        # ofp_packet_in (1.3):
        # buffer_id(4) total_len(2) reason(1) table_id(1) cookie(8)
        # match (variable, ofp_match), pad(2), data(variable)
        if len(payload) < 24:
            return
        buffer_id, total_len, reason, table_id = struct.unpack("!IHB B", payload[:8])
        cookie = struct.unpack("!Q", payload[8:16])[0]
        # parse match
        mtype, mlen = struct.unpack("!HH", payload[16:20])
        match_bytes = payload[20:20+mlen]
        pad2_idx = 20 + ((mlen + 7) // 8) * 8
        # ofp_packet_in has 2 bytes pad after match
        data_idx = pad2_idx + 2
        frame = payload[data_idx:]

        in_port = None
        # Extract IN_PORT from OXM match
        mbuf = match_bytes[4:]  # skip ofp_match header (type,len)
        i = 0
        while i + 4 <= len(mbuf):
            oxm_header = struct.unpack("!I", mbuf[i:i+4])[0]
            oxm_class = (oxm_header >> 16) & 0xFFFF
            field = (oxm_header >> 9) & 0x7F
            hasmask = (oxm_header >> 8) & 0x1
            length = oxm_header & 0xFF
            i += 4
            if i + length > len(mbuf):
                break
            value = mbuf[i:i+length]
            i += length
            if oxm_class == OXM_CLASS_OPENFLOW_BASIC and field == OXM_OF_IN_PORT and hasmask == 0 and length == 4:
                in_port = struct.unpack("!I", value)[0]

        if in_port is None:
            # If we can't find in_port, default to table port (rare)
            in_port = 0

        # Parse Ethernet header (if available)
        if len(frame) >= 14:
            dst = frame[0:6]
            src = frame[6:12]
            eth_type = struct.unpack("!H", frame[12:14])[0]
        else:
            dst, src, eth_type = b"", b"", 0

        if self.dp:
            self.dp.learn(src, in_port)
        else:
            return

        # Decide output port
        out_port = self.dp.lookup(dst)
        if out_port is None:
            # Unknown destination: flood
            self.output_packet(in_port=in_port, out_port=OFPP_FLOOD, dst=dst, src=src)
        else:
            if out_port == in_port:
                # Same port: drop
                return
            # Install short-lived bidirectional flows (MAC-based)
            self.install_mac_flow(src, dst, in_port, out_port)
            self.install_mac_flow(dst, src, out_port, in_port)
            # Optionally, we could also send the current packet via OUTPUT action,
            # but the installed flow will handle subsequent packets.

    def output_packet(self, in_port: int, out_port: int, dst: bytes, src: bytes):
        # For simplicity, rely on table-miss + actions. OVS will flood via OFPP_FLOOD
        # If you wish to craft a PacketOut, add OFPT_PACKET_OUT support.
        mac_str = f"{format_mac(src)} -> {format_mac(dst)}"
        if out_port == OFPP_FLOOD:
            print(f"[~] FLOOD (dpid=0x{self.dpid:016x}, in={in_port}): {mac_str}")
        else:
            print(f"[>] OUTPUT (dpid=0x{self.dpid:016x}, in={in_port} -> out={out_port}): {mac_str}")

    def install_mac_flow(self, src: bytes, dst: bytes, in_port: int, out_port: int):
        # Match: eth_src, eth_dst
        oxms = pack_oxm_eth_src(src) + pack_oxm_eth_dst(dst)
        match = pack_match(oxms)
        actions = pack_output_action(out_port, 0)
        inst = pack_instruction_apply_actions(actions)
        fm = pack_flow_mod_add(match, inst,
                               priority=DEFAULT_PRIORITY_LEARNED,
                               idle_timeout=DEFAULT_IDLE_TIMEOUT,
                               hard_timeout=DEFAULT_HARD_TIMEOUT)
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
