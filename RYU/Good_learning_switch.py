from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
import time


class SmartSwitchIDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    FLOOD_THRESHOLD = 100  # packets/sec

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_table = {}       # {dpid: {mac: port}}
        self.ip_stats = {}        # {src_ip: [count, timestamp]}
        self.blocked_ips = set()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id

        self.mac_table.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)

        in_port = msg.match['in_port']
        src_mac = eth.src
        dst_mac = eth.dst

        # Learn MAC
        self.mac_table[dpid][src_mac] = in_port

        # IDS logic (only IP traffic)
        if ip:
            src_ip = ip.src

            if src_ip in self.blocked_ips:
                return  # silently drop

            now = time.time()
            if src_ip not in self.ip_stats:
                self.ip_stats[src_ip] = [1, now]
            else:
                self.ip_stats[src_ip][0] += 1
                if now - self.ip_stats[src_ip][1] >= 1:
                    if self.ip_stats[src_ip][0] > self.FLOOD_THRESHOLD:
                        self.logger.warning(f"⚠️ FLOOD from {src_ip} → BLOCKED")
                        self.block_ip(dp, src_ip)
                        self.blocked_ips.add(src_ip)
                        return
                    self.ip_stats[src_ip] = [1, now]

        # Decide output port
        if dst_mac in self.mac_table[dpid]:
            out_port = self.mac_table[dpid][dst_mac]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow only if not flooding
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=src_mac,
                eth_dst=dst_mac
            )
            dp.send_msg(
                parser.OFPFlowMod(
                    datapath=dp,
                    priority=10,
                    match=match,
                    instructions=[
                        parser.OFPInstructionActions(
                            ofp.OFPIT_APPLY_ACTIONS, actions
                        )
                    ]
                )
            )

        # Send packet
        dp.send_msg(
            parser.OFPPacketOut(
                datapath=dp,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
        )

    def block_ip(self, dp, ip_addr):
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_addr
        )

        dp.send_msg(
            parser.OFPFlowMod(
                datapath=dp,
                priority=100,
                match=match,
                instructions=[]
            )
        )
