from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib import hub
import random
import time
h
# ========= COLORS =========
G = "\033[92m"
R = "\033[91m"
Y = "\033[93m"
C = "\033[96m"
W = "\033[0m"
B = "\033[94m"

class MTDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.real_to_virtual = {}
        self.virtual_to_real = {}

        self.shuffle_interval = 10  # seconds
        self.virtual_pool = [f"192.168.100.{i}" for i in range(50, 250)]

        print(f"\n{G}✔ SAFE MTD IP Rewrite Controller Started{W}\n")

        self.shuffle_thread = hub.spawn(self.ip_shuffle_loop)

    # ================= SWITCH SETUP =================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

        print(f"{G}[✓] Switch {dp.id} connected{W}")

    def add_flow(self, dp, priority, match, actions, buffer_id=None):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst,
            buffer_id=buffer_id if buffer_id else ofp.OFP_NO_BUFFER
        )
        dp.send_msg(mod)

    # ================= PACKET HANDLER =================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id

        self.mac_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == 0x88cc:
            return

        src = eth.src
        dst = eth.dst
        in_port = msg.match['in_port']

        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofp.OFPP_FLOOD)

        actions = []

        # ================= ARP HANDLING =================
        if arp_pkt:
            real_src = arp_pkt.src_ip
            real_dst = arp_pkt.dst_ip

            if real_src not in self.real_to_virtual:
                self.assign_virtual_ip(real_src)

            if real_dst in self.real_to_virtual:
                arp_pkt.dst_ip = self.real_to_virtual[real_dst]

            arp_pkt.src_ip = self.real_to_virtual[real_src]

            actions.append(parser.OFPActionOutput(out_port))
            out = parser.OFPPacketOut(
                datapath=dp,
                buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=pkt.data
            )
            dp.send_msg(out)
            return

        # ================= IP REWRITE =================
        if ip_pkt:
            real_src = ip_pkt.src
            real_dst = ip_pkt.dst

            if real_src not in self.real_to_virtual:
                self.assign_virtual_ip(real_src)

            if real_dst in self.real_to_virtual:
                ip_pkt.dst = self.real_to_virtual[real_dst]

            ip_pkt.src = self.real_to_virtual[real_src]

            actions.extend([
                parser.OFPActionSetField(ipv4_src=ip_pkt.src),
                parser.OFPActionSetField(ipv4_dst=ip_pkt.dst),
                parser.OFPActionOutput(out_port)
            ])
        else:
            actions.append(parser.OFPActionOutput(out_port))

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        dp.send_msg(out)

    # ================= IP SHUFFLING =================
    def ip_shuffle_loop(self):
        while True:
            time.sleep(self.shuffle_interval)
            if not self.real_to_virtual:
                continue

            print(f"\n{Y}⚡ IP SHUFFLE TRIGGERED{W}")
            for real_ip in list(self.real_to_virtual.keys()):
                new_virtual = random.choice(self.virtual_pool)
                self.real_to_virtual[real_ip] = new_virtual
                self.virtual_to_real[new_virtual] = real_ip
                print(f"{C}{real_ip} ⇒ {new_virtual}{W}")

    def assign_virtual_ip(self, real_ip):
        v_ip = random.choice(self.virtual_pool)
        self.real_to_virtual[real_ip] = v_ip
        self.virtual_to_real[v_ip] = real_ip
        print(f"{B}[MAP] {real_ip} → {v_ip}{W}")
