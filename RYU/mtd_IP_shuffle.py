# RYU/mtd_IP_shuffle_fixed.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib.packet import ether_types
import random

class MTDIPShuffle(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MTDIPShuffle, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.real_to_virtual = {}
        self.virtual_to_real = {}
        self.host_ports = {}  # (dpid, ip) -> port

        # Initial mapping
        self.hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
        for ip in self.hosts:
            self._assign_virtual_ip(ip)

    def _assign_virtual_ip(self, real_ip):
        virtual_ip = "192.168.100.{}".format(random.randint(50, 250))
        while virtual_ip in self.virtual_to_real:
            virtual_ip = "192.168.100.{}".format(random.randint(50, 250))
        self.real_to_virtual[real_ip] = virtual_ip
        self.virtual_to_real[virtual_ip] = real_ip

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            self._handle_arp(datapath, arp_pkt, in_port)
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            self._handle_ip(datapath, ip_pkt, in_port)

    def _handle_arp(self, datapath, arp_pkt, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid = datapath.id

        if arp_pkt.opcode != arp.ARP_REQUEST:
            return

        real_ip = arp_pkt.dst_ip
        if real_ip not in self.real_to_virtual:
            return

        virtual_ip = self.real_to_virtual[real_ip]
        dst_mac = "aa:bb:cc:{:02x}:{:02x}:{:02x}".format(
            *[int(x) for x in virtual_ip.split('.')[1:]]
        )

        # Send ARP reply
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=arp_pkt.src_mac,
            src=dst_mac
        ))
        arp_reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=dst_mac,
            src_ip=virtual_ip,
            dst_mac=arp_pkt.src_mac,
            dst_ip=arp_pkt.src_ip
        ))
        arp_reply.serialize()

        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=arp_reply.data)
        datapath.send_msg(out)

        # Learn port for host
        self.host_ports[(dpid, real_ip)] = in_port

    def _handle_ip(self, datapath, ip_pkt, in_port):
        dpid = datapath.id
        src_real = ip_pkt.src
        dst_real = ip_pkt.dst

        if dst_real not in self.real_to_virtual or src_real not in self.real_to_virtual:
            return

        src_virtual = self.real_to_virtual[src_real]
        dst_virtual = self.real_to_virtual[dst_real]

        # Install bidirectional flows
        self._install_bidirectional_flows(datapath, src_real, dst_real, src_virtual, dst_virtual)

    def _install_bidirectional_flows(self, datapath, src_real, dst_real, src_virtual, dst_virtual):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        in_port_src = self.host_ports.get((datapath.id, src_real))
        out_port_dst = self.host_ports.get((datapath.id, dst_real))

        if not in_port_src or not out_port_dst:
            return  # wait until both hosts send ARP to learn ports

        # Forward src -> dst
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_virtual, ipv4_dst=dst_virtual)
        actions = [
            parser.OFPActionSetField(ipv4_src=src_virtual),
            parser.OFPActionSetField(ipv4_dst=dst_virtual),
            parser.OFPActionOutput(out_port_dst)
        ]
        self._add_flow(datapath, 10, match, actions)

        # Forward dst -> src
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=dst_virtual, ipv4_dst=src_virtual)
        actions = [
            parser.OFPActionSetField(ipv4_src=dst_virtual),
            parser.OFPActionSetField(ipv4_dst=src_virtual),
            parser.OFPActionOutput(in_port_src)
        ]
        self._add_flow(datapath, 10, match, actions)

    def shuffle_ips(self):
        # Shuffle all virtual IPs
        self.real_to_virtual.clear()
        self.virtual_to_real.clear()
        for ip in self.hosts:
            self._assign_virtual_ip(ip)
        self.logger.info("⚡ IP Shuffle Triggered")
        self._print_mapping()

    def _print_mapping(self):
        print("\n            IP SHUFFLE MAP             ")
        print("┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━┓")
        print("┃ REAL IP  ┃ VIRTUAL IP      ┃ SWITCH ┃")
        print("┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━┩")
        for real_ip, virtual_ip in self.real_to_virtual.items():
            for (dpid, host_ip), port in self.host_ports.items():
                if host_ip == real_ip:
                    print(f"│ {real_ip:<8} │ {virtual_ip:<15} │ SW-{dpid}   │")
        print("└──────────┴─────────────────┴────────┘\n")