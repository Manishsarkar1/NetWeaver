from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib.packet import ether_types
from rich.console import Console
from rich.table import Table

console = Console()

class MTDHostLearning(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}     # dpid -> {mac: port}
        self.ip_to_host = {}      # ip -> (mac, dpid, port)

        console.print("\n[bold green]✔ SDN Host Learning Controller Started[/bold green]\n")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=0,
                                match=match, instructions=inst)
        dp.send_msg(mod)

        console.print(f"[cyan][✓] Switch {dp.id} connected[/cyan]")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # Learn IP from ARP
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.ip_to_host[arp_pkt.src_ip] = (eth.src, dpid, in_port)
            self.print_hosts()

        # Learn IP from IPv4
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.ip_to_host[ip_pkt.src] = (eth.src, dpid, in_port)
            self.print_hosts()

        # Forwarding logic
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        dp.send_msg(out)

    def print_hosts(self):
        table = Table(title="🌐 Discovered Hosts", show_lines=True)
        table.add_column("REAL IP", style="bold yellow")
        table.add_column("MAC", style="magenta")
        table.add_column("SWITCH", style="cyan")
        table.add_column("PORT", style="green")

        for ip, (mac, dpid, port) in self.ip_to_host.items():
            table.add_row(ip, mac, f"SW-{dpid}", str(port))

        console.print(table)
