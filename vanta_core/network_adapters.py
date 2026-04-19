from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class NetworkBackendDescriptor:
    name: str
    transport: str
    target: str
    supports_physical_switches: bool
    supports_flow_programming: bool
    supports_packet_io: bool
    status: str

    def to_dict(self):
        return asdict(self)


class BaseNetworkAdapter:
    """Abstracts the control-plane operations needed by the controller."""

    descriptor = NetworkBackendDescriptor(
        name="base",
        transport="unknown",
        target="unknown",
        supports_physical_switches=False,
        supports_flow_programming=False,
        supports_packet_io=False,
        status="abstract",
    )

    def __init__(self, logger=None):
        self._logger = logger

    def register_switch(self, datapaths, datapath):
        datapaths[datapath.id] = datapath
        return datapath.id

    def list_switches(self, datapaths):
        return [{"dpid": dpid, "id": f"s{dpid}"} for dpid in datapaths]

    def install_controller_table_miss(self, datapath):
        raise NotImplementedError

    def install_flow(self, datapath, priority, match, actions, idle=0, hard=0, buffer_id=None):
        raise NotImplementedError

    def install_packet_flow(self, datapath, in_port, out_port, pkt, buffer_id=None):
        raise NotImplementedError

    def forward_packet(self, datapath, msg, in_port, out_port):
        raise NotImplementedError

    def get_backend_metadata(self):
        return self.descriptor.to_dict()


class RyuOpenFlowAdapter(BaseNetworkAdapter):
    descriptor = NetworkBackendDescriptor(
        name="ryu_openflow",
        transport="openflow13",
        target="mininet_or_ovs",
        supports_physical_switches=True,
        supports_flow_programming=True,
        supports_packet_io=True,
        status="active",
    )

    def install_controller_table_miss(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.install_flow(datapath, 0, match, actions)

    def install_flow(self, datapath, priority, match, actions, idle=0, hard=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle,
            hard_timeout=hard,
        )
        if buffer_id:
            kwargs["buffer_id"] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    def install_packet_flow(self, datapath, in_port, out_port, pkt, buffer_id=None):
        protocols = getattr(pkt, "protocols", [])
        if not protocols:
            raise RuntimeError("Packet did not include an Ethernet header for flow installation.")
        eth = protocols[0]
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
        actions = [parser.OFPActionOutput(out_port)]
        self.install_flow(datapath, 1, match, actions, idle=30, buffer_id=buffer_id)

    def forward_packet(self, datapath, msg, in_port, out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)


class PlannedHardwareAdapter(BaseNetworkAdapter):
    """Placeholder for production backends that are configured but not yet implemented."""

    def __init__(self, name, transport, target, logger=None):
        super().__init__(logger=logger)
        self.descriptor = NetworkBackendDescriptor(
            name=name,
            transport=transport,
            target=target,
            supports_physical_switches=True,
            supports_flow_programming=False,
            supports_packet_io=False,
            status="planned",
        )
        if self._logger:
            self._logger.warning(
                "Network backend '%s' is scaffolded but not yet implemented; "
                "flow programming remains unavailable.",
                name,
            )

    def install_controller_table_miss(self, datapath):
        raise RuntimeError(f"Network backend '{self.descriptor.name}' is not implemented yet.")

    def install_flow(self, datapath, priority, match, actions, idle=0, hard=0, buffer_id=None):
        raise RuntimeError(f"Network backend '{self.descriptor.name}' is not implemented yet.")

    def install_packet_flow(self, datapath, in_port, out_port, pkt, buffer_id=None):
        raise RuntimeError(f"Network backend '{self.descriptor.name}' is not implemented yet.")

    def forward_packet(self, datapath, msg, in_port, out_port):
        raise RuntimeError(f"Network backend '{self.descriptor.name}' is not implemented yet.")


def build_network_adapter(config, logger=None):
    backend = (config.network_backend or "ryu_openflow").lower()
    target = (config.network_target or "mininet").lower()

    if backend == "ryu_openflow":
        return RyuOpenFlowAdapter(logger=logger)
    if backend == "openflow_hardware":
        return PlannedHardwareAdapter(
            name="openflow_hardware",
            transport="openflow13",
            target=target,
            logger=logger,
        )
    if backend == "netconf":
        return PlannedHardwareAdapter(
            name="netconf",
            transport="netconf",
            target=target,
            logger=logger,
        )
    if backend == "p4runtime":
        return PlannedHardwareAdapter(
            name="p4runtime",
            transport="p4runtime",
            target=target,
            logger=logger,
        )
    raise ValueError(f"Unsupported network backend: {backend}")
