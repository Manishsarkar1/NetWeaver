from dataclasses import asdict, dataclass, field
from typing import Dict, List

from .hardware_policy import HardwareInventoryManager


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


@dataclass
class OpenFlowDeviceRecord:
    dpid: int
    target: str
    connected: bool = True
    negotiated_version: str = "unknown"
    n_buffers: int = 0
    n_tables: int = 0
    auxiliary_id: int = 0
    capabilities: List[str] = field(default_factory=list)
    ports: List[dict] = field(default_factory=list)
    policy_status: str = "unknown"
    policy_reasons: List[str] = field(default_factory=list)
    expected_capabilities: List[str] = field(default_factory=list)
    flow_constraints: dict = field(default_factory=dict)

    def to_switch_summary(self):
        return {
            "dpid": self.dpid,
            "id": f"s{self.dpid}",
            "target": self.target,
            "connected": self.connected,
            "capabilities": list(self.capabilities),
            "port_count": len(self.ports),
            "negotiated_version": self.negotiated_version,
            "policy_status": self.policy_status,
            "policy_reasons": list(self.policy_reasons),
        }

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

    def register_switch(self, datapaths, datapath, features_msg=None):
        datapaths[datapath.id] = datapath
        return datapath.id

    def handle_port_desc_reply(self, msg):
        return None

    def list_switches(self, datapaths):
        return [{"dpid": dpid, "id": f"s{dpid}"} for dpid in datapaths]

    def get_device_inventory(self):
        return []

    def approve_device(self, dpid, target=None, rollout_mode="enforce", expected_capabilities=None, min_ports=1, flow_constraints=None, notes="Approved via onboarding flow."):
        raise RuntimeError("Device onboarding is not supported by this network backend.")

    def set_device_rollout_mode(self, dpid, rollout_mode):
        raise RuntimeError("Per-device rollout mode is not supported by this network backend.")

    def install_controller_table_miss(self, datapath):
        raise NotImplementedError

    def install_flow(self, datapath, priority, match, actions, idle=0, hard=0, buffer_id=None):
        raise NotImplementedError

    def install_packet_flow(self, datapath, in_port, out_port, pkt, buffer_id=None):
        raise NotImplementedError

    def forward_packet(self, datapath, msg, in_port, out_port):
        raise NotImplementedError

    def get_backend_metadata(self):
        metadata = self.descriptor.to_dict()
        metadata["device_count"] = len(self.get_device_inventory())
        return metadata


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
        if buffer_id is not None:
            kwargs["buffer_id"] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))
        return True

    def install_packet_flow(self, datapath, in_port, out_port, pkt, buffer_id=None):
        protocols = getattr(pkt, "protocols", [])
        if not protocols:
            raise RuntimeError("Packet did not include an Ethernet header for flow installation.")
        eth = protocols[0]
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
        actions = [parser.OFPActionOutput(out_port)]
        return self.install_flow(datapath, 1, match, actions, idle=30, buffer_id=buffer_id)

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
        return True


class OpenFlowHardwareAdapter(RyuOpenFlowAdapter):
    """Production-oriented adapter for real OpenFlow endpoints such as bare-metal OVS."""

    def __init__(self, target="openflow_switch", inventory_path="config/hardware_inventory.json", rollout_mode="enforce", logger=None):
        super().__init__(logger=logger)
        self.descriptor = NetworkBackendDescriptor(
            name="openflow_hardware",
            transport="openflow13",
            target=target,
            supports_physical_switches=True,
            supports_flow_programming=True,
            supports_packet_io=True,
            status="active",
        )
        self._device_inventory: Dict[int, OpenFlowDeviceRecord] = {}
        self._policy_manager = HardwareInventoryManager(inventory_path, mode=rollout_mode)
        self._policy = self._policy_manager.get_policy()
        self._inventory_path = inventory_path

    def register_switch(self, datapaths, datapath, features_msg=None):
        dpid = super().register_switch(datapaths, datapath, features_msg=features_msg)
        record = self._build_device_record(datapath, features_msg)
        self._apply_policy(record)
        self._device_inventory[dpid] = record
        self._request_port_descriptions(datapath)
        return dpid

    def handle_port_desc_reply(self, msg):
        datapath = msg.datapath
        record = self._device_inventory.get(datapath.id)
        if record is None:
            return None
        record.ports = [self._serialize_port(port) for port in getattr(msg, "body", [])]
        self._apply_policy(record)
        return record.to_dict()

    def list_switches(self, datapaths):
        if self._device_inventory:
            return [
                self._device_inventory[dpid].to_switch_summary()
                for dpid in sorted(self._device_inventory)
            ]
        return super().list_switches(datapaths)

    def get_device_inventory(self):
        return [
            self._device_inventory[dpid].to_dict()
            for dpid in sorted(self._device_inventory)
        ]

    def get_backend_metadata(self):
        self._policy = self._policy_manager.get_policy()
        metadata = super().get_backend_metadata()
        metadata["inventory_path"] = self._inventory_path
        metadata["rollout_mode"] = self._policy.mode
        metadata["approved_device_count"] = sum(
            1 for record in self._device_inventory.values()
            if record.policy_status == "approved"
        )
        return metadata

    def install_flow(self, datapath, priority, match, actions, idle=0, hard=0, buffer_id=None):
        if priority > 0:
            decision = self._ensure_flow_allowed(datapath.id)
            constraints = decision.flow_constraints
            idle = min(idle, constraints.max_idle_timeout) if constraints.max_idle_timeout >= 0 else idle
            hard = min(hard, constraints.max_hard_timeout) if constraints.max_hard_timeout > 0 else hard
            if not constraints.allow_buffer_id:
                buffer_id = None
        return super().install_flow(
            datapath,
            priority,
            match,
            actions,
            idle=idle,
            hard=hard,
            buffer_id=buffer_id,
        )

    def forward_packet(self, datapath, msg, in_port, out_port):
        record = self._device_inventory.get(datapath.id)
        if record and not record.flow_constraints.get("allow_packet_out", True):
            if self._logger:
                self._logger.warning(
                    "Packet-out skipped for s%s due to hardware rollout policy.",
                    datapath.id,
                )
            return False
        return super().forward_packet(datapath, msg, in_port, out_port)

    def _ensure_flow_allowed(self, dpid):
        record = self._device_inventory.get(dpid)
        if record is None:
            raise RuntimeError(f"Unknown hardware datapath {dpid}.")
        if record.policy_status == "approved":
            return self._policy.evaluate_device(record)

        message = (
            f"Hardware rollout policy blocked flow programming on s{dpid}: "
            + ", ".join(record.policy_reasons or ["device_not_approved"])
        )
        if self._policy.mode == "audit":
            if self._logger:
                self._logger.warning(message + " (audit mode, continuing)")
            return self._policy.evaluate_device(record)
        raise RuntimeError(message)

    def _apply_policy(self, record):
        self._policy = self._policy_manager.get_policy()
        decision = self._policy.evaluate_device(record)
        record.policy_status = "approved" if decision.approved else "blocked"
        record.policy_reasons = list(decision.reasons)
        record.expected_capabilities = list(decision.expected_capabilities)
        record.flow_constraints = decision.flow_constraints.to_dict()

    def approve_device(self, dpid, target=None, rollout_mode="enforce", expected_capabilities=None, min_ports=1, flow_constraints=None, notes="Approved via onboarding flow."):
        policy = self._policy_manager.approve_device(
            dpid,
            target=target or self.descriptor.target,
            rollout_mode=rollout_mode,
            expected_capabilities=expected_capabilities or [],
            min_ports=min_ports,
            flow_constraints=flow_constraints or {},
            notes=notes,
        )
        self._policy = self._policy_manager.get_policy()
        record = self._device_inventory.get(int(dpid))
        if record is not None:
            self._apply_policy(record)
            return record.to_dict()
        return {
            "dpid": int(dpid),
            "target": target or self.descriptor.target,
            "policy": policy.to_dict(),
        }

    def set_device_rollout_mode(self, dpid, rollout_mode):
        self._policy_manager.set_device_rollout_mode(dpid, rollout_mode)
        self._policy = self._policy_manager.get_policy()
        record = self._device_inventory.get(int(dpid))
        if record is not None:
            self._apply_policy(record)
            return record.to_dict()
        return {
            "dpid": int(dpid),
            "rollout_mode": rollout_mode,
        }

    def _build_device_record(self, datapath, features_msg):
        ofproto = datapath.ofproto
        version_value = getattr(getattr(datapath, "ofproto", None), "OFP_VERSION", None)
        version_text = "unknown" if version_value is None else f"0x{version_value:02x}"

        return OpenFlowDeviceRecord(
            dpid=datapath.id,
            target=self.descriptor.target,
            negotiated_version=version_text,
            n_buffers=getattr(features_msg, "n_buffers", 0),
            n_tables=getattr(features_msg, "n_tables", 0),
            auxiliary_id=getattr(features_msg, "auxiliary_id", 0),
            capabilities=self._decode_capabilities(ofproto, getattr(features_msg, "capabilities", 0)),
        )

    def _request_port_descriptions(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        request_cls = getattr(parser, "OFPPortDescStatsRequest", None)
        if request_cls is None:
            return
        datapath.send_msg(request_cls(datapath, 0, ofproto.OFPP_ANY))

    @staticmethod
    def _decode_capabilities(ofproto, capability_bits):
        names = [
            ("OFPC_FLOW_STATS", "flow_stats"),
            ("OFPC_TABLE_STATS", "table_stats"),
            ("OFPC_PORT_STATS", "port_stats"),
            ("OFPC_GROUP_STATS", "group_stats"),
            ("OFPC_IP_REASM", "ip_reassembly"),
            ("OFPC_QUEUE_STATS", "queue_stats"),
            ("OFPC_PORT_BLOCKED", "port_blocked"),
        ]
        decoded = []
        for attr_name, label in names:
            attr_value = getattr(ofproto, attr_name, None)
            if attr_value is not None and capability_bits & attr_value:
                decoded.append(label)
        return decoded

    @staticmethod
    def _serialize_port(port):
        return {
            "port_no": getattr(port, "port_no", None),
            "name": OpenFlowHardwareAdapter._coerce_port_name(getattr(port, "name", "")),
            "hw_addr": getattr(port, "hw_addr", ""),
            "config": getattr(port, "config", 0),
            "state": getattr(port, "state", 0),
            "curr_speed": getattr(port, "curr_speed", 0),
            "max_speed": getattr(port, "max_speed", 0),
        }

    @staticmethod
    def _coerce_port_name(name):
        if isinstance(name, bytes):
            return name.decode("utf-8", errors="ignore").rstrip("\x00")
        return str(name).rstrip("\x00")


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
        return OpenFlowHardwareAdapter(
            target=target,
            inventory_path=config.hardware_inventory_path,
            rollout_mode=config.hardware_rollout_mode,
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
