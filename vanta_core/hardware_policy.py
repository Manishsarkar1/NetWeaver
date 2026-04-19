import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class FlowConstraintPolicy:
    max_idle_timeout: int = 60
    max_hard_timeout: int = 0
    allow_buffer_id: bool = True
    allow_packet_out: bool = True

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class HardwareDevicePolicy:
    approved: bool = False
    expected_capabilities: tuple = ()
    min_ports: int = 0
    flow_constraints: FlowConstraintPolicy = field(default_factory=FlowConstraintPolicy)
    notes: str = ""

    def to_dict(self):
        payload = asdict(self)
        payload["expected_capabilities"] = list(self.expected_capabilities)
        return payload


@dataclass(frozen=True)
class HardwarePolicyDecision:
    approved: bool
    mode: str
    reasons: tuple
    expected_capabilities: tuple
    flow_constraints: FlowConstraintPolicy

    def to_dict(self):
        payload = asdict(self)
        payload["reasons"] = list(self.reasons)
        payload["expected_capabilities"] = list(self.expected_capabilities)
        return payload


@dataclass(frozen=True)
class HardwareInventoryPolicy:
    mode: str = "enforce"
    default_policy: HardwareDevicePolicy = field(default_factory=HardwareDevicePolicy)
    devices: dict = field(default_factory=dict)

    def get_device_policy(self, dpid):
        return self.devices.get(str(dpid), self.default_policy)

    def evaluate_device(self, device_record):
        device_policy = self.get_device_policy(device_record.dpid)
        reasons = []

        if not device_policy.approved:
            reasons.append("device_not_approved")

        missing_capabilities = sorted(
            capability
            for capability in device_policy.expected_capabilities
            if capability not in set(device_record.capabilities)
        )
        if missing_capabilities:
            reasons.append(
                "missing_capabilities:" + ",".join(missing_capabilities)
            )

        if len(device_record.ports) < device_policy.min_ports:
            reasons.append(
                f"insufficient_ports:{len(device_record.ports)}/{device_policy.min_ports}"
            )

        return HardwarePolicyDecision(
            approved=not reasons,
            mode=self.mode,
            reasons=tuple(reasons or ("approved",)),
            expected_capabilities=tuple(device_policy.expected_capabilities),
            flow_constraints=device_policy.flow_constraints,
        )

    def to_dict(self):
        return {
            "mode": self.mode,
            "default_policy": self.default_policy.to_dict(),
            "devices": {
                key: value.to_dict()
                for key, value in self.devices.items()
            },
        }


def load_hardware_inventory_policy(path, mode="enforce"):
    config_path = Path(path)
    if not config_path.exists():
        return HardwareInventoryPolicy(mode=mode)

    payload = json.loads(config_path.read_text(encoding="utf-8"))
    default_policy = _build_device_policy(payload.get("default_policy", {}))
    devices = {
        str(dpid): _build_device_policy(device_payload)
        for dpid, device_payload in payload.get("devices", {}).items()
    }
    effective_mode = str(payload.get("mode", mode)).lower()
    return HardwareInventoryPolicy(
        mode=effective_mode,
        default_policy=default_policy,
        devices=devices,
    )


def _build_device_policy(payload):
    flow_constraints = FlowConstraintPolicy(
        max_idle_timeout=int(payload.get("flow_constraints", {}).get("max_idle_timeout", 60)),
        max_hard_timeout=int(payload.get("flow_constraints", {}).get("max_hard_timeout", 0)),
        allow_buffer_id=bool(payload.get("flow_constraints", {}).get("allow_buffer_id", True)),
        allow_packet_out=bool(payload.get("flow_constraints", {}).get("allow_packet_out", True)),
    )
    return HardwareDevicePolicy(
        approved=bool(payload.get("approved", False)),
        expected_capabilities=tuple(payload.get("expected_capabilities", [])),
        min_ports=int(payload.get("min_ports", 0)),
        flow_constraints=flow_constraints,
        notes=str(payload.get("notes", "")),
    )
