import json
import threading
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
    rollout_mode: str = "inherit"
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

        effective_mode = _normalize_mode(
            device_policy.rollout_mode if device_policy.rollout_mode != "inherit" else self.mode
        )

        return HardwarePolicyDecision(
            approved=not reasons,
            mode=effective_mode,
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


class HardwareInventoryManager:
    def __init__(self, path, mode="enforce"):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._fallback_mode = _normalize_mode(mode)
        self._policy = self._load()

    def get_policy(self):
        with self._lock:
            return self._policy

    def reload(self):
        with self._lock:
            self._policy = self._load()
            return self._policy

    def approve_device(
        self,
        dpid,
        target="openflow_switch",
        rollout_mode="enforce",
        expected_capabilities=None,
        min_ports=1,
        flow_constraints=None,
        notes="Approved via onboarding flow.",
    ):
        with self._lock:
            payload = self._read_payload()
            devices = payload.setdefault("devices", {})
            device_payload = devices.setdefault(str(dpid), {})
            device_payload["approved"] = True
            device_payload["rollout_mode"] = _normalize_mode(rollout_mode)
            device_payload["expected_capabilities"] = list(expected_capabilities or [])
            device_payload["min_ports"] = int(min_ports)
            device_payload["target"] = target
            device_payload["notes"] = notes
            if flow_constraints:
                device_payload["flow_constraints"] = dict(flow_constraints)
            self._write_payload(payload)
            self._policy = self._load()
            return self._policy.get_device_policy(dpid)

    def set_device_rollout_mode(self, dpid, rollout_mode):
        with self._lock:
            payload = self._read_payload()
            devices = payload.setdefault("devices", {})
            device_payload = devices.setdefault(str(dpid), {})
            device_payload["rollout_mode"] = _normalize_mode(rollout_mode)
            self._write_payload(payload)
            self._policy = self._load()
            return self._policy.get_device_policy(dpid)

    def _load(self):
        if not self.path.exists():
            return HardwareInventoryPolicy(mode=self._fallback_mode)

        payload = json.loads(self.path.read_text(encoding="utf-8"))
        default_policy = _build_device_policy(payload.get("default_policy", {}))
        devices = {
            str(dpid): _build_device_policy(device_payload)
            for dpid, device_payload in payload.get("devices", {}).items()
        }
        effective_mode = _normalize_mode(payload.get("mode", self._fallback_mode))
        return HardwareInventoryPolicy(
            mode=effective_mode,
            default_policy=default_policy,
            devices=devices,
        )

    def _read_payload(self):
        if not self.path.exists():
            return {
                "mode": self._fallback_mode,
                "default_policy": HardwareDevicePolicy().to_dict(),
                "devices": {},
            }
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write_payload(self, payload):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_hardware_inventory_policy(path, mode="enforce"):
    return HardwareInventoryManager(path, mode=mode).get_policy()


def _build_device_policy(payload):
    flow_constraints = FlowConstraintPolicy(
        max_idle_timeout=int(payload.get("flow_constraints", {}).get("max_idle_timeout", 60)),
        max_hard_timeout=int(payload.get("flow_constraints", {}).get("max_hard_timeout", 0)),
        allow_buffer_id=bool(payload.get("flow_constraints", {}).get("allow_buffer_id", True)),
        allow_packet_out=bool(payload.get("flow_constraints", {}).get("allow_packet_out", True)),
    )
    return HardwareDevicePolicy(
        approved=bool(payload.get("approved", False)),
        rollout_mode=_normalize_mode(payload.get("rollout_mode", "inherit"), allow_inherit=True),
        expected_capabilities=tuple(payload.get("expected_capabilities", [])),
        min_ports=int(payload.get("min_ports", 0)),
        flow_constraints=flow_constraints,
        notes=str(payload.get("notes", "")),
    )


def _normalize_mode(mode, allow_inherit=False):
    value = str(mode or "enforce").lower()
    valid = {"audit", "enforce"}
    if allow_inherit:
        valid.add("inherit")
    if value not in valid:
        return "inherit" if allow_inherit else "enforce"
    return value
