import json
import tempfile
import unittest
from pathlib import Path

from vanta_core.hardware_policy import (
    HardwareInventoryManager,
    load_hardware_inventory_policy,
)


class FakeDevice:
    def __init__(self, dpid, capabilities=None, ports=None):
        self.dpid = dpid
        self.capabilities = capabilities or []
        self.ports = ports or []


class HardwarePolicyTests(unittest.TestCase):
    def test_missing_file_returns_default_blocking_policy(self):
        policy = load_hardware_inventory_policy("does-not-exist.json", mode="enforce")

        decision = policy.evaluate_device(FakeDevice(1))

        self.assertFalse(decision.approved)
        self.assertIn("device_not_approved", decision.reasons)

    def test_policy_file_approves_matching_device(self):
        payload = {
            "mode": "enforce",
            "default_policy": {
                "approved": False,
                "expected_capabilities": ["flow_stats"],
                "min_ports": 1,
            },
            "devices": {
                "7": {
                    "approved": True,
                    "rollout_mode": "audit",
                    "expected_capabilities": ["flow_stats", "port_stats"],
                    "min_ports": 2,
                    "flow_constraints": {
                        "max_idle_timeout": 15,
                        "allow_buffer_id": False,
                        "allow_packet_out": True,
                    },
                }
            },
        }
        path = self._write_policy(payload)
        policy = load_hardware_inventory_policy(str(path), mode="enforce")

        decision = policy.evaluate_device(
            FakeDevice(
                7,
                capabilities=["flow_stats", "port_stats"],
                ports=[{"port_no": 1}, {"port_no": 2}],
            )
        )

        self.assertTrue(decision.approved)
        self.assertEqual(decision.reasons, ("approved",))
        self.assertEqual(decision.mode, "audit")
        self.assertEqual(decision.flow_constraints.max_idle_timeout, 15)
        self.assertFalse(decision.flow_constraints.allow_buffer_id)

    def test_onboarding_manager_promotes_device_without_manual_json_edit(self):
        path = self._write_policy(
            {
                "mode": "audit",
                "default_policy": {
                    "approved": False,
                    "expected_capabilities": [],
                    "min_ports": 0,
                },
                "devices": {},
            }
        )
        manager = HardwareInventoryManager(str(path), mode="audit")

        manager.approve_device(
            21,
            target="site_a_edge",
            rollout_mode="enforce",
            expected_capabilities=["flow_stats"],
            min_ports=1,
            notes="Approved by onboarding API.",
        )

        policy = manager.get_policy()
        decision = policy.evaluate_device(
            FakeDevice(21, capabilities=["flow_stats"], ports=[{"port_no": 1}])
        )

        self.assertTrue(decision.approved)
        self.assertEqual(decision.mode, "enforce")

        persisted = json.loads(path.read_text(encoding="utf-8"))
        self.assertTrue(persisted["devices"]["21"]["approved"])
        self.assertEqual(persisted["devices"]["21"]["rollout_mode"], "enforce")

    @staticmethod
    def _write_policy(payload):
        directory = Path(tempfile.mkdtemp())
        path = directory / "hardware_inventory.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
