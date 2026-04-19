import unittest

from vanta_core.config import RuntimeConfig
from vanta_core.network_adapters import (
    PlannedHardwareAdapter,
    RyuOpenFlowAdapter,
    build_network_adapter,
)


class NetworkAdapterFactoryTests(unittest.TestCase):
    def test_ryu_backend_is_default_active_adapter(self):
        config = RuntimeConfig(
            secret_key="secret",
            admin_username="admin",
            admin_password="password",
        )

        adapter = build_network_adapter(config)

        self.assertIsInstance(adapter, RyuOpenFlowAdapter)
        self.assertEqual(adapter.get_backend_metadata()["status"], "active")

    def test_hardware_backend_returns_planned_adapter_until_implemented(self):
        config = RuntimeConfig(
            secret_key="secret",
            admin_username="admin",
            admin_password="password",
            network_backend="openflow_hardware",
            network_target="arista_eos",
        )

        adapter = build_network_adapter(config)

        self.assertIsInstance(adapter, PlannedHardwareAdapter)
        metadata = adapter.get_backend_metadata()
        self.assertEqual(metadata["name"], "openflow_hardware")
        self.assertEqual(metadata["target"], "arista_eos")
        self.assertEqual(metadata["status"], "planned")

    def test_list_switches_produces_dashboard_friendly_shape(self):
        adapter = RyuOpenFlowAdapter()
        switches = adapter.list_switches({1: object(), 7: object()})

        self.assertEqual(
            switches,
            [
                {"dpid": 1, "id": "s1"},
                {"dpid": 7, "id": "s7"},
            ],
        )


if __name__ == "__main__":
    unittest.main()
