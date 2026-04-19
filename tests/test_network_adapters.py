import json
import tempfile
import unittest
from pathlib import Path

from vanta_core.config import RuntimeConfig
from vanta_core.network_adapters import (
    OpenFlowHardwareAdapter,
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

    def test_hardware_backend_returns_real_openflow_adapter(self):
        config = RuntimeConfig(
            secret_key="secret",
            admin_username="admin",
            admin_password="password",
            network_backend="openflow_hardware",
            network_target="arista_eos",
        )

        adapter = build_network_adapter(config)

        self.assertIsInstance(adapter, OpenFlowHardwareAdapter)
        metadata = adapter.get_backend_metadata()
        self.assertEqual(metadata["name"], "openflow_hardware")
        self.assertEqual(metadata["target"], "arista_eos")
        self.assertEqual(metadata["status"], "active")
        self.assertEqual(metadata["device_count"], 0)

    def test_planned_backend_still_available_for_netconf(self):
        config = RuntimeConfig(
            secret_key="secret",
            admin_username="admin",
            admin_password="password",
            network_backend="netconf",
            network_target="cisco_ios_xe",
        )

        adapter = build_network_adapter(config)

        self.assertIsInstance(adapter, PlannedHardwareAdapter)
        self.assertEqual(adapter.get_backend_metadata()["status"], "planned")

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

    def test_hardware_inventory_tracks_connected_switch(self):
        inventory_path = self._write_inventory(
            {
                "mode": "enforce",
                "default_policy": {
                    "approved": False,
                    "expected_capabilities": ["flow_stats", "port_stats"],
                    "min_ports": 1,
                    "flow_constraints": {
                        "max_idle_timeout": 60,
                        "max_hard_timeout": 0,
                        "allow_buffer_id": True,
                        "allow_packet_out": True,
                    },
                },
                "devices": {
                    "11": {
                        "approved": True,
                        "expected_capabilities": ["flow_stats", "port_stats"],
                        "min_ports": 1,
                        "flow_constraints": {
                            "max_idle_timeout": 20,
                            "max_hard_timeout": 0,
                            "allow_buffer_id": False,
                            "allow_packet_out": True,
                        },
                    }
                },
            }
        )
        features = type(
            "Features",
            (),
            {
                "n_buffers": 256,
                "n_tables": 4,
                "auxiliary_id": 0,
                "capabilities": 0x1 | 0x4,
            },
        )()
        parser = type(
            "Parser",
            (),
            {
                "OFPPortDescStatsRequest": lambda self, datapath, flags, port: (
                    "port_desc",
                    datapath.id,
                    flags,
                    port,
                )
            },
        )()
        ofproto = type(
            "Ofproto",
            (),
            {
                "OFP_VERSION": 0x04,
                "OFPP_ANY": 0xFFFFFFFF,
                "OFPC_FLOW_STATS": 0x1,
                "OFPC_PORT_STATS": 0x4,
            },
        )()

        class FakeDatapath:
            def __init__(self):
                self.id = 11
                self.ofproto = ofproto
                self.ofproto_parser = parser
                self.sent_messages = []

            def send_msg(self, msg):
                self.sent_messages.append(msg)

        datapath = FakeDatapath()
        adapter = OpenFlowHardwareAdapter(
            target="bare_metal_ovs",
            inventory_path=str(inventory_path),
            rollout_mode="enforce",
        )

        dpid = adapter.register_switch({}, datapath, features)

        self.assertEqual(dpid, 11)
        inventory = adapter.get_device_inventory()
        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0]["target"], "bare_metal_ovs")
        self.assertIn("flow_stats", inventory[0]["capabilities"])
        self.assertEqual(inventory[0]["policy_status"], "blocked")
        self.assertIn("insufficient_ports:0/1", inventory[0]["policy_reasons"])
        self.assertEqual(datapath.sent_messages[0], ("port_desc", 11, 0, 0xFFFFFFFF))

        reply = type(
            "PortReply",
            (),
            {
                "datapath": datapath,
                "body": [
                    type(
                        "Port",
                        (),
                        {
                            "port_no": 1,
                            "name": b"eth1\x00",
                            "hw_addr": "00:11:22:33:44:55",
                            "config": 0,
                            "state": 0,
                            "curr_speed": 1000,
                            "max_speed": 1000,
                        },
                    )()
                ],
            },
        )()

        adapter.handle_port_desc_reply(reply)
        inventory = adapter.get_device_inventory()
        self.assertEqual(inventory[0]["ports"][0]["name"], "eth1")
        self.assertEqual(inventory[0]["policy_status"], "approved")
        self.assertEqual(inventory[0]["flow_constraints"]["allow_buffer_id"], False)

    def test_unapproved_switch_blocks_non_bootstrap_flows(self):
        inventory_path = self._write_inventory(
            {
                "mode": "enforce",
                "default_policy": {
                    "approved": False,
                    "expected_capabilities": [],
                    "min_ports": 0,
                    "flow_constraints": {
                        "max_idle_timeout": 30,
                        "max_hard_timeout": 0,
                        "allow_buffer_id": True,
                        "allow_packet_out": True,
                    },
                },
                "devices": {},
            }
        )
        parser = type(
            "Parser",
            (),
            {
                "OFPInstructionActions": lambda self, instruction, actions: ("inst", instruction, actions),
                "OFPFlowMod": lambda self, **kwargs: ("flowmod", kwargs),
                "OFPMatch": lambda self, **kwargs: ("match", kwargs),
                "OFPActionOutput": lambda self, port: ("output", port),
                "OFPPortDescStatsRequest": lambda self, datapath, flags, port: ("port_desc", datapath.id, flags, port),
            },
        )()
        ofproto = type(
            "Ofproto",
            (),
            {
                "OFP_VERSION": 0x04,
                "OFPP_ANY": 0xFFFFFFFF,
                "OFPIT_APPLY_ACTIONS": 4,
            },
        )()

        class FakeDatapath:
            def __init__(self):
                self.id = 99
                self.ofproto = ofproto
                self.ofproto_parser = parser
                self.sent_messages = []

            def send_msg(self, msg):
                self.sent_messages.append(msg)

        datapath = FakeDatapath()
        adapter = OpenFlowHardwareAdapter(
            target="bare_metal_ovs",
            inventory_path=str(inventory_path),
            rollout_mode="enforce",
        )
        adapter.register_switch({}, datapath, type("Features", (), {})())

        with self.assertRaises(RuntimeError):
            adapter.install_flow(
                datapath,
                10,
                ("match", {}),
                [("output", 1)],
                idle=45,
            )

    @staticmethod
    def _write_inventory(payload):
        directory = Path(tempfile.mkdtemp())
        path = directory / "hardware_inventory.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
