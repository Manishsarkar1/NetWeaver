import tempfile
import unittest
from pathlib import Path

from vanta_core.state_store import SQLiteStateStore


class StateStoreTests(unittest.TestCase):
    def test_sqlite_store_persists_and_restores_state(self):
        directory = Path(tempfile.mkdtemp())
        db_path = directory / "vanta.db"
        store = SQLiteStateStore(str(db_path))

        store.record_morph_event({"protocol": "TCP", "trigger": "reply"})
        store.record_threat_event({"threat_type": "port_scan", "source_ip": "1.1.1.1"})
        store.record_audit_log("hardware_onboarded", {"dpid": 1})
        store.upsert_vip_mapping("10.0.0.1", "192.168.100.1")

        bootstrap = store.load_bootstrap_state()

        self.assertEqual(len(bootstrap["morph_history"]), 1)
        self.assertEqual(len(bootstrap["threats"]), 1)
        self.assertEqual(len(bootstrap["audit_logs"]), 1)
        self.assertEqual(
            bootstrap["vip_mappings"],
            [{"real_ip": "10.0.0.1", "vip": "192.168.100.1"}],
        )

    def test_sqlite_store_removes_vip_mapping(self):
        directory = Path(tempfile.mkdtemp())
        db_path = directory / "vanta.db"
        store = SQLiteStateStore(str(db_path))

        store.upsert_vip_mapping("10.0.0.1", "192.168.100.1")
        store.remove_vip_mapping("10.0.0.1")

        bootstrap = store.load_bootstrap_state()
        self.assertEqual(bootstrap["vip_mappings"], [])


if __name__ == "__main__":
    unittest.main()
