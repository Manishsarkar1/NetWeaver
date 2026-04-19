import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path


class NullStateStore:
    backend_name = "none"
    persistence_enabled = False

    def load_bootstrap_state(self):
        return {
            "morph_history": [],
            "threats": [],
            "audit_logs": [],
            "vip_mappings": [],
        }

    def record_morph_event(self, event_dict):
        return None

    def record_threat_event(self, threat_dict):
        return None

    def record_audit_log(self, action, details):
        return None

    def upsert_vip_mapping(self, real_ip, vip):
        return None

    def remove_vip_mapping(self, real_ip):
        return None


class SQLiteStateStore:
    backend_name = "sqlite"
    persistence_enabled = True

    def __init__(self, db_path):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    def load_bootstrap_state(self):
        with self._lock, self._connect() as conn:
            morphs = [
                json.loads(row[0])
                for row in conn.execute(
                    "SELECT payload FROM morph_events ORDER BY id DESC LIMIT 500"
                ).fetchall()
            ]
            threats = [
                json.loads(row[0])
                for row in conn.execute(
                    "SELECT payload FROM threat_events ORDER BY id DESC LIMIT 500"
                ).fetchall()
            ]
            audit_logs = [
                json.loads(row[0])
                for row in conn.execute(
                    "SELECT payload FROM audit_logs ORDER BY id DESC LIMIT 500"
                ).fetchall()
            ]
            vip_mappings = [
                {"real_ip": row[0], "vip": row[1]}
                for row in conn.execute(
                    "SELECT real_ip, vip FROM vip_mappings ORDER BY real_ip ASC"
                ).fetchall()
            ]
        return {
            "morph_history": list(reversed(morphs)),
            "threats": list(reversed(threats)),
            "audit_logs": list(reversed(audit_logs)),
            "vip_mappings": vip_mappings,
        }

    def record_morph_event(self, event_dict):
        self._insert_payload("morph_events", event_dict)

    def record_threat_event(self, threat_dict):
        self._insert_payload("threat_events", threat_dict)

    def record_audit_log(self, action, details):
        payload = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "details": details,
        }
        self._insert_payload("audit_logs", payload)

    def upsert_vip_mapping(self, real_ip, vip):
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO vip_mappings(real_ip, vip, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(real_ip) DO UPDATE SET
                    vip=excluded.vip,
                    updated_at=excluded.updated_at
                """,
                (real_ip, vip, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )
            conn.commit()

    def remove_vip_mapping(self, real_ip):
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM vip_mappings WHERE real_ip = ?", (real_ip,))
            conn.commit()

    def _insert_payload(self, table_name, payload):
        with self._lock, self._connect() as conn:
            conn.execute(
                f"INSERT INTO {table_name}(created_at, payload) VALUES (?, ?)",
                (
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    json.dumps(payload),
                ),
            )
            conn.commit()

    def _connect(self):
        return sqlite3.connect(self._db_path)

    def _init_db(self):
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS morph_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vip_mappings (
                    real_ip TEXT PRIMARY KEY,
                    vip TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()


def build_state_store(config):
    backend = getattr(config, "state_backend", "sqlite").lower()
    if backend == "none":
        return NullStateStore()
    if backend == "sqlite":
        return SQLiteStateStore(config.state_db_path)
    raise ValueError(f"Unsupported state backend: {backend}")
