# state_db.py
import sqlite3
import json
import threading
import logging

logger = logging.getLogger("RedPearl")

class RedPearlStateDB:
    def __init__(self, db_path="redpearl_state.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_db()

    def _get_connection(self):
        # enable WAL mode for high-concurrency reader/writer safety
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self):
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    ip TEXT PRIMARY KEY,
                    mac TEXT,
                    vendor TEXT,
                    identity TEXT,
                    protocols TEXT,
                    queries INTEGER,
                    attributes TEXT,
                    state TEXT,
                    telemetry_flags TEXT,
                    telemetry_protocol TEXT,
                    updated_at REAL
                )
            """)
            conn.commit()
            conn.close()

    def upsert_host(self, ip: str, data: dict):
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Serialize sets/dicts safely
            protos = data.get("Protocols", set())
            if isinstance(protos, set):
                protos = list(protos)
            
            attributes = data.get("Attributes", {})
            telemetry_flags = data.get("TelemetryFlags", {})
            
            cursor.execute("""
                INSERT INTO hosts (ip, mac, vendor, identity, protocols, queries, attributes, state, telemetry_flags, telemetry_protocol, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac = excluded.mac,
                    vendor = excluded.vendor,
                    identity = excluded.identity,
                    protocols = excluded.protocols,
                    queries = excluded.queries,
                    attributes = excluded.attributes,
                    state = COALESCE(excluded.state, hosts.state),
                    telemetry_flags = COALESCE(excluded.telemetry_flags, hosts.telemetry_flags),
                    telemetry_protocol = COALESCE(excluded.telemetry_protocol, hosts.telemetry_protocol),
                    updated_at = excluded.updated_at
            """, (
                ip,
                data.get("MAC", "Unknown MAC"),
                data.get("Vendor", "Unknown Vendor"),
                data.get("Identity", ""),
                json.dumps(protos),
                data.get("Queries", 1),
                json.dumps(attributes),
                data.get("State"),
                json.dumps(telemetry_flags),
                data.get("TelemetryProtocol", ""),
                data.get("updated_at", 0.0)
            ))
            conn.commit()
            conn.close()

    def load_state_dict(self) -> dict:
        with self.lock:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM hosts")
            rows = cursor.fetchall()
            conn.close()
            
            result = {}
            for row in rows:
                result[row["ip"]] = {
                    "MAC": row["mac"],
                    "Vendor": row["vendor"],
                    "Identity": row["identity"],
                    "Protocols": set(json.loads(row["protocols"])) if row["protocols"] else set(),
                    "Queries": row["queries"],
                    "Attributes": json.loads(row["attributes"]) if row["attributes"] else {},
                    "State": row["state"],
                    "TelemetryFlags": json.loads(row["telemetry_flags"]) if row["telemetry_flags"] else {},
                    "TelemetryProtocol": row["telemetry_protocol"]
                }
            return result
