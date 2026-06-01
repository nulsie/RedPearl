import re
import logging

class MDNSTelemetryEngine:
    """
    Parses dynamic bitmasks and records from mDNS TXT records (Apple AirPlay & Google Cast)
    and maintains a live state machine to track endpoint telemetry over time.
    """
    
    def __init__(self):
        # Keeps track of the last known state per device to identify live transitions
        # Structure: { mac_or_ip: { "state": "Idle", "flags": {...} } }
        self.state_registry = {}

    @staticmethod
    def parse_txt_dict(raw_txt_records):
        """Helper to ensure all keys and values are normal strings."""
        normalized = {}
        for k, v in raw_txt_records.items():
            key = k.decode('utf-8', errors='ignore').lower() if isinstance(k, bytes) else str(k).lower()
            val = v.decode('utf-8', errors='ignore') if isinstance(v, bytes) else str(v)
            normalized[key] = val
        return normalized

    def extract_apple_airplay(self, txt_data):
        """
        Parses Apple AirPlay (_airplay._tcp.local) Status Flags (sf) and Feature Flags (ff/features).
        """
        telemetry = {
            "protocol": "AirPlay",
            "model": txt_data.get("model", "Unknown Apple Device"),
            "os_version": txt_data.get("srcvers", "Unknown"),
            "device_id": txt_data.get("deviceid", "Unknown"),
            "flags": {},
            "state": "Idle"
        }

        # Parse Status Flags (sf) - typically encoded as a hexadecimal integer string (e.g., "0x4")
        sf_str = txt_data.get("sf", "0x0")
        try:
            sf = int(sf_str, 16) if sf_str.startswith("0x") else int(sf_str)
        except ValueError:
            sf = 0

        # Bitmask breakdown for Apple Status Flags (sf)
        telemetry["flags"]["password_required"] = bool(sf & (1 << 2))     # Bit 2
        telemetry["flags"]["supports_screen_mirroring"] = bool(sf & (1 << 7)) # Bit 7
        telemetry["flags"]["system_audio_streaming"] = bool(sf & (1 << 9)) # Bit 9
        telemetry["flags"]["pin_required"] = bool(sf & (1 << 11))         # Bit 11

        # Deduce operational state based on status flags
        if telemetry["flags"]["system_audio_streaming"]:
            telemetry["state"] = "Streaming Audio/Video"
        elif telemetry["flags"]["password_required"] or telemetry["flags"]["pin_required"]:
            telemetry["state"] = "Locked / Authentication Required"
        else:
            telemetry["state"] = "Idle / Available"

        # Parse Feature Flags (ff / features) if present
        ff_str = txt_data.get("features", txt_data.get("ff", "0x0"))
        try:
            ff = int(ff_str, 16) if ff_str.startswith("0x") else int(ff_str)
            telemetry["flags"]["supports_airplay_video"] = bool(ff & (1 << 0))
            telemetry["flags"]["supports_airplay_photo"] = bool(ff & (1 << 1))
            telemetry["flags"]["supports_fairplay_encryption"] = bool(ff & (1 << 4))
            telemetry["flags"]["supports_metadata"] = bool(ff & (1 << 12))
        except ValueError:
            pass

        return telemetry

    def extract_google_cast(self, txt_data):
        """
        Parses Google Cast/Chromecast (_googlecast._tcp.local) Status codes (st) and capabilities (ca).
        """
        telemetry = {
            "protocol": "GoogleCast",
            "friendly_name": txt_data.get("fn", "Google Cast Endpoint"),
            "model": txt_data.get("md", "Chromecast/Google Home"),
            "active_app_id": txt_data.get("rs", "None (Idle)"),
            "flags": {},
            "state": "Unknown"
        }

        # Parse Status Code (st) -> 0: Idle, 1: Setup mode, 2: Active Application
        st_val = txt_data.get("st", "")
        if st_val == "0":
            telemetry["state"] = "Idle"
        elif st_val == "1":
            telemetry["state"] = "In Setup Mode"
        elif st_val == "2" or telemetry["active_app_id"] != "None (Idle)":
            telemetry["state"] = f"Streaming App: {telemetry['active_app_id']}"
        else:
            telemetry["state"] = "Idle"

        # Parse Capabilities (ca) bitmask
        try:
            ca = int(txt_data.get("ca", "0"))
            telemetry["flags"]["audio_supported"] = bool(ca & 1)
            telemetry["flags"]["video_supported"] = bool(ca & 2)
            telemetry["flags"]["multizone_audio"] = bool(ca & 32)
        except ValueError:
            pass

        return telemetry

    def update_and_check_transitions(self, host_id, raw_txt):
        """
        Updates the internal state engine and returns details ONLY if a state transition occurred.
        """
        txt_dict = self.parse_txt_dict(raw_txt)
        telemetry = None

        # Route to appropriate extractor based on protocol signatures
        if "sf" in txt_dict or "deviceid" in txt_dict:
            telemetry = self.extract_apple_airplay(txt_dict)
        elif "fn" in txt_dict or "st" in txt_dict:
            telemetry = self.extract_google_cast(txt_dict)

        if not telemetry:
            return None

        # State Machine Transition Logic
        previous_record = self.state_registry.get(host_id)
        self.state_registry[host_id] = telemetry

        if previous_record:
            old_state = previous_record["state"]
            new_state = telemetry["state"]
            
            if old_state != new_state:
                return {
                    "event": "STATE_TRANSITION",
                    "host": host_id,
                    "protocol": telemetry["protocol"],
                    "device": telemetry["model"] if telemetry["protocol"] == "AirPlay" else telemetry["friendly_name"],
                    "from_state": old_state,
                    "to_state": new_state,
                    "flags": telemetry["flags"]
                }
        else:
            return {
                "event": "INITIAL_DISCOVERY",
                "host": host_id,
                "protocol": telemetry["protocol"],
                "device": telemetry["model"] if telemetry["protocol"] == "AirPlay" else telemetry["friendly_name"],
                "from_state": None,
                "to_state": telemetry["state"],
                "flags": telemetry["flags"]
            }
        
        return None
