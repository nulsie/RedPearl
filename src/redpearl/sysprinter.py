import json
import os
import re

class FingerprintEngine:
    """
    An advanced heuristic engine for passive OS and device identification.
    Uses protocol stacking and identity-string analysis.
    """

    SIGNATURES = {
        "Apple": {
            "protocols": {"mDNS"},
            "strings": ["_airplay._tcp.local", "_airdrop._tcp.local", "_raop._tcp.local", 
                        "_apple-mobdev2._tcp.local", "_companion-link._tcp.local"],
            "vendors": ["Apple"]
        },
        "Windows": {
            "protocols": {"LLMNR", "NetBIOS-NS", "WS-Discovery"},
            "strings": ["microsoft", "ms-wbt-server", "workgroup", "wndp"],
            "vendors": ["Microsoft"]
        },
        "Android/Google": {
            "protocols": {"mDNS", "SSDP"},
            "strings": ["_googlecast._tcp.local", "chromecast", "android", "google home"],
            "vendors": ["Google"]
        },
        "Linux/IoT": {
            "protocols": {"SSDP", "mDNS"},
            "strings": ["linux/", "upnp/1.0", "posix", "openwrt", "tasmota", "esp32"],
            "vendors": ["Raspberry Pi", "Espressif", "Ubiquiti"]
        },
        "Gaming": {
            "protocols": {"SSDP", "mDNS"},
            "strings": ["playstation", "nintendo-switch", "xbox", "wiiu"],
            "vendors": ["Sony Interactive", "Nintendo"]
        },
        "Printers": {
            "protocols": {"mDNS", "SSDP", "WS-Discovery"},
            "strings": ["_ipp._tcp.local", "_printer._tcp.local", "pdl-datastream", "jetdirect"],
            "vendors": ["HP", "Canon", "Epson", "Brother", "Lexmark"]
        }
    }

    @classmethod
    def load_external_signatures(cls, filepath):
        """
        Appends user-defined signatures from a JSON file to the engine.
        Format expected: {"Category": {"protocols": [], "strings": [], "vendors": []}}
        """
        if not os.path.exists(filepath):
            print(f"[!] Signature file not found: {filepath}")
            return
    
        try:
            with open(filepath, 'r') as f:
                custom_data = json.load(f)
                
            for category, rules in custom_data.items():
                if category in cls.SIGNATURES:
                    # Append to existing category
                    cls.SIGNATURES[category]["protocols"].update(set(rules.get("protocols", [])))
                    cls.SIGNATURES[category]["strings"].extend(rules.get("strings", []))
                    cls.SIGNATURES[category]["vendors"].extend(rules.get("vendors", []))
                else:
                    # Add new category
                    cls.SIGNATURES[category] = {
                        "protocols": set(rules.get("protocols", [])),
                        "strings": rules.get("strings", []),
                        "vendors": rules.get("vendors", [])
                    }
            print(f"[+] Successfully merged custom signatures from {filepath}")
        except Exception as e:
            print(f"[!] Error loading custom signatures: {e}")

    @classmethod
    def identify(cls, data):
        """
        Calculates confidence scores for various OS/Device categories.
        """
        identity = data.get('Identity', '').lower()
        vendor = data.get('Vendor', '').lower()

        # FIX: Strip version suffixes (e.g. "_v4", "_v6") and normalize to upper case
        captured_protos = {p.upper() for p in data.get('Protocols', set())}
        
        scores = {category: 0 for category in cls.SIGNATURES}

        for category, rules in cls.SIGNATURES.items():
            # Rule 1: Protocol Stacking 
            rule_protos = {rp.upper() for rp in rules["protocols"]}

            matching_protos = [
                rp for rp in rule_protos 
                if any(rp in cp for cp in captured_protos)
            ]
            scores[category] += len(matching_protos) * 2

            # Rule 2: Identity String Matching
            if any(s in identity for s in rules["strings"]):
                scores[category] += 5

            # Rule 3: Vendor Matching
            if any(v.lower() in vendor for v in rules["vendors"]):
                scores[category] += 3

        # Return the category with the highest score
        best_fit = max(scores, key=scores.get)
        
        if scores[best_fit] == 0:
            return "Unknown System"
            
        # Specific sub-classification logic
        if best_fit == "Apple":
            if "iphone" in identity: return "Apple iOS (iPhone)"
            if "tv" in identity: return "Apple TV"
            return "macOS / Apple Device"

        if best_fit == "Linux/IoT":
            if "linux/" in identity:
                version = re.search(r'linux/(\d+\.\d+)', identity)
                return f"Linux Kernel {version.group(1)}" if version else "Linux IoT"
            return "Embedded Linux"

        if best_fit == "Gaming":
            if "playstation" in identity: return "Sony PlayStation"
            if "nintendo" in identity: return "Nintendo Switch"
            return "Gaming Console"

        return best_fit
