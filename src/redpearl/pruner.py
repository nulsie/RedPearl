# pruner.py
# new thing(v1.1.0): this creates a whitelist config(whitelist.json) that idifies noisy infra such as printers, network switches etc, and prunes them from active workflows, saving active thread resources and avoiding noisy firewall alarms
import json
import os
import logging

logger = logging.getLogger("RedPearl")

class OUIPruner:
    def __init__(self, whitelist_path="whitelist.json"):
        self.whitelist_path = whitelist_path
        # default infra vendors to suppress from active enterprise probing
        self.default_suppressed_vendors = {
            "cisco systems", "hewlett packard", "hp inc", "xerox", 
            "ricoh", "konica minolta", "lexmark", "brother industries",
            "aruba networks", "juniper networks", "axis communications",
            "apc by schneider electric", "cisco-linksys"
        }
        self.suppressed_vendors = self._load_whitelist()

    def _load_whitelist(self):
        if os.path.exists(self.whitelist_path):
            try:
                with open(self.whitelist_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    custom_vendors = data.get("suppressed_vendors", [])
                    return set(v.lower() for v in custom_vendors).union(self.default_suppressed_vendors)
            except Exception as e:
                logger.debug(f"[-] Failed to load enterprise whitelist: {e}")
        
        self._save_default_whitelist()
        return self.default_suppressed_vendors

    def _save_default_whitelist(self):
        try:
            data = {
                "description": "RedPearl Infrastructure Suppression Whitelist",
                "suppressed_vendors": list(self.default_suppressed_vendors)
            }
            with open(self.whitelist_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
        except Exception:
            pass

    def should_suppress_active_recon(self, vendor_name: str) -> bool:
        if not vendor_name or vendor_name == "Unknown Vendor":
            return False
        
        vendor_lower = vendor_name.lower()
        for suppressed in self.suppressed_vendors:
            if suppressed in vendor_lower:
                return True
        return False
