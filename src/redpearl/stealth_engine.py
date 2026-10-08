# stealth_engine.py
import random
import math
import socket

class StealthProfileEngine:
    def __init__(self, target_profile: str = "windows_workstation"):
        self.profile = target_profile
        
        # mapping scrutinized ports to high-reputation, native-looking endpoints
        self.egress_routing_matrix = {
            53: "8.8.8.8",            # google DNS
            80: "www.example.com",     # generic HTTP keep-alive
            443: "www.microsoft.com" if "windows" in target_profile else "www.ubuntu.com",
            123: "pool.ntp.org",       # network time protocol
            8443: "scans.io",          # common telemetry endpoint
            # fallback for generic/unmapped ports
            "default": "1.1.1.1" 
        }

    def get_poisson_delay(self, target_average: float, min_floor: float = 0.08) -> float:
        if target_average <= min_floor:
            return min_floor
        
        # lambda (rate parameter) is 1 / mean
        lambd = 1.0 / (target_average - min_floor)
        jittered_delay = random.expovariate(lambd) + min_floor
        
        # hard cap to ensure the scan doesn't hang indefinitely on statistical outliers
        return min(jittered_delay, target_average * 3.5)

    def resolve_egress_target(self, port: int) -> str:
        return self.egress_routing_matrix.get(port, self.egress_routing_matrix["default"])
        
