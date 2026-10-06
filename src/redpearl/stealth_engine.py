# stealth_engine.py
import random
import math
import socket

class StealthProfileEngine:
    """
    Centralized stealth profile manager for SilentMapper.
    Controls timing entropy (Poisson processes) and destination diversification.
    """
    def __init__(self, target_profile: str = "windows_workstation"):
        self.profile = target_profile
        
        # Mapping scrutinized ports to high-reputation, native-looking endpoints
        self.egress_routing_matrix = {
            53: "8.8.8.8",            # Google DNS
            80: "www.example.com",     # Generic HTTP Keep-alive
            443: "www.microsoft.com" if "windows" in target_profile else "www.ubuntu.com",
            123: "pool.ntp.org",       # Network Time Protocol
            8443: "scans.io",          # Common telemetry endpoint
            # Fallback for generic/unmapped ports
            "default": "1.1.1.1" 
        }

    def get_poisson_delay(self, target_average: float, min_floor: float = 0.08) -> float:
        """
        Calculates a continuous exponential distribution delay interval 
        to accurately model a Poisson process, breaking frequency analysis signatures.
        """
        if target_average <= min_floor:
            return min_floor
        
        # Lambda (rate parameter) is 1 / mean
        lambd = 1.0 / (target_average - min_floor)
        jittered_delay = random.expovariate(lambd) + min_floor
        
        # Hard cap to ensure the scan doesn't hang indefinitely on statistical outliers
        return min(jittered_delay, target_average * 3.5)

    def resolve_egress_target(self, port: int) -> str:
        """
        Returns the appropriate dynamic target for a specific port to evade
        destination-concentration triggers in IDSs.
        """
        return self.egress_routing_matrix.get(port, self.egress_routing_matrix["default"])
        
