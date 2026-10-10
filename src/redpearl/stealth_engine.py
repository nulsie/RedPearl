# stealth_engine.py
import random
import math
import socket
import time
import threading

# (v1.1.0) add(or change or smth idk): i added an adaptive token-bucket and jitter rate shaping for making 'blemding in' more monitored networks more suitable
class AdaptiveTokenBucket:
    def __init__(self, rate: float = 10.0, capacity: float = 20.0):
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.rate = float(rate)
        self.min_rate = 1.0       # floor rate to prevent complete stalling
        self.max_rate = 50.0      # ceiling rate for enterprise speed
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_refill = now

    def acquire(self, tokens: int = 1, timeout: float = 5.0) -> bool:
        start_time = time.time()
        while True:
            with self.lock:
                self._refill()
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True
            
            # check timeout
            if time.time() - start_time > timeout:
                return False
            
            # sleep briefly before retrying token acquisition
            time.sleep(0.05)

    def adjust_rate(self, congestion_detected: bool):
        with self.lock:
            if congestion_detected:
                # back off aggressively to prevent triggering IDS/IPS thresholds
                self.rate = max(self.min_rate, self.rate * 0.5)
            else:
                # slowly recover token generation rate
                self.rate = min(self.max_rate, self.rate * 1.1)


class StealthProfileEngine:
    def __init__(self, target_profile: str = "windows_workstation"):
        self.profile = target_profile
        
        # start the adaptive token bucket for enterprise pacing
        # default starting rate: 15 packets/sec with a burst capacity of 30
        self.token_bucket = AdaptiveTokenBucket(rate=15.0, capacity=30.0)

        # mapping scrutinized ports to high-reputation, native-looking endpoints
        self.egress_routing_matrix = {
            53: "8.8.8.8",            # google DNS
            80: "www.example.com",     # generic HTTP keep-alive
            443: "www.microsoft.com" if "windows" in target_profile else "www.ubuntu.com",
            123: "pool.ntp.org",       # network time protocol
            8443: "scans.io",          # common telemetry endpoint
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

    def pace_action(self, congestion_feedback: bool = False):
        # adapt bucket rate based on recent socket errors or timeouts
        self.token_bucket.adjust_rate(congestion_detected=congestion_feedback)
        
        # wait for token availability (blocks gracefully if limits are hit)
        self.token_bucket.acquire(tokens=1, timeout=3.0)
        
        # apply standard entropy sleep
        jitter = self.get_poisson_delay(target_average=0.15)
        time.sleep(jitter)

    def resolve_egress_target(self, port: int) -> str:
        return self.egress_routing_matrix.get(port, self.egress_routing_matrix["default"])
