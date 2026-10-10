import asyncio
import json
import sys
from typing import List, Dict, Any
from stealth_engine import StealthProfileEngine

class EgressAuditor:
    def __init__(self, public_target: str = "1.1.1.1", timeout: float = 2.0, max_concurrency: int = 100, stealth_engine=None):
        self.target = public_target
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        # common egress / high-probability reverse shell ports

        self.stealth = stealth_engine if stealth_engine else StealthProfileEngine(target_profile="windows_workstation")

        self.default_ports = [
            21, 22, 23, 25, 53, 80, 139, 443, 445, 
            1433, 3306, 3389, 8080, 8443, 9001
        ]

    async def test_port(self, port: int, destination: str, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
        result = {
            "port": port,
            "status": "Blocked",
            "reason": "Timeout / Dropped",
            "egress_allowed": False
        }
        
        # acquire a slot from the semaphore before opening a socket
        async with semaphore:
            try:
                # connect using the dynamically resolved destination, not a static target
                coro = asyncio.open_connection(destination, port) 
                reader, writer = await asyncio.wait_for(coro, timeout=self.timeout)
    
                # if we reach here, the port is open and allowed
                result.update({
                    "status": "Open",
                    "reason": "Handshake Successful",
                    "egress_allowed": True
                })
                writer.close()
                await writer.wait_closed()
                
            except ConnectionRefusedError:
                # CRITICAL: the firewall allowed the packet out, but the target refused it.
                result.update({
                    "status": "Closed but Allowed",
                    "reason": "Received TCP RST (No Firewall Block)",
                    "egress_allowed": True
                })
                
            except asyncio.TimeoutError:
                # packet was silently dropped by a firewall
                pass
                
            except OSError as e:
                result["reason"] = f"OS Error: {str(e)}"
                
        return result

    # refactored for v1.1.0 jitter rate shaping
    async def run(self, custom_ports: List[int] = None, target_average_delay: float = 0.2) -> List[Dict[str, Any]]:
        ports_to_scan = custom_ports if custom_ports else self.default_ports
        completed_tasks = []
        sem = asyncio.Semaphore(self.max_concurrency)
                    
        for port in ports_to_scan:
            destination_ip = self.stealth.resolve_egress_target(port)
        
            task = asyncio.create_task(self.test_port(port, destination_ip, sem))
            completed_tasks.append(task)
                        
            if target_average_delay > 0:
                # use the new async-safe enterprise rate shaper
                await self.stealth.pace_action_async(congestion_feedback=False)
                            
        return await asyncio.gather(*completed_tasks)

# --- framework integration / standalone execution ---
if __name__ == "__main__":
    auditor = EgressAuditor(timeout=1.5, max_concurrency=10, profile="windows_workstation")
    
    print("[*] Launching Integrated Stealth Egress Audit...")
    # target an average of 1.2 seconds between queries using poisson delays
    scan_results = asyncio.run(auditor.run(target_average_delay=1.2))
    
    print("\n=== STEALTH EGRESS AUDIT REPORT ===")
    for r in scan_results:
        if r["egress_allowed"]:
            print(f"[+] Outbound Access Allowed -> {r['destination']}:{r['port']} ({r['reason']})")
