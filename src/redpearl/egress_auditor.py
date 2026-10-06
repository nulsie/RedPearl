import asyncio
import json
import sys
from typing import List, Dict, Any
from stealth_engine import StealthProfileEngine

class EgressAuditor:
    """
    An efficient, sudoless egress auditor that utilizes asyncio 
    to rapidly map allowed outbound paths through a network firewall.
    """
    def __init__(self, public_target: str = "1.1.1.1", timeout: float = 2.0, max_concurrency: int = 100, stealth_engine=None):
        self.target = public_target
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        # Common egress / high-probability reverse shell ports

        self.stealth = stealth_engine if stealth_engine else StealthProfileEngine(target_profile="windows_workstation")

        self.default_ports = [
            21, 22, 23, 25, 53, 80, 139, 443, 445, 
            1433, 3306, 3389, 8080, 8443, 9001
        ]

    async def test_port(self, port: int, destination: str, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
        """
        Tests a single outbound port and analyzes the TCP handshake behavior,
        respecting the concurrency limit enforced by the semaphore.
        """
        result = {
            "port": port,
            "status": "Blocked",
            "reason": "Timeout / Dropped",
            "egress_allowed": False
        }
        
        # Acquire a slot from the semaphore before opening a socket
        async with semaphore:
            try:
                # Connect using the dynamically resolved destination, not a static target
                coro = asyncio.open_connection(destination, port) 
                reader, writer = await asyncio.wait_for(coro, timeout=self.timeout)
    
                # If we reach here, the port is open and allowed
                result.update({
                    "status": "Open",
                    "reason": "Handshake Successful",
                    "egress_allowed": True
                })
                writer.close()
                await writer.wait_closed()
                
            except ConnectionRefusedError:
                # CRITICAL: The firewall allowed the packet out, but the target refused it.
                result.update({
                    "status": "Closed but Allowed",
                    "reason": "Received TCP RST (No Firewall Block)",
                    "egress_allowed": True
                })
                
            except asyncio.TimeoutError:
                # Packet was silently dropped by a firewall
                pass
                
            except OSError as e:
                result["reason"] = f"OS Error: {str(e)}"
                
        return result

    async def run(self, custom_ports: List[int] = None, target_average_delay: float = 0.2) -> List[Dict[str, Any]]:
        ports_to_scan = custom_ports if custom_ports else self.default_ports
        completed_tasks = []
        sem = asyncio.Semaphore(self.max_concurrency)
                
        for port in ports_to_scan: # FIX: Changed 'ports' to 'ports_to_scan'
            # Now this will successfully pull from stealth_engine.py
            destination_ip = self.stealth.resolve_egress_target(port)
    
            # FIX: Pass the resolved destination_ip to test_port
            task = asyncio.create_task(self.test_port(port, destination_ip, sem))
            completed_tasks.append(task) # FIX: Append the 'task', not 'result'
                    
            if target_average_delay > 0:
                # Now the Poisson math will actually calculate the delay
                entropy_sleep = self.stealth.get_poisson_delay(target_average_delay)
                await asyncio.sleep(entropy_sleep)
                        
        return await asyncio.gather(*completed_tasks)

# --- Framework Integration / Standalone Execution ---
if __name__ == "__main__":
    auditor = EgressAuditor(timeout=1.5, max_concurrency=10, profile="windows_workstation")
    
    print("[*] Launching Integrated Stealth Egress Audit...")
    # Target an average of 1.2 seconds between queries using Poisson delays
    scan_results = asyncio.run(auditor.run(target_average_delay=1.2))
    
    print("\n=== STEALTH EGRESS AUDIT REPORT ===")
    for r in scan_results:
        if r["egress_allowed"]:
            print(f"[+] Outbound Access Allowed -> {r['destination']}:{r['port']} ({r['reason']})")
