import os
import subprocess
import platform
import re
import logging
logger = logging.getLogger("RedPearl")

class NeighborCacheResolver:
    """
    A standalone helper to extract IPv4 (ARP) and IPv6 (NDP) neighbor tables.
    Implements cascading fallbacks to ensure maximum compatibility across environments.
    """

    @classmethod
    def get_mac_mapping(cls):
        """Returns a unified dictionary mapping IP addresses to MAC addresses."""
        cache = {}
        os_type = platform.system().lower()

        try:
            if "windows" in os_type:
                cache.update(cls._get_windows_ipv4())
                cache.update(cls._get_windows_ipv6())
            elif "linux" in os_type or "darwin" in os_type:
                cache.update(cls._get_unix_ipv4())
                cache.update(cls._get_unix_ipv6())
        except Exception as e:
            logger.debug(f"Subprocess fallback failed: {e}", exc_info=True)

        return cache

    # ==========================================
    # UNIX / LINUX FALLBACKS
    # ==========================================

    @classmethod
    def _get_unix_ipv4(cls):
        cache = {}
        
        # Fallback 1: Direct Kernel File Read (Fastest, no subprocess overhead)
        if os.path.exists("/proc/net/arp"):
            try:
                with open("/proc/net/arp", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                            cache[parts[0]] = parts[3].lower()
                if cache: return cache
            except Exception as e:
                logger.debug(f"Subprocess fallback failed: {e}", exc_info=True)

        # Fallback 2: Modern IPRoute2
        try:
            out = subprocess.check_output(["ip", "neigh", "show"], stderr=subprocess.DEVNULL).decode(errors='ignore')
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    idx = parts.index("lladdr")
                    cache[parts[0]] = parts[idx + 1].lower()
            if cache: return cache
        except Exception as e:
            logger.debug(f"Subprocess fallback failed: {e}", exc_info=True)

        # Fallback 3: Legacy ARP Command
        try:
            out = subprocess.check_output(["arp", "-an"], stderr=subprocess.DEVNULL).decode(errors='ignore')
            for ip, mac in re.findall(r"\((.*?)\)\s+at\s+([0-9a-fA-F:]+)", out):
                cache[ip] = mac.lower()
        except Exception as e:
            logger.debug(f"Subprocess fallback failed: {e}", exc_info=True)

        return cache

    @classmethod
    def _get_unix_ipv6(cls):
        cache = {}
        
        # Fallback 1: Modern IPRoute2
        try:
            out = subprocess.check_output(["ip", "-6", "neigh", "show"], stderr=subprocess.DEVNULL).decode(errors='ignore')
            for line in out.splitlines():
                parts = line.split()
                if "lladdr" in parts:
                    idx = parts.index("lladdr")
                    if idx + 1 < len(parts):
                        ip_addr = parts[0]
                        mac_addr = parts[idx + 1]
                        cache[ip_addr] = mac_addr.lower()
            if cache: return cache
        except Exception as e:
            logger.debug(f"Subprocess fallback failed: {e}", exc_info=True)

        return cache

    # ==========================================
    # WINDOWS FALLBACKS
    # ==========================================

    @classmethod
    def _get_windows_ipv4(cls):
        cache = {}
        
        # Fallback 1: Standard ARP utility
        try:
            out = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL).decode(errors='ignore')
            for ip, mac in re.findall(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9a-fA-F-]+)\s+", out):
                cache[ip] = mac.replace('-', ':').lower()
            if cache: return cache
        except Exception as e:
            logger.debug(f"Subprocess fallback failed: {e}", exc_info=True)

        # Fallback 2: PowerShell Get-NetNeighbor (Handles newer Windows environments)
        try:
            cmd = "powershell -NoProfile -Command \"Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress, LinkLayerAddress\""
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode(errors='ignore')
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and "." in parts[0] and "-" in parts[1]:
                    cache[parts[0]] = parts[1].replace('-', ':').lower()
        except Exception as e:
            logger.debug(f"Subprocess fallback failed: {e}", exc_info=True)

        return cache

    @classmethod
    def _get_windows_ipv6(cls):
        cache = {}

        # Fallback 1: Standard Netsh
        try:
            out = subprocess.check_output(["netsh", "interface", "ipv6", "show", "neighbors"], stderr=subprocess.DEVNULL).decode(errors='ignore')
            for ip, mac in re.findall(r"([0-9a-fA-F:]+)\s+([0-9a-fA-F-]+)\s+\w+", out):
                if not ip.startswith("ff02"):
                    cache[ip] = mac.replace('-', ':').lower()
            if cache: return cache
        except Exception as e:
            logger.debug(f"Subprocess fallback failed: {e}", exc_info=True)

        # Fallback 2: PowerShell Get-NetNeighbor
        try:
            cmd = "powershell -NoProfile -Command \"Get-NetNeighbor -AddressFamily IPv6 | Select-Object IPAddress, LinkLayerAddress\""
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode(errors='ignore')
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and ":" in parts[0] and "-" in parts[1]:
                    if not parts[0].startswith("ff02"):
                        cache[parts[0]] = parts[1].replace('-', ':').lower()
        except Exception as e:
            logger.debug(f"Subprocess fallback failed: {e}", exc_info=True)

        return cache
