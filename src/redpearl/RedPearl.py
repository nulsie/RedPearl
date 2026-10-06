import socket
import struct
import subprocess
import platform
import re
import threading
import time
import json
import urllib.request
import os
import sys
import select
import random
import logging
from urllib.parse import urlparse
from logging.handlers import RotatingFileHandler
import xml.etree.ElementTree as ET
import shlex

try:
    import defusedxml.ElementTree as DET
    HAS_DEFUSED = True
except ImportError:
    HAS_DEFUSED = False

import argparse
import copy
import asyncio
from sysprinter import FingerprintEngine
from mac_resolver import NeighborCacheResolver
from concurrent.futures import ThreadPoolExecutor
from mdns_state import MDNSTelemetryEngine
from wsd_engine import WSDPassiveEngine
from rdnsse import ReverseDNSSwarmEngine
from engagement_engine import ReactiveEngagementEngine
from egress_auditor import EgressAuditor
from defensive_parser import DefensiveParser, ParsingError
from stealth_engine import StealthProfileEngine

logger = logging.getLogger("RedPearl")

def setup_logger(debug_mode=False):
    logger = logging.getLogger("RedPearl")
    # Set the base level
    logger.setLevel(logging.DEBUG) 

    # 1. Console Handler (For clean operator output)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if debug_mode else logging.INFO)
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # 2. File Handler (For detailed debugging and stack traces)
    file_handler = RotatingFileHandler(
        "redpearl_session.log", 
        maxBytes=10 * 1024 * 1024, # 10 MB per file
        backupCount=5               # Keep last 5 files
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(module)s | %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger

class RedPearl:
    def __init__(self, config_file="protocols.json", passive_only=True, active_mac_resolve=False, interface_ip="0.0.0.0", debug=False, send_flare=False, send_wsd_flare=False, reverse_dns_swarm=False, target_resolver=False, egress_audit=False, egress_target="1.1.1.1", egress_ports=None):
        self.network_map = {}
        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix="REdPearlWorker")
        self.stealth_engine = StealthProfileEngine(target_profile="windows_workstation")

        self.passive_only = passive_only
        self.active_mac_resolve = active_mac_resolve
        self.interface_ip = interface_ip
        self.debug = debug
        self.send_flare = send_flare
        self.send_wsd_flare = send_wsd_flare

        self.egress_audit = egress_audit
        self.egress_target = egress_target
        self.egress_ports = egress_ports

        self.egress_lock = threading.Lock()
        self.audited_hosts = set()
        
        self.oui_db = self._load_or_fetch_oui()
        self.neighbor_cache = self._build_neighbor_cache()
        self.protocols = self._load_config(config_file)

        self.network_map = self._load_state()
        self.baseline_map = copy.deepcopy(self.network_map)
        self.netbios_sock = None
        self.telemetry_engine = MDNSTelemetryEngine()

        self.wsd_engine = WSDPassiveEngine(interface_ip=self.interface_ip, debug=self.debug)

        self.reverse_dns_swarm = reverse_dns_swarm
        self.target_resolver = target_resolver
        self.dns_engine = ReverseDNSSwarmEngine()
        self.dns_dispatched = set()
        self.coerced_targets = set()
        self.engagement_engine = ReactiveEngagementEngine(
            executor=self.executor, 
            debug=self.debug,
            active_fetch=(not self.passive_only),
            stealth_engine=self.stealth_engine
        )
  
        if platform.system().lower() != "windows" and os.getuid() != 0 and self.debug:
            sys.stderr.write("[*] Running in non-root environment. NetBIOS listening may require explicit --send-flare to trigger responses.\n")

        if not self.passive_only:
            print("[!] WARNING: Pure passivity disabled. Engine will perform active HTTP requests for UPnP/SSDP endpoints.")
         
    def _load_config(self, filepath):
        try:
            with open(filepath, 'r') as f:
                config = json.load(f)
                return config.get("protocols", {})
        except Exception as e:
            logger.debug(f"[!] Error loading config: {e}\n")
            return {}

    def _poke_ip(self, target_ip):
        """Forces the OS to trigger an ARP or NDP request via dummy UDP transmission with randomized jitter."""
        try:
            # Use mDNS (5353) to blend into normal discovery traffic
            target_port = 5353 
            payload = b'\x00'
                
            if ":" in target_ip:
                poke_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            else:
                poke_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    
            for _ in range(3):
                poke_sock.sendto(payload, (target_ip, target_port))

                delay = self.stealth_engine.get_poisson_delay(target_average=0.25)
                time.sleep(delay)
                    
            poke_sock.close()
        except Exception as e:
            logger.debug(f"[-] Poke failed for {target_ip}: {e}\n")

    def _run_egress_audit(self, target_ip):
        """Worker thread entry-point to execute the paced egress auditor against a discovered endpoint."""
        # Use a mutual exclusion lock to guarantee only one host undergoes auditing at a time
        with self.egress_lock:
            if self.debug:
                sys.stderr.write(f"[*] Starting targeted egress analysis against newly discovered host: {target_ip}\n")
                    
            # Instantiate the auditor dynamically using the discovered internal/external IP
            auditor = EgressAuditor(
                public_target=target_ip, 
                timeout=1.5,
                stealth_engine=self.stealth_engine # <--- Pass the instance
            )
                    
            try:
                # Execute sequentially with a 200ms delay between port connections
                results = asyncio.run(auditor.run(custom_ports=self.egress_ports, target_average_delay=0.2))
                allowed_paths = [r for r in results if r["egress_allowed"]]
                allowed_ports = [r["port"] for r in allowed_paths]
                        
                # Safe thread-bound modification of the main map object
                with self.lock:
                    if target_ip in self.network_map:
                        if "Attributes" not in self.network_map[target_ip]:
                            self.network_map[target_ip]["Attributes"] = {}
                        self.network_map[target_ip]["Attributes"]["egress_telemetry"] = {
                            "open_ports": allowed_ports,
                            "total_tested": len(results),
                            "timestamp": time.time()
                        }
                        
                print(f"\n[+] HOST-SPECIFIC AUDIT COMPLETE: {target_ip}")
                print(f"    Accessible Paths: {allowed_ports if allowed_ports else 'None (Strict Boundary Enforcement)'}\n")
                        
            except Exception as e:
                if self.debug:
                    sys.stderr.write(f"[-] Targeted Egress Auditor runtime error for {target_ip}: {e}\n")

    def _execute_coercion_worker(self, target_ip, target_uuid):
        """Asynchronous worker container handled by the REdPearl pool."""
        if self.debug:
            sys.stderr.write(f"[*] [Worker] Initiating coercion handshake sequence for {target_ip}\n")
                
        data, addr = self.wsd_engine.send_unicast_resolve(target_ip, target_uuid)
            
        if data and addr:
            # Feed the unicast response cleanly back into the  framework pipeline!
            # It will get completely unpacked, and update the UI display mapping automatically.
            self._process_packet(data, addr, "WS-Discovery", "wsd_advanced")

    @staticmethod
    def _extract_mdns_txt_records(payload: bytes) -> dict:
        txt_metadata = {}
        if len(payload) < 12:
            return txt_metadata
        
        try:
            # 1. Unpack Header Safely
            header = DefensiveParser.safe_unpack('!HHHHHH', payload, 0)
            _, flags, qdcount, ancount, nscount, arcount = header
            offset = 12
        
            # 2. Skip Question Section using the safe pointer resolver
            for _ in range(qdcount):
                _, offset = DefensiveParser.safe_resolve_dns_pointer(payload, offset)
                offset += 4  # Skip QTYPE and QCLASS
        
            # 3. Parse Records
            total_records = ancount + nscount + arcount
            for _ in range(total_records):
                if offset >= len(payload):
                    break
        
                # Skip the Record Name safely
                _, offset = DefensiveParser.safe_resolve_dns_pointer(payload, offset)
        
                # Read Record Header safely
                rtype, rclass, ttl, rdlength = DefensiveParser.safe_unpack('!HHIH', payload, offset)
                offset += 10
        
                if offset + rdlength > len(payload):
                    break
        
                rdata = payload[offset:offset+rdlength]
                offset += rdlength
        
                if rtype == 16:  # TXT Record
                    txt_offset = 0
                    while txt_offset < len(rdata):
                        txt_str_len = rdata[txt_offset]
                        txt_offset += 1
                            
                        if txt_offset + txt_str_len <= len(rdata):
                            raw_string = rdata[txt_offset:txt_offset+txt_str_len]
                            try:
                                decoded_str = raw_string.decode('utf-8', errors='ignore')
                                if '=' in decoded_str:
                                    key, value = decoded_str.split('=', 1)
                                    txt_metadata[key.lower().strip()] = value.strip()
                            except Exception:
                                pass
                        txt_offset += txt_str_len
        
        except ParsingError:
            pass # Catch DefensiveParser boundary and loop exceptions gracefully
        except Exception:
            pass
        
        return txt_metadata

    def _correlate_dual_stack(self):
        """
        Internal Correlation Layer: Scans the active network map to identify when 
        an IPv4 address and a Link-Local IPv6 address (fe80::/10) resolve to the 
        exact same physical MAC address. Unifies them into a single Identity Object.
        """
        with self.lock:
            # Group current map contents by MAC address to find multi-stack candidates
            mac_groups = {}
            for ip, data in list(self.network_map.items()):
                mac = data.get("MAC")
                if mac and mac != "Unknown MAC":
                    mac_groups.setdefault(mac, []).append((ip, data))
            
            for mac, entries in mac_groups.items():
                if len(entries) < 2:
                    continue
                        
                ipv4_candidate = None
                ipv6_candidate = None
                        
                # Separate the entries into IPv4 and Link-Local IPv6
                for ip, data in entries:
                    if ":" in ip:
                        if ip.lower().startswith("fe80:"):
                            ipv6_candidate = (ip, data)
                    else:
                        ipv4_candidate = (ip, data)
                        
                # If we have a dual-stack pair that hasn't been unified yet
                if ipv4_candidate and ipv6_candidate:
                    ip4, d4 = ipv4_candidate
                    ip6, d6 = ipv6_candidate
                            
                    # Check if they are already pointing to the exact same dictionary in memory
                    if d4 is not d6:
                        if self.debug:
                            sys.stderr.write(f"[*] Correlating stacks: Unifying {ip4} and {ip6} under MAC {mac}\n")
                                
                        # Construct the unified Identity Object
                        unified = {
                            "IPv4": ip4,
                            "IPv6": ip6,
                            "MAC": mac,
                            "Vendor": d4.get("Vendor") if d4.get("Vendor") != "Unknown Vendor" else d6.get("Vendor"),
                            "Protocols": d4.get("Protocols", set()).union(d6.get("Protocols", set())),
                            "Queries": d4.get("Queries", 0) + d6.get("Queries", 0),
                            "Attributes": d4.get("Attributes", {}).copy()
                        }
                                
                        # Merge passive payload attributes safely
                        unified["Attributes"].update(d6.get("Attributes", {}))
                                
                        # Heuristically select the highest-quality identity string
                        id4 = d4.get("Identity", "")
                        id6 = d6.get("Identity", "")
                        if "Unknown" in id4 and "Unknown" not in id6:
                            unified["Identity"] = id6
                        elif "Unknown" in id6 and "Unknown" not in id4:
                            unified["Identity"] = id4
                        else:
                            # Fallback to the longer, more descriptive name
                            unified["Identity"] = id4 if len(id4) >= len(id6) else id6
                                
                        # Retain telemetry state machines from whichever stack recorded them
                        for source_dict in (d4, d6):
                            if "State" in source_dict:
                                unified["State"] = source_dict["State"]
                                unified["TelemetryFlags"] = source_dict.get("TelemetryFlags", {})
                                unified["TelemetryProtocol"] = source_dict.get("TelemetryProtocol", "")
                                
                        # CRITICAL: Re-route map references to point to the exact same object
                        self.network_map[ip4] = unified
                        self.network_map[ip6] = unified
                                
                        print(f"\n[+] DUAL-STACK CORRELATION: Consolidated target context for {ip4} ⇄ {ip6} [{mac}]")

    def _verify_target_profiles(self):
        """
        Background task to refine target intelligence. Detects multi-stack 
        high-value targets and flags potential honeytokens or network deception.
        """
        time.sleep(5)
        while True:
            time.sleep(10)
                    
            with self.lock:
                # FIX: Cast to list() to prevent "dictionary changed size during iteration" errors
                for ip, current_data in list(self.network_map.items()):
                    if ip not in self.baseline_map:
                        continue
                                
                    old_profile = FingerprintEngine.identify(self.baseline_map[ip])
                    new_profile = FingerprintEngine.identify(current_data)
                            
                    # Ignore initial discovery transitions from Unknown
                    if "Unknown" in old_profile:
                        self.baseline_map[ip] = copy.deepcopy(current_data)
                        continue
                            
                    # Target profile has evolved or shifted
                    if old_profile != new_profile:
                        print(f"\n[+] RECON ADVANCEMENT: [{ip}]")
                        print(f"    └─ Identity Refined: {old_profile} ➔ {new_profile}")
                                
                        # Offensive Check: Identical hardware footprint, completely different OS signatures?
                        old_mac = self.baseline_map[ip].get("MAC", "")
                        new_mac = current_data.get("MAC", "")
                                
                        if old_mac == new_mac and old_mac != "":
                            # If the signature swings wildly (e.g., Apple to Windows or IoT to Enterprise)
                            # under the exact same MAC, it's a strong indicator of a honeypot script spinning up.
                            print(f"    └─ ALERT: Static MAC footprint with morphing signatures. Possible deception/honeypot segment.")
                                
                        # Sync the baseline to keep tracking transitions linearly
                        self.baseline_map[ip] = copy.deepcopy(current_data)

    def _fire_compliant_flare(self):
        """
        Transmits a single, un-targeted mDNS service enumeration query.
        Acts as a non-aggressive 'kickstart' to flood the multiplexer 
        with baseline responses instantly.
        """
        print("[*] Igniting compliant flare (Dual-Stack mDNS mass-query)...")
                
        # 1. Construct Raw DNS mDNS Query for _services._dns-sd._udp.local
        dns_header = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        qname = b'\x09_services\x07_dns-sd\x04_udp\x05local\x00'
        qinfo = struct.pack('!HH', 12, 1)
        payload = dns_header + qname + qinfo
        
        # Fire IPv4 mDNS Flare
        try:
            sock_v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_v4.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            if self.interface_ip and self.interface_ip not in ["0.0.0.0", "::"]:
                sock_v4.bind((self.interface_ip, 0))
            sock_v4.sendto(payload, ('224.0.0.251', 5353))
            sock_v4.close()
        except Exception as e:
            logger.debug(f"[-] IPv4 Flare failed: {e}\n")
        
        # Fire IPv6 mDNS Flare
        try:
            sock_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock_v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            sock_v6.sendto(payload, ('ff02::fb', 5353))
            sock_v6.close()
        except Exception as e:
            logger.debug(f"[-] IPv6 Flare failed: {e}\n")
    
        # === NEW: SUDOLESS ACTIVE NETBIOS FLARE ===
        if self.netbios_sock:
            if self.debug:
                sys.stderr.write("[*] Injecting active NetBIOS Node Status broadcast via ephemeral socket...\n")
                
            # Construct standard NetBIOS Wildcard Node Status Query payload
            netbios_header = b'\xa1\xb2\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            netbios_name = b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00' # "*" padded
            netbios_footer = b'\x00\x21\x00\x01' # Type: NS, Class: IN
            nb_payload = netbios_header + netbios_name + netbios_footer
    
            try:
                # We broadcast OUT of the exact socket registered to the asyncio loop.
                # Remote machines reply directly to our random unprivileged source port.
                self.netbios_sock.sendto(nb_payload, ('255.255.255.255', 137))
            except Exception as e:
                if self.debug:
                    sys.stderr.write(f"[-] Sudoless NetBIOS broadcast injection failed: {e}\n")

    def _build_neighbor_cache(self):
        """Delegates resolution to the robust multi-fallback resolver."""
        return NeighborCacheResolver.get_mac_mapping()

    def _neighbor_refresher(self):
        while True:
            new_data = self._build_neighbor_cache() 
                
            with self.lock:
                self.neighbor_cache.update(new_data)
                for ip, host_data in self.network_map.items():
                    if host_data["MAC"] == "Unknown MAC" and ip in self.neighbor_cache:
                        mac = self.neighbor_cache[ip]
                        host_data["MAC"] = mac
                        host_data["Vendor"] = self.get_vendor(mac)
                        print(f"[*] Latent Resolution: {ip} resolved to {mac} ({host_data['Vendor']})")

                self._correlate_dual_stack()
                
            time.sleep(5)

    def _execute_ptr_lookup_worker(self, target_ip):
        """Asynchronous execution container handled by REdPearlWorker pools."""
            
        # 1. Unprivileged CLDAP Active Directory Profiling
        cldap_data = self.dns_engine.query_cldap(target_ip)

        time.sleep(self.stealth_engine.get_poisson_delay(0.8)) 

        snmp_desc = ""
        # Cycle through standard enterprise defaults
        for comm in ["public", "private", "internal"]:
            snmp_desc = self.dns_engine.query_snmp(target_ip, community=comm)
            if snmp_desc:
                break # Stop iterating once we get a valid hardware footprint
            time.sleep(self.stealth_engine.get_poisson_delay(0.5))

        time.sleep(self.stealth_engine.get_poisson_delay(0.8))

        # 2. Traditional Inverse DNS PTR Swarm against Gateway
        resolved_name = None
        if self.target_resolver:
            logger.debug(f"[*] Dispatching PTR query for {target_ip} to resolver {self.target_resolver}\n")
            resolved_name = self.dns_engine.query_server(target_ip, self.target_resolver)
                    
        with self.lock:
            if target_ip not in self.network_map:
                return
                    
            # Process AD Profiling First (Enterprise Context Takes Priority)
            if cldap_data and cldap_data.get("is_dc"):
                indicators = cldap_data.get("indicators", [])
                    
                # Heuristically format the extracted Netlogon strings
                # Usually yields: [Forest/Domain, Hostname, AD Site Name]
                ad_context = " | ".join(indicators[:3]) 
                    
                self.network_map[target_ip]["Identity"] = f"Domain Controller [{ad_context}]"
                self.network_map[target_ip]["Protocols"].add("CLDAP")
                    
                if "Attributes" not in self.network_map[target_ip]:
                    self.network_map[target_ip]["Attributes"] = {}
                    
                # The final string in the sequence is typically the physical/logical AD Site configuration
                if len(indicators) > 2:
                    self.network_map[target_ip]["Attributes"]["ad_site"] = indicators[-1]
                        
                print(f"\n[!] ENTERPRISE ASSET: {target_ip} identified as Active Directory Domain Controller.")

            elif snmp_desc:
                old_identity = self.network_map[target_ip].get("Identity", "")
                            
                # Only override if the current identity isn't already highly descriptive
                if not old_identity or "Unknown" in old_identity or "Protocol" in old_identity:
                    # Truncate for a clean UI output
                    self.network_map[target_ip]["Identity"] = f"SNMP: {snmp_desc[:65]}..."
                            
                    self.network_map[target_ip]["Protocols"].add("SNMP")
                            
                    if "Attributes" not in self.network_map[target_ip]:
                        self.network_map[target_ip]["Attributes"] = {}
                    self.network_map[target_ip]["Attributes"]["sys_descr"] = snmp_desc[:120]
                            
                    print(f"\n[*] HARDWARE DISCOVERY: {target_ip} footprint extracted via SNMPv2c.")
            
            # Process Standard PTR Resolution Fallback
            if resolved_name:
                old_identity = self.network_map[target_ip].get("Identity", "")
                    
                # Only override the Identity if we didn't just label it as a Domain Controller
                if not old_identity or "Unknown" in old_identity or "Protocol" in old_identity:
                    self.network_map[target_ip]["Identity"] = f"DNS: {resolved_name}"
                    print(f"[*] Swarm Resolution Success: {target_ip} identified as '{resolved_name}' via inverse lookup.")
                    
                # Append the reverse domain as an attribute regardless
                if "Attributes" not in self.network_map[target_ip]:
                    self.network_map[target_ip]["Attributes"] = {}
                self.network_map[target_ip]["Attributes"]["reverse_dns"] = resolved_name
                    
                if self.debug and not cldap_data.get("is_dc"):
                    print(f"[*] Swarm Attribute Enriched: {target_ip} linked to record '{resolved_name}'")

    def _load_or_fetch_oui(self):
        txt_source = "oui.txt"
        cache_file = "mac_vendors.json"
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f: return json.load(f)
            except Exception: pass
        oui_dict = {}
        if os.path.exists(txt_source):
            try:
                with open(txt_source, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if "(hex)" in line:
                            parts = line.split("(hex)")
                            oui_dict[parts[0].strip().replace("-", "").upper()] = parts[1].strip()
                with open(cache_file, 'w') as f: json.dump(oui_dict, f)
                return oui_dict
            except Exception: pass
        return {"B827EB": "Raspberry Pi Foundation"} 

    def get_vendor(self, mac):
        if not mac or mac == "Unknown MAC": return "Unknown Vendor"
        prefix = mac.replace(':', '').replace('-', '').upper()[:6]
        return self.oui_db.get(prefix, "Unknown Vendor")

    def _extract_dns_hostname(self, payload):
        try:
            # Safely resolve starting right after the 12-byte DNS header
            hostname, _ = DefensiveParser.safe_resolve_dns_pointer(payload, initial_offset=12)
            return hostname if hostname else "Unknown"
        except ParsingError:
            return "Unknown"
        except Exception: 
            return "Unknown"

    def _extract_ssdp_info(self, payload):
        server_info = "SSDP Device"
        location_url = None
        
        try:
            text = payload.decode('utf-8', errors='ignore')
            for line in text.split('\r\n'):
                if line.lower().startswith('server:') or line.lower().startswith('user-agent:'):
                    server_info = line.split(':', 1)[1].strip()
                elif line.lower().startswith('location:'):
                    location_url = line.split(':', 1)[1].strip()
    
            if location_url and not self.passive_only:
                try:
                    parsed_url = urlparse(location_url)
                    host = parsed_url.hostname
                    port = parsed_url.port or 80
                    path = parsed_url.path if parsed_url.path else "/"
                    if parsed_url.query:
                        path += f"?{parsed_url.query}"
    
                    # 1. Rigidly Normalized HTTP GET (Mimicking Windows UPnP Crawler)
                    # Strict CRLF (\r\n) enforcement and native header ordering
                    normalized_req = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {host}:{port}\r\n"
                        f"Connection: Close\r\n"
                        f"User-Agent: WINDOWS, UPnP/1.0, MicroStack/1.0.1497\r\n"
                        f"Accept: text/xml, application/xml\r\n"
                        f"\r\n"
                    ).encode('ascii')
    
                    # 2. Dispatch via Raw Socket to avoid Python library fingerprints
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(2.0)
                        sock.connect((host, port))
                        sock.sendall(normalized_req)
    
                        response_data = bytearray()
                        while True:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            response_data.extend(chunk)
    
                    # 3. Extract the XML body from the HTTP response
                    parts = response_data.split(b"\r\n\r\n", 1)
                    if len(parts) == 2:
                        xml_body = parts[1]
                        
                        # 4. Safe XML Parsing (Defending against Honeypots)
                        parser = DET if HAS_DEFUSED else ET
                        root = parser.fromstring(xml_body)
                        
                        details, services = {}, set()
                        for elem in root.iter():
                            tag = elem.tag.split('}')[-1] 
                            if tag in ['friendlyName', 'modelName', 'modelNumber', 'serialNumber'] and elem.text:
                                details[tag] = elem.text.strip()
                            elif tag == 'serviceType' and elem.text:
                                parts = elem.text.split(':')
                                if len(parts) >= 4: services.add(parts[-2])
                                
                        id_parts = []
                        if 'friendlyName' in details: id_parts.append(details['friendlyName'])
                        elif 'modelName' in details: id_parts.append(details['modelName'])
                        if 'modelNumber' in details: id_parts.append(f"[Mod: {details['modelNumber']}]")
                        if 'serialNumber' in details: id_parts.append(f"[SN: {details['serialNumber']}]")
                        if services: id_parts.append(f"[Srv: {', '.join(list(services)[:3])}]")
                        
                        if id_parts: return " ".join(id_parts)
    
                except DET.ParseError if HAS_DEFUSED else ET.ParseError:
                    if self.debug:
                        import sys
                        sys.stderr.write(f"[-] Malformed or malicious XML ignored at {location_url}\n")
                except Exception as e:
                    if self.debug:
                        import sys
                        sys.stderr.write(f"[-] Active normalized fetch failed for {location_url}: {e}\n")
                        
            return server_info
        except Exception: 
            return "Unknown SSDP"

    def _extract_netbios_name(self, payload):
        if len(payload) < 45: return None
        try:
            encoded_name = payload[13:45]
            decoded = ""
            for i in range(0, len(encoded_name), 2):
                char_code = ((encoded_name[i] - 0x41) << 4) | (encoded_name[i+1] - 0x41)
                if char_code <= 32: break
                decoded += chr(char_code)
            return decoded.strip()
        except Exception: return None

    def _extract_wsd_info(self, payload):
        try:
            text = payload.decode('utf-8', errors='ignore')
            match = re.search(r'<(?:wsd:)?Address>(?:urn:uuid:)?([^<]+)', text)
            return f"WSD ID: {match.group(1)[:15]}" if match else "WSD Device"
        except Exception: return None

    def _extract_json_info(self, payload):
        try:
            data = json.loads(payload.decode('utf-8', errors='ignore'))
            return data.get('displayname') or data.get('host_int') or "JSON Service"
        except Exception: return None

    def _setup_multicast_socket(self, proto_name, mcast_grp, mcast_port):
        """Initializes, configures, and binds standard dual-stack sockets."""
        is_ipv6 = ":" in mcast_grp
        sock = socket.socket(socket.AF_INET6 if is_ipv6 else socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            
        # PIVOT FOR SUDOLESS PRIVILEGED PORTS
        is_ephemeral = False
        if platform.system().lower() != "windows" and mcast_port < 1024:
            if os.getuid() != 0:
                if self.debug:
                    sys.stderr.write(f"[*] Non-root: Pivoting {proto_name} from port {mcast_port} to ephemeral port.\n")
                mcast_port = 0  # Kernel dynamically assigns an unprivileged port (>1024)
                is_ephemeral = True
    
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except Exception: pass
    
            # Enable broadcast capabilities natively
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            except Exception: pass
    
            if is_ipv6:
                if platform.system().lower() == "windows":
                    bind_ip = self.interface_ip if ":" in self.interface_ip else "::"
                    sock.bind((bind_ip, mcast_port))
                else:
                    sock.bind(('::', mcast_port))
                    
                # Only join multicast groups if we are not running on an ephemeral port
                if not is_ephemeral:
                    if_idx = 0
                    if self.interface_ip and self.interface_ip not in ["0.0.0.0", "::"]:
                        try: if_idx = socket.if_nametoindex(self.interface_ip)
                        except OSError: if_idx = 0
                    mreq = socket.inet_pton(socket.AF_INET6, mcast_grp) + struct.pack("@I", if_idx)
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
            else:
                if platform.system().lower() == "windows":
                    bind_ip = self.interface_ip if ":" not in self.interface_ip else "0.0.0.0"
                    sock.bind((bind_ip, mcast_port))
                else:
                    sock.bind(('0.0.0.0', mcast_port))
                    
                # Only join multicast groups if we are not running on an ephemeral port
                if not is_ephemeral:
                    bind_interface = self.interface_ip if ":" not in self.interface_ip else "0.0.0.0"
                    mreq = struct.pack("4s4s", socket.inet_aton(mcast_grp), socket.inet_aton(bind_interface))
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    
            # Keep a reference to the NetBIOS socket so the flare can broadcast out of it
            if "netbios" in proto_name.lower():
                self.netbios_sock = sock
    
            return sock
                
        except PermissionError:
            print(f"[!] Permission Denied binding to port {mcast_port} for {proto_name}.")
            return None
        except OSError as e:
            if e.errno in [98, 10048]:
                print(f"[!] Port {mcast_port} busy. Skipping {proto_name}...")
            else:
                print(f"[!] Stack Initialization Failure for {proto_name}: {e}")
            return None

    def _process_packet(self, data, addr, proto_name, proto_type):
        """Processes collected socket buffers safely outside the main reading loop."""
        sender_ip = addr[0]
        if "%" in sender_ip:
            sender_ip = sender_ip.split("%")[0]
        
        if sender_ip.startswith("127.") or sender_ip == "::1":
            return

        device_attributes = {}
        
        if proto_type == "dns": identity = self._extract_dns_hostname(data)
        elif proto_type == "http": identity = self._extract_ssdp_info(data)
        elif proto_type == "netbios": identity = self._extract_netbios_name(data)
        elif proto_type == "json": identity = self._extract_json_info(data)

        elif proto_type == "wsd_advanced":
            wsd_result = self.wsd_engine.parse_wsd_payload(data, addr)
            if wsd_result and wsd_result.get("uuid"):
                # Use the inferred OS as the primary identity
                identity = f"{wsd_result['inferred_os']} [{wsd_result['event_type'][:5]}]"

                device_attributes["uuid"] = wsd_result["uuid"][:18] + "..."
                        
                if wsd_result["xaddrs"]:
                    device_attributes["url"] = wsd_result["xaddrs"][0][:25] 

                if not self.passive_only and "Hello" in wsd_result["event_type"]:
                    with self.lock:
                        if sender_ip not in self.coerced_targets:
                            self.coerced_targets.add(sender_ip)
                            # Dispatch to the worker thread immediately to avoid blocking the network loop
                            self.executor.submit(self._execute_coercion_worker, sender_ip, wsd_result["uuid"])

                if not self.passive_only:
                    # Pass the wsd_result to trigger the HTTP WSDL inspection
                    self.engagement_engine.route_engagement(wsd_result, sender_ip)

            else:
                identity = "WS-Discovery Device"
                
        elif proto_type == "soap": identity = self._extract_wsd_info(data) # Legacy fallback
        else: identity = f"Unknown Protocol ({proto_type})"
                
        if not identity or len(identity) < 2:
            identity = f"Unknown ({proto_name} Host)"
        
        # Intercept and harvest mDNS attributes passively
        if proto_name.startswith("mDNS"):
            device_attributes = self._extract_mdns_txt_records(data)
        
        with self.lock:
            if sender_ip not in self.network_map:
                mac_addr = self.neighbor_cache.get(sender_ip, "Unknown MAC")
        
                if mac_addr == "Unknown MAC" and self.active_mac_resolve:
                    self.executor.submit(self._poke_ip, sender_ip)
        
                vendor = self.get_vendor(mac_addr) 
                                                        
                self.network_map[sender_ip] = {
                    "Identity": identity,
                    "MAC": mac_addr,
                    "Vendor": vendor,
                    "Protocols": {proto_name},
                    "Queries": 1,
                    "Attributes": device_attributes
                }
                        
                # Enrich identity using high-precision passive attributes if they exist
                if "model" in device_attributes:
                    self.network_map[sender_ip]["Identity"] = f"Model: {device_attributes['model']}"
                elif "fn" in device_attributes:
                    self.network_map[sender_ip]["Identity"] = device_attributes["fn"]
                                        
                # FIX: Removed the 'if self.baseline_map' check so alerts fire on clean slate runs too
                if sender_ip not in self.baseline_map:
                        logger.warning(f"\n[!] DISCOVERY ALERT: New host [{sender_ip}] linked up via {proto_name} ({vendor})")
                                            
            else:
                self.network_map[sender_ip]["Queries"] += 1
                self.network_map[sender_ip]["Protocols"].add(proto_name)
                        
                if "Attributes" not in self.network_map[sender_ip]:
                    self.network_map[sender_ip]["Attributes"] = {}
                self.network_map[sender_ip]["Attributes"].update(device_attributes)
                        
                # Keep enriching identities as new text data fields streams in over time
                if "model" in device_attributes:
                    self.network_map[sender_ip]["Identity"] = f"Model: {device_attributes['model']}"
                elif "fn" in device_attributes:
                    self.network_map[sender_ip]["Identity"] = device_attributes["fn"]
                                        
                if self.network_map[sender_ip]["MAC"] == "Unknown MAC":
                    new_mac = self.neighbor_cache.get(sender_ip, "Unknown MAC")
                    if new_mac != "Unknown MAC":
                        self.network_map[sender_ip]["MAC"] = new_mac
                        self.network_map[sender_ip]["Vendor"] = self.get_vendor(new_mac)
                                
                old_identity = self.network_map[sender_ip]["Identity"]
                if "Unknown" in old_identity and "Unknown" not in identity:
                    self.network_map[sender_ip]["Identity"] = identity

            self._correlate_dual_stack()

            if self.egress_audit and sender_ip not in self.audited_hosts:
                self.audited_hosts.add(sender_ip)
                # Offloads safely to the  background pool; egress_lock manages the serial ordering
                self.executor.submit(self._run_egress_audit, sender_ip)
            
            # 2. Dispatch Unprivileged Inverse DNS PTR Swarm Task
            if self.reverse_dns_swarm and self.target_resolver:
                with self.lock:
                    if sender_ip not in self.dns_dispatched:
                        self.dns_dispatched.add(sender_ip)
                        self.executor.submit(self._execute_ptr_lookup_worker, sender_ip)

            if proto_name.startswith("mDNS") and device_attributes:
                telemetry_event = self.telemetry_engine.update_and_check_transitions(sender_ip, device_attributes)
                if telemetry_event:
                    self.network_map[sender_ip]["State"] = telemetry_event["to_state"]
                    self.network_map[sender_ip]["TelemetryFlags"] = telemetry_event["flags"]
                    self.network_map[sender_ip]["TelemetryProtocol"] = telemetry_event["protocol"]
                     
                    if telemetry_event["event"] == "STATE_TRANSITION":
                        print(f"\n[⇄] TELEMETRY TRANSITION: [{sender_ip}] ({telemetry_event['device']}) changed state: {telemetry_event['from_state']} ➔ {telemetry_event['to_state']}")
                    elif telemetry_event["event"] == "INITIAL_DISCOVERY":
                        print(f"\n[+] TELEMETRY DISCOVERY: [{sender_ip}] ({telemetry_event['device']}) initial state: {telemetry_event['to_state']}")        

                if not self.passive_only:
                    self.engagement_engine.route_engagement(telemetry_event, sender_ip)

    def _async_packet_receiver(self, sock, proto_name, proto_type):
        """Callback executed instantly by the event loop when data hits the socket kernel buffer."""
        try:
            # Expand buffer size to 65535 to prevent packet truncation under heavy loads
            data, addr = sock.recvfrom(65535)
                
            # If active fetching is enabled, offload the processing to a separate thread
            # to prevent blocking the core asyncio event loop.
            if not self.passive_only and proto_type == "http":
                self.executor.submit(self._process_packet, data, addr, proto_name, proto_type)
            else:
                self._process_packet(data, addr, proto_name, proto_type)

        except Exception as e:
            if self.debug:
                sys.stderr.write(f"[-] Async kernel read failure inside {proto_name}: {e}\n")
    
    def _run_async_loop(self, socket_registry):
        """Establishes a cross-platform event loop and registers low-level socket readers."""
        # Windows compatibility adjustment: ProactorEventLoop doesn't support add_reader() on raw sockets
        if platform.system().lower() == "windows":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
        for sock, (proto_name, proto_type) in socket_registry.items():
            # Configure socket to operate in non-blocking mode for the event loop
            sock.setblocking(False)
            loop.add_reader(sock, self._async_packet_receiver, sock, proto_name, proto_type)
    
        # Run the loop forever inside its background execution thread
        try:
            loop.run_forever()
        except Exception as e:
            if self.debug:
                sys.stderr.write(f"[-] Event loop encountered critical failure: {e}\n")
    
    def start_listeners(self):
        if not self.protocols: 
            return
                
        # Keep neighbor resolution tracking on its own periodic thread
        threading.Thread(target=self._neighbor_refresher, daemon=True).start()

        threading.Thread(target=self._verify_target_profiles, daemon=True).start()
            
        socket_registry = {}

        self.wsd_engine = WSDPassiveEngine(interface_ip=self.interface_ip, debug=self.debug)
        if hasattr(self.wsd_engine, 'sock') and self.wsd_engine.sock:
            # Tag it as 'wsd_advanced' so the packet processor knows how to route it
            socket_registry[self.wsd_engine.sock] = ("WS-Discovery", "wsd_advanced")
            print(f"[*] Listening on [{self.wsd_engine.WSD_MCAST_GRP}]:{self.wsd_engine.WSD_PORT} for WS-Discovery (Advanced)...")
        
        for name, details in self.protocols.items():
            sock = self._setup_multicast_socket(name, details['mcast_grp'], details['port'])
            if sock:
                socket_registry[sock] = (name, details.get('type', 'dns'))
                print(f"[*] Listening on [{details['mcast_grp']}]:{details['port']} for {name}...")
            
        if socket_registry:
            # Spin up the high-performance event loop container inside a background thread
            threading.Thread(target=self._run_async_loop, args=(socket_registry,), daemon=True).start()
            time.sleep(0.5)
    
        if self.send_flare:
            self._fire_compliant_flare()

        if self.send_wsd_flare:
            # Fire the active WS-Discovery flare through the sub-engine
            self.wsd_engine.send_probe_flare()

        if self.egress_audit:
            if self.debug:
                sys.stderr.write("[*] Scheduling Egress Auditor thread to executor pool...\n")
            self.executor.submit(self._run_egress_audit)

    def display_results(self):
        print("\n" + "="*145)
        print(" EXTENSIVE PASSIVE NETWORK MAP (CONSOLIDATED DUAL-STACK REALITY)")
        print("="*145)
        print(f"{'TARGET NETWORK ADDRESSES':<46} | {'MAC ADDRESS':<17} | {'VENDOR':<15} | {'OS/DEVICE CLASS':<20} | {'SERVICES'}")
        print("-" * 145)
                
        with self.lock:
            seen_object_ids = set()
            safe_entries = []
                
            for ip, data in self.network_map.items():
                obj_id = id(data)
                if obj_id in seen_object_ids:
                    continue  # Skip duplicate memory references to show one row per machine
                seen_object_ids.add(obj_id)
                    
                data_copy = data.copy()
                data_copy["Protocols"] = list(data["Protocols"])
                    
                # Format the dual-stack line layout
                if "IPv4" in data and "IPv6" in data:
                    display_ip = f"{data['IPv4']} / {data['IPv6']}"
                else:
                    display_ip = ip
                        
                safe_entries.append((display_ip, data_copy))
                    
        def sort_key(entry_tuple):
            data = entry_tuple[1]
            # Primary sort using IPv4 if available, fallback to IPv6 or string representation
            sort_target = data.get("IPv4") or data.get("IPv6") or entry_tuple[0]
            try:
                if ":" in sort_target:
                    return (1, socket.inet_pton(socket.AF_INET6, sort_target))
                return (0, socket.inet_pton(socket.AF_INET, sort_target))
            except Exception:
                return (2, sort_target.encode())
    
        for display_ip, data in sorted(safe_entries, key=sort_key):
            os_guess = FingerprintEngine.identify(data)
            protos_summary = ",".join(data['Protocols'])[:25]
            print(f"{display_ip:<46} | {data['MAC']:<17} | {data['Vendor'][:15]:<15} | {os_guess:<20} | {protos_summary}")
            if data['Identity'] and "Unknown" not in data['Identity']:
                print(f"    └─ Identity: {data['Identity'][:95]}")
            if data.get('Attributes'):
                attr_str = ", ".join([f"{k}:{v}" for k, v in data['Attributes'].items()])
                print(f"    └─ TXT Records: {attr_str[:120]}")
        print("="*145)

    def _load_state(self, filepath="network_state.json"):
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    for ip, details in data.items():
                        if isinstance(details.get("Protocols"), list):
                            details["Protocols"] = set(details["Protocols"])
                    return data
            except Exception: pass
        return {}
    
    def save_state(self, filepath="network_state.json"):
        try:
            export_data = {}
            with self.lock:
                for ip, details in self.network_map.items():
                    export_data[ip] = details.copy()
                    export_data[ip]["Protocols"] = list(details["Protocols"])
            with open(filepath, 'w') as f: json.dump(export_data, f, indent=4)
        except Exception: pass
        
def show_boot_screen():
    """Displays the initial ASCII art and console instructions."""
    # Clearing screen based on OS
    os.system('cls' if os.name == 'nt' else 'clear')
        
    banner = """
     ___        _ ___              _
    | _ \___ __| | _ \___ __ _ _ _| |
    |   / -_) _` |  _/ -_) _` | '_| |
    |_|_\___\__,_|_| \___\__,_|_| |_|
        
    [ RedPearl v1.0.0 ]
    [ Sudoless Passive-Aggressive Network Scalpel ]
    """
    print(banner)
    print("Type 'help' to see available commands or 'scan' to begin.")
    print("Example: scan --resolve-mac --send-flare\n")
    
def run_scan(args):
    """Executes the core RedPearl engine with the provided arguments."""
    logger = setup_logger(debug_mode=args.debug)
    
    if args.aess:
        FingerprintEngine.load_external_signatures(args.aess)
    
    target_dns = args.resolver
    if args.reverse_swarm and not target_dns:
        # Fallback estimation to standard local gateway defaults
        target_dns = "192.168.1.1" 
        if args.debug:
            sys.stderr.write(f"[*] No explicit resolver designated. Defaulting to standard gateway boundary target: {target_dns}\n")
    
    custom_egress_ports = None
    if args.egraud_ports:
        try:
            custom_egress_ports = [int(p.strip()) for p in args.egraud_ports.split(",")]
        except ValueError:
            sys.stderr.write("[-] CLI parsing error: --egraud-ports must be a comma-separated list of integers.\n")
            return
        
    mapper = RedPearl(
        passive_only=args.passive_only, 
        active_mac_resolve=args.resolve_mac, 
        interface_ip=args.interface,
        debug=args.debug,
        send_flare=args.send_flare,
        send_wsd_flare=args.send_wsd_flare,
        reverse_dns_swarm=args.reverse_swarm,
        target_resolver=target_dns,
        egress_audit=args.egraud,
        egress_target=args.egraud_target,
        egress_ports=custom_egress_ports
    ) 
        
    mapper.start_listeners()
    
    try:
        logger.info("[*] Engine processing... (Press Ctrl+C to halt scan and return to prompt)")
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Suspending listeners...")
    finally:
        mapper.display_results()
        mapper.save_state()
    
if __name__ == "__main__":
    # Standardize the argument parser so it can be reused inside the shell
    parser = argparse.ArgumentParser(description="RedPearl: Passive Dual-Stack Discovery", prog="scan")
    parser.add_argument("--interface", type=str, default="0.0.0.0", help="Local interface IP or system label name (e.g., eth0) to map bindings.")
    parser.add_argument("--xufetch", action="store_false", dest="passive_only", help="Break pure passivity to fetch active UPnP HTTP descriptions.")
    parser.add_argument("--resolve-mac", action="store_true", help="Force neighbor table generation via asynchronous discovery bursts.")
    parser.add_argument("--aess", type=str, help="External engine profile definitions path.")
    parser.add_argument("--send-flare", action="store_true", help="Transmit a non-aggressive, multi-stack mDNS service enumeration query to kickstart responses.")
    parser.add_argument("--send-wsd-flare", action="store_true", help="Transmit an active WS-Discovery Probe query to flush out stealthy Windows targets.")
    parser.add_argument("--debug", action="store_true", help="Output stream allocation errors to standard error stream.")
    parser.add_argument("--reverse-swarm", action="store_true", help="Launch unprivileged inverse DNS PTR query swarms against discovered assets.")
    parser.add_argument("--resolver", type=str, help="Target IP of local gateway or primary DNS server to query for dynamic DHCP records.")
    parser.add_argument("--egraud", action="store_true", help="Launch the async outbound firewall egress path security auditor.")
    parser.add_argument("--egraud-target", type=str, default="1.1.1.1", help="External public destination IP used for egress mapping.")
    parser.add_argument("--egraud-ports", type=str, help="Comma-separated custom TCP ports to validate (e.g., 22,53,443,9001).")
    
    show_boot_screen()
    
    # Interactive Console Loop
    while True:
        try:
            # Capture user input
            cmd_line = input("\033[91mredpearl>\033[0m ").strip()
            if not cmd_line:
                continue
    
            # shlex.split correctly handles spaces and quotes just like bash
            parts = shlex.split(cmd_line)
            cmd = parts[0].lower()
    
            if cmd in ['exit', 'quit']:
                print("[*] Terminating. Goodbye.")
                break
                
            elif cmd == 'help':
                print("\n=== RedPearl Console Commands ===")
                print("  scan [args]    - Launch the reconnaissance engine.")
                print("                   (Type 'scan -h' to see all mapping arguments)")
                print("  help           - Show this menu.")
                print("  clear          - Clear the terminal screen.")
                print("  exit, quit     - Exit the framework.\n")
                    
            elif cmd == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
    
            elif cmd == 'scan':
                try:
                    # Pass all arguments *after* the word 'scan' to argparse
                    args = parser.parse_args(parts[1:])
                    run_scan(args)
                except SystemExit:
                    # Argparse automatically raises SystemExit when it hits -h/--help or encounters a bad argument.
                    # Catching it prevents the entire interactive console from crashing.
                    continue
    
            else:
                print(f"[-] Unknown command: '{cmd}'. Type 'help' for available commands.")
    
        except KeyboardInterrupt:
            # Catching Ctrl+C at the main prompt so they don't accidentally kill the app
            print("\n[*] Type 'exit' to quit the console.")
        except Exception as e:
            print(f"[-] Console Error: {e}")
