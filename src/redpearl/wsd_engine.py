import socket
import struct
import xml.etree.ElementTree as ET
import uuid
import logging
logger = logging.getLogger("RedPearl")
# Attempt to load defusedxml to block XXE and XML entity bombs safely.
# Falls back to native ElementTree if the library is missing.
try:
    import defusedxml.ElementTree as DET
    HAS_DEFUSED = True
except ImportError:
    HAS_DEFUSED = False

class WSDPassiveEngine:
    """
    Passively listens to WS-Discovery (UDP 3702) multicasts.
    Extracts UUIDs, hardware Types, Scopes, XAddrs, and infers OS context.
    """
    
    WSD_MCAST_GRP = '239.255.255.250'
    WSD_PORT = 3702

    def __init__(self, interface_ip='0.0.0.0', debug=False):
        self.interface_ip = interface_ip
        self.debug = debug
        self.sock = self._setup_socket()

    def _build_normalized_wsd_probe(self, probe_uuid: str) -> bytes:
        """
        Constructs a rigidly normalized, minified WS-Discovery Probe envelope.
        Prevents string-formatting artifacts from acting as IDS signatures.
        """
        # 1. Register Exact Namespaces to enforce strict prefixing
        namespaces = {
            "soap": "http://www.w3.org/2003/05/soap-envelope",
            "wsa": "http://www.w3.org/2005/08/addressing",
            "wsd": "http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01"
        }
            
        for prefix, uri in namespaces.items():
            ET.register_namespace(prefix, uri)
    
        # 2. Programmatically build the XML Tree
        envelope = ET.Element("{http://www.w3.org/2003/05/soap-envelope}Envelope")
            
        header = ET.SubElement(envelope, "{http://www.w3.org/2003/05/soap-envelope}Header")
            
        # Action
        action = ET.SubElement(header, "{http://www.w3.org/2005/08/addressing}Action")
        action.text = "http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01/Probe"
            
        # MessageID
        msg_id = ET.SubElement(header, "{http://www.w3.org/2005/08/addressing}MessageID")
        msg_id.text = f"urn:uuid:{probe_uuid}"
            
        # To
        to = ET.SubElement(header, "{http://www.w3.org/2005/08/addressing}To")
        to.text = "urn:docs-oasis-open-org:ws-dd:ns:discovery:2009:01"
    
        # Body
        body = ET.SubElement(envelope, "{http://www.w3.org/2003/05/soap-envelope}Body")
        probe = ET.SubElement(body, "{http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01}Probe")
    
        # 3. Serialize rigidly (minified, UTF-8, strict XML declaration)
        # short_empty_elements=True ensures <Probe /> instead of <Probe></Probe>
        xml_bytes = ET.tostring(envelope, encoding="utf-8", method="xml", short_empty_elements=True)
            
        # Prepend the strict XML declaration (ET.tostring doesn't always add it exactly how Windows does)
        return b'<?xml version="1.0" encoding="utf-8"?>' + xml_bytes

    def send_probe_flare(self):
        """
        Transmits a standard, unprivileged wildcard WS-Discovery Probe payload 
        to trigger active ProbeMatches responses from quiet Windows targets.
        """
        probe_uuid = str(uuid.uuid4())

        soap_payload = self._build_normalized_wsd_probe(probe_uuid)
            
        try:
            # Explicitly creating a clean, unprivileged outbound UDP socket 
            flare_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                
            # Allow multi-hop routing locally if bound to a nested virtual network bridge
            flare_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                
            if self.interface_ip != '0.0.0.0':
                flare_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.interface_ip))
                    
            if self.debug:
                print(f"[*] Transmitting active WS-Discovery Flare [ID: {probe_uuid}] to {self.WSD_MCAST_GRP}:{self.WSD_PORT}")
                    
            flare_sock.sendto(soap_payload, (self.WSD_MCAST_GRP, self.WSD_PORT))
            flare_sock.close()
        except Exception as e:
            if self.debug:
                import sys
                print(f"[!] Warning: Failed to emit WS-Discovery flare: {e}", file=sys.stderr)

    def send_unicast_resolve(self, target_ip, target_uuid):
        """
        Transmits a targeted unicast WS-Discovery Resolve envelope directly to a host.
        Blocks for a short timeout to catch the direct point-to-point ResolveMatches reply.
        """
        import uuid

        probe_uuid = str(uuid.uuid4())

        soap_payload = self._build_normalized_wsd_probe(probe_uuid)
    
        try:
            # Establish a short-lived ephemeral UDP socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2.5) # Dynamic boundary allowance for high latency links
                    
                if self.interface_ip and self.interface_ip != '0.0.0.0':
                    try:
                        sock.bind((self.interface_ip, 0))
                    except Exception as e:
                        logger.debug(f"Subprocess fallback failed: {e}", exc_info=True)
                    
                if self.debug:
                    print(f"[*] [Coercion Engine] Directing active unicast Resolve hook to {target_ip}:{self.WSD_PORT}")
                    
                # Transmit explicitly to the target host's IP address
                sock.sendto(soap_payload, (target_ip, self.WSD_PORT))
                    
                # Capture the exclusive unicast response directly on this thread
                data, addr = sock.recvfrom(65535)
                return data, addr
                    
        except socket.timeout:
            if self.debug:
                print(f"[-] [Coercion Engine] Target {target_ip} failed to return ResolveMatches within timeout.")
        except Exception as e:
            if self.debug:
                print(f"[!] [Coercion Engine] Transaction pipeline failure for {target_ip}: {e}")
                    
        return None, None

    def _setup_socket(self):
        """Binds to 3702. Naturally sudoless since port > 1024."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        if hasattr(socket, 'SO_REUSEPORT'):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except socket.error:
                pass

        sock.bind(('', self.WSD_PORT))

        # Join the multicast group
        mreq = struct.pack("4s4s", socket.inet_aton(self.WSD_MCAST_GRP), socket.inet_aton(self.interface_ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setblocking(False)
        return sock

    def parse_wsd_payload(self, raw_data, addr):
        """
        Parses the SOAP XML envelope securely using universal namespace wildcards.
        """
        try:
            # Secure parsing choice: defusedxml strictly blocks malicious expansion entities.
            if HAS_DEFUSED:
                root = DET.fromstring(raw_data)
            else:
                root = ET.fromstring(raw_data)
            
            telemetry = {
                "ip": addr[0],
                "event_type": "Unknown",
                "uuid": None,
                "types": [],
                "xaddrs": [],
                "inferred_os": "Unknown"
            }

            # 1. Determine Event Type using universal namespace wildcard ({*})
            action_elem = root.find('.//{*}Action')
            if action_elem is not None and action_elem.text:
                action = action_elem.text.lower()
                if "hello" in action: telemetry["event_type"] = "Hello (Device Online)"
                elif "bye" in action: telemetry["event_type"] = "Bye (Device Offline)"
                elif "probe" in action: telemetry["event_type"] = "Probe (Active Searcher)"

            # 2. Extract UUID via deep wildcard matching
            address_elem = root.find('.//{*}EndpointReference/{*}Address')
            if address_elem is not None and address_elem.text:
                telemetry["uuid"] = address_elem.text.replace("urn:uuid:", "")

            # 3. Extract Hardware Categories (Types)
            types_elem = root.find('.//{*}Types')
            if types_elem is not None and types_elem.text:
                telemetry["types"] = types_elem.text.split()
                self._infer_os_from_types(telemetry)

            # 4. Extract Service URLs (XAddrs)
            xaddrs_elem = root.find('.//{*}XAddrs')
            if xaddrs_elem is not None and xaddrs_elem.text:
                telemetry["xaddrs"] = xaddrs_elem.text.split()

            # 5. Extract Message ID for tracking duplicate multicasts
            msg_id_elem = root.find('.//{*}MessageID')
            if msg_id_elem is not None:
                telemetry["message_id"] = msg_id_elem.text

            return telemetry

        except (ET.ParseError, ValueError, LookupError):
            # Gracefully catches malformed structures, bad encodings, or invalid characters
            if self.debug: print(f"[-] Malformed or Malicious WS-D SOAP from {addr[0]}")
            return None
        except Exception as e:
            if self.debug: print(f"[-] WS-D Engine Exception: {e}")
            return None

    def _infer_os_from_types(self, telemetry):
        """
        Uses heuristic stacking on WS-D 'Types' to infer the OS/Hardware context.
        """
        types_str = " ".join(telemetry["types"]).lower()
        
        if "pub:computer" in types_str or "ms-wbt-server" in types_str:
            telemetry["inferred_os"] = "Windows (Workstation/Server)"
        elif "networkvideotransmitter" in types_str or "onvif" in types_str:
            telemetry["inferred_os"] = "IoT Linux (ONVIF Camera)"
        elif "printdevice" in types_str or "printer" in types_str:
            telemetry["inferred_os"] = "Network Printer"

    def fileno(self):
        """Exposes the socket file descriptor for the async event loop."""
        return self.sock.fileno()


if __name__ == "__main__":
    import select
    
    print("[*] Starting hardened passive WS-Discovery Listener...")
    if not HAS_DEFUSED:
        print("[!] Warning: 'defusedxml' package missing. Running with standard standard parsing rules.")
        
    engine = WSDPassiveEngine(debug=True)
    
    try:
        while True:
            r, _, _ = select.select([engine.sock], [], [])
            for sock in r:
                data, addr = sock.recvfrom(65536)
                result = engine.parse_wsd_payload(data, addr)
                if result and result.get("uuid"):
                    print(f"\n[+] WS-D Target: {result['ip']}")
                    print(f"    Event: {result['event_type']}")
                    print(f"    UUID:  {result['uuid']}")
                    print(f"    Types: {', '.join(result['types'])}")
                    print(f"    URLs:  {', '.join(result['xaddrs'])}")
                    print(f"    OS:    {result['inferred_os']}")
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
