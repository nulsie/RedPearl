import asyncio
import socket
import struct
import random
import time
import sys
import threading
import ssl
import re
from urllib.parse import urlparse
from defensive_parser import DefensiveParser
from stealth_engine import StealthProfileEngine

class ReactiveEngagementEngine:
    """
    Takes telemetry events discovered by the passive/low-privilege scanners
    and fires real-time, interactive micro-engagements to prove boundary enforcement
    and protocol compliance without triggering traditional IDS alert sweeps.
    """
    def __init__(self, executor, debug=False, active_fetch=False, stealth_engine=None):
        self.debug = debug
        self.active_fetch = active_fetch
        self.tls_probed = set()
        self.loop = asyncio.new_event_loop()
        self.stealth = stealth_engine

        threading.Thread(target=self._run_async_loop, daemon=True).start()

    def _run_async_loop(self):
        """Keeps the async engine running infinitely in the background."""
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def route_engagement(self, event_data, target_ip):
        """Evaluates telemetry patterns to deploy a context-aware protocol flare."""
        if not event_data or not target_ip:
            return
    
        event_type = event_data.get("event")
        protocol = event_data.get("protocol")
        to_state = event_data.get("to_state")
    
        if protocol == "AirPlay" and to_state == "Streaming":
            if self.debug:
                sys.stderr.write(f"[*] ENGAGE: Target {target_ip} entered STREAMING state. Testing profile leak...\n")
            # Dispatch to the async loop
            asyncio.run_coroutine_threadsafe(self._engage_airplay_handshake_async(target_ip), self.loop)
    
        elif protocol == "WS-Discovery" or event_data.get("types"):
            xaddrs = event_data.get("xaddrs", [])
            if xaddrs:
                if self.debug:
                    sys.stderr.write(f"[*] ENGAGE: Target {target_ip} exposed SOAP Endpoint. Verifying network boundary...\n")
                # Dispatch to the async loop
                asyncio.run_coroutine_threadsafe(self._engage_wsd_endpoint_async(target_ip, xaddrs), self.loop)

        if self.active_fetch and target_ip not in self.tls_probed:
            self.tls_probed.add(target_ip)
            asyncio.run_coroutine_threadsafe(self._stealth_tls_dispatch(target_ip), self.loop)

    async def _stealth_tls_dispatch(self, target_ip):
        """Paces out the TLS harvesting probes to break scanning signatures."""
        for port in [443, 8443, 3389, 636]:
            # Fire the individual probe
            await self._engage_tls_harvesting_async(target_ip, port)
                
            # Apply the mathematically sound Poisson delay between probes
            if self.stealth:
                delay = self.stealth.get_poisson_delay(target_average=1.2)
                await asyncio.sleep(delay)

    async def _engage_tls_harvesting_async(self, target_ip, port):
        """
        Connects to a TLS endpoint, conducts the handshake, and extracts the raw X.509
        certificate bytes to parse Common Names (CN) and SANs without validating the chain.
        """
        try:
            # Create a blind context to ensure the handshake completes for self-signed certs
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    
            # Open a non-blocking TCP connection with a strict timeout
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port, ssl=context),
                timeout=2.0
            )
    
            # Retrieve the underlying SSL socket to grab the raw binary DER certificate
            ssl_sock = writer.get_extra_info('ssl_object')
            der_cert = None
            if ssl_sock:
                der_cert = ssl_sock.getpeercert(binary_form=True)
    
            # Drop the connection immediately. We don't want to send HTTP requests.
            writer.close()
            await writer.wait_closed()
    
            if der_cert:
                self._parse_raw_x509(target_ip, port, der_cert)
    
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError):
            pass # Port closed or not speaking TLS

    def _parse_raw_x509(self, target_ip, port, der_cert: bytes):
        decoded_strings = DefensiveParser.extract_printable_ascii(der_cert, min_length=4)
                
        extracted = set()
        for decoded in decoded_strings:
            if "." in decoded and not decoded.startswith(".") and not decoded.endswith("."):
                if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$', decoded):
                    if not any(noise in decoded.lower() for noise in ['rsa', 'sha256', 'pki', 'x509']):
                        extracted.add(decoded.lower())
        
        if extracted:
            print(f"\n[+] TLS METADATA HARVEST: {target_ip}:{port}")
            print(f"    └─ Internal Hostnames/SANs: {', '.join(list(extracted)[:4])}")

    async def _engage_airplay_handshake_async(self, target_ip):
        """
        Asynchronously simulates an ephemeral AirPlay pairing receiver socket to see if the target
        dynamically routes credentials or descriptive JSON headers across the current segment.
        """
        try:
            # Open a non-blocking TCP connection with a timeout to Port 7000
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, 7000), 
                timeout=2.0
            )
                
            # Send probe payload representing a harmless Info status request
            req = "GET /info HTTP/1.1\r\nUser-Agent: MediaControl/1.0\r\nConnection: close\r\n\r\n"
            writer.write(req.encode())
            await writer.drain()
                
            response_data = bytearray()
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                    if not chunk:
                        break
                    response_data.extend(chunk)
            except asyncio.TimeoutError:
                pass # Target closed transmission early or stopped responding
            finally:
                writer.close()
                await writer.wait_closed()
                    
            if b"Server: AirTunes" in response_data:
                print(f"[!] FLAGSHIP ENGAGEMENT SUCCESS: Verified dynamic pathway to active Apple asset {target_ip} on Port 7000 during active stream.")
        except Exception as e:
            if self.debug:
                sys.stderr.write(f"[-] AirPlay engagement bypass check failed for {target_ip}: {e}\n")

    async def _engage_wsd_endpoint_async(self, target_ip, xaddrs):
        """
        Asynchronously interrogates the discovered SOAP URL over unprivileged HTTP.
        """
        for url in xaddrs:
            if "http://" in url:
                try:
                    parsed_url = urlparse(url)
                    host_ip = parsed_url.hostname
                    port = parsed_url.port or 80
                    path = parsed_url.path if parsed_url.path else "/"
                    if parsed_url.query:
                        path += f"?{parsed_url.query}"
                    cleaned_host = parsed_url.netloc
    
                    # Open a non-blocking TCP connection with a timeout
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(host_ip, port), 
                            timeout=2.5
                        )
                    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                        continue # Skip silently if port is closed or drops
    
                    req = f"GET {path} HTTP/1.1\r\nHost: {cleaned_host}\r\nConnection: close\r\n\r\n"
                    writer.write(req.encode())
                    await writer.drain()
    
                    response_data = bytearray()
                    try:
                        while True:
                            # Non-blocking read with a timeout
                            chunk = await asyncio.wait_for(reader.read(4096), timeout=2.5)
                            if not chunk:
                                break
                            response_data.extend(chunk)
                    except asyncio.TimeoutError:
                        pass # Server stopped talking without sending FIN
                    finally:
                        writer.close()
                        await writer.wait_closed()
    
                    final_data = bytes(response_data)
                    if b"xml" in final_data or b"envelope" in final_data.lower():
                        print(f"[!] FLAGSHIP ENGAGEMENT SUCCESS: Extracted Live WS-Discovery metadata configuration directly from {target_ip} via {url}")
                        break
    
                except Exception as e:
                    if self.debug:
                        sys.stderr.write(f"[-] Async WSD engagement failed for {url}: {e}\n")
                    continue
