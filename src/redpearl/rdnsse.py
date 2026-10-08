import socket
import struct
import random
import sys
import re
from defensive_parser import DefensiveParser, ParsingError
import logging
logger = logging.getLogger("RedPearl")

class ReverseDNSSwarmEngine:
    @staticmethod
    def ip_to_ptr_name(ip_address: str) -> str:
        if ":" in ip_address:
            # expand and reverse IPv6 to 32 hex nibbles for .ip6.arpa
            try:
                packed = socket.inet_pton(socket.AF_INET6, ip_address)
                nibbles = []
                for byte in packed:
                    # extract high and low nibbles
                    nibbles.append(f"{(byte >> 4) & 0x0F:x}")
                    nibbles.append(f"{byte & 0x0F:x}")
                return ".".join(reversed(nibbles)) + ".ip6.arpa"
            except Exception:
                return ""
        else:
            # reverse IPv4 octets for .in-addr.arpa
            parts = ip_address.split('.')
            if len(parts) == 4:
                return ".".join(reversed(parts)) + ".in-addr.arpa"
            return ""

    @staticmethod
    def build_dns_query(ptr_domain: str) -> bytes:
        tx_id = random.randint(1000, 65535)
        header = struct.pack('!HHHHHH', tx_id, 0x0100, 1, 0, 0, 0)
        
        # encode domain string into DNS label format
        query_name = b""
        for label in ptr_domain.split('.'):
            if label:
                encoded_label = label.encode('utf-8', errors='ignore')
                query_name += struct.pack('B', len(encoded_label)) + encoded_label
        query_name += b'\x00' # null terminator
        
        query_footer = struct.pack('!HH', 12, 1)
        return header + query_name + query_footer

    @staticmethod
    def parse_ptr_response(payload: bytes) -> str:
        try:
            if len(payload) < 12: return ""
    
            _, flags, qdcount, ancount, _, _ = DefensiveParser.safe_unpack('!HHHHHH', payload, 0)
                
            if (flags & 0x000F) != 0: return ""
    
            offset = 12
    
            for _ in range(qdcount):
                _, offset = DefensiveParser.safe_resolve_dns_pointer(payload, offset)
                offset += 4 
    
            for _ in range(ancount):
                if offset >= len(payload): break
                    
                _, offset = DefensiveParser.safe_resolve_dns_pointer(payload, offset) 
                    
                rtype, rclass, ttl, rdlength = DefensiveParser.safe_unpack('!HHIH', payload, offset)
                offset += 10
                    
                if offset + rdlength > len(payload): break
                    
                if rtype == 12:
                    hostname, _ = DefensiveParser.safe_resolve_dns_pointer(payload, offset)
                    if hostname:
                        return hostname
                    
                offset += rdlength
                    
        except ParsingError:
            pass
        except Exception as e:
            logger.debug(f"Subprocess fallback failed: {e}", exc_info=True)
            return ""

    def query_server(self, target_ip: str, dns_server: str, timeout: float = 1.5) -> str:
        ptr_domain = self.ip_to_ptr_name(target_ip)
        if not ptr_domain:
            return ""
            
        packet = self.build_dns_query(ptr_domain)
        server_addr = (dns_server, 53)
        
        # handle IPv6 destination server sockets dynamically
        sock_family = socket.AF_INET6 if ":" in dns_server else socket.AF_INET
        
        try:
            with socket.socket(sock_family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, server_addr)
                response, _ = sock.recvfrom(2048)
                return self.parse_ptr_response(response)
        except Exception:
            return ""

    def query_cldap(self, target_ip: str, timeout: float = 1.5) -> dict:
        # static ASN.1 BER encoded LDAP SearchRequest
        # Message ID: 1, Base DN: "", Scope: BaseObject, Filter: (objectClass=*), Attribute: netlogon
        cldap_payload = bytes.fromhex(
            "30840000002d02010163840000002404000a01000a0100020100020100010100870b6f626a656374636c61737330840000000a04086e65746c6f676f6e"
        )
            
        try:
            sock_family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
            with socket.socket(sock_family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                # send the LDAP ping directly to port 389 on the target
                sock.sendto(cldap_payload, (target_ip, 389))
                response, _ = sock.recvfrom(4096)
                    
                return self._parse_cldap_response(response)
        except Exception:
            return {}

    def _parse_cldap_response(self, payload: bytes) -> dict:
        try:
            decoded_strings = DefensiveParser.extract_printable_ascii(payload, min_length=4)
            filtered = []
                    
            for val in decoded_strings:
                if val.lower() not in ['netlogon', 'objectclass']: 
                    filtered.append(val)
                    
            unique_indicators = list(dict.fromkeys(filtered))
                    
            if unique_indicators:
                return {"is_dc": True, "indicators": unique_indicators}
        except Exception as e:
            logger.debug(f"Subprocess fallback failed: {e}", exc_info=True)
            return {}

    def query_snmp(self, target_ip: str, community: str = "public", timeout: float = 1.0) -> str:
        try:
            # dynamically encode the community string length for the ASN.1 sequence
            comm_bytes = community.encode('utf-8')
            comm_len = len(comm_bytes)
                
            # static VarBindList for 1.3.6.1.2.1.1.1.0 (sysDescr) + Null Value
            varbind_list = b'\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00'
                
            # generate random 32-bit Request ID
            req_id = struct.pack('!I', random.randint(1, 4294967295))
                
            # construct GetRequest PDU: tag (0xa0) + length (0x1c) + req_id + err_stat + err_index + varbinds
            pdu = b'\xa0\x1c\x02\x04' + req_id + b'\x02\x01\x00\x02\x01\x00' + varbind_list
                
            # construct final SNMP Message: Sequence + Version (1 = v2c) + Community + PDU
            msg_len = 3 + (2 + comm_len) + len(pdu)
            payload = b'\x30' + bytes([msg_len]) + b'\x02\x01\x01\x04' + bytes([comm_len]) + comm_bytes + pdu
    
            sock_family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
            with socket.socket(sock_family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                # dispatch to standard SNMP port 161
                sock.sendto(payload, (target_ip, 161))
                response, _ = sock.recvfrom(4096)
                    
                return self._parse_snmp_response(response, community)
        except Exception as e:
            logger.debug(f"Subprocess fallback failed: {e}", exc_info=True)
            return ""

    def _parse_snmp_response(self, payload: bytes, community: str) -> str:
        try:
            # replace ReDoS-prone regex with linear string extraction
            decoded_strings = DefensiveParser.extract_printable_ascii(payload, min_length=15)
                    
            for decoded in decoded_strings:
                decoded = decoded.strip()
                if decoded and decoded != community:
                    return decoded.replace('\r', ' ').replace('\n', ' ')
        except Exception as e:
            logger.debug(f"Subprocess fallback failed: {e}", exc_info=True)
            return ""
