import struct

class ParsingError(Exception):
    """Custom exception to catch malicious, truncated, or malformed payloads safely."""
    pass


class DefensiveParser:
    """
    A hardened binary and text layout parser designed to withstand adversarial subnets,
    preventing Out-Of-Bounds (OOB) reads, ReDoS hangs, and infinite recursive pointer loops.
    """

    @staticmethod
    def safe_unpack(fmt: str, data: bytes, offset: int = 0) -> tuple:
        """
        Wraps struct.unpack with explicit size validation against the buffer boundaries.
        Prevents struct.error and IndexError exceptions from terminating event loops.
        """
        try:
            expected_size = struct.calcsize(fmt)
        except struct.error as e:
            raise ParsingError(f"Invalid format string '{fmt}': {e}")

        # Strict boundary enforcement
        if offset < 0 or offset >= len(data):
            raise ParsingError(f"Offset {offset} is out of bounds for data length {len(data)}")
        
        if len(data) - offset < expected_size:
            raise ParsingError(
                f"Truncated buffer payload: Format '{fmt}' requires {expected_size} bytes, "
                f"but only {len(data) - offset} bytes are available at offset {offset}."
            )

        try:
            return struct.unpack(fmt, data[offset:offset + expected_size])
        except struct.error as e:
            raise ParsingError(f"Decompression structural failure: {e}")

    @staticmethod
    def extract_printable_ascii(
        payload: bytes, 
        min_length: int = 15, 
        max_string_length: int = 256, 
        max_total_strings: int = 50
    ) -> list:
        """
        A linear, O(N) byte-walker that replaces regex matching (e.g., re.findall) on raw binary data.
        Eliminates Regular Expression Denial of Service (ReDoS) vulnerabilities.
        
        Enforces resource constraints on both length and overall quantity to block OOM attacks.
        """
        discovered_strings = []
        current_chunk = bytearray()
        
        for byte in payload:
            # Check for standard printable ASCII range [Space to Tilde]
            if 32 <= byte <= 126:
                if len(current_chunk) < max_string_length:
                    current_chunk.append(byte)
                else:
                    # Truncate strings that exceed limits to prevent memory exhaustion
                    if len(current_chunk) >= min_length:
                        discovered_strings.append(current_chunk.decode('ascii', errors='ignore'))
                    current_chunk = bytearray()
            else:
                # Boundary hit; evaluate the gathered printable sequence
                if len(current_chunk) >= min_length:
                    discovered_strings.append(current_chunk.decode('ascii', errors='ignore'))
                    if len(discovered_strings) >= max_total_strings:
                        break
                current_chunk = bytearray()
                
        # Catch lingering trailing strings
        if len(current_chunk) >= min_length and len(discovered_strings) < max_total_strings:
            discovered_strings.append(current_chunk.decode('ascii', errors='ignore'))

        return discovered_strings

    @staticmethod
    def safe_resolve_dns_pointer(data: bytes, initial_offset: int, max_depth: int = 5) -> tuple:
        """
        Parses a DNS-style compressed label chain while tracking tracking metrics 
        and depth to actively neutralize infinite pointer compression loops.
        
        Returns:
            tuple: (decoded_name_string, next_buffer_offset)
        """
        labels = []
        offset = initial_offset
        visited_offsets = set()
        depth = 0
        
        # Track whether we jumped so we can accurately return the original structural cursor
        first_jump_offset = None 

        while True:
            if depth > max_depth:
                raise ParsingError("Adversarial Pointer Nesting: Maximum recursion loop depth exceeded.")
            
            # Read single length byte
            length_bytes = DefensiveParser.safe_unpack("!B", data, offset)
            length = length_bytes[0]
            
            # Null byte means regular termination of the label chain
            if length == 0:
                offset += 1
                break
                
            # Check for DNS Pointer compression flags (top two bits set: 0xC0)
            if (length & 0xC0) == 0xC0:
                depth += 1
                pointer_bytes = DefensiveParser.safe_unpack("!H", data, offset)
                # Combine bytes and mask off the compression bits
                pointer_target = pointer_bytes[0] & 0x3FFF 
                
                if pointer_target in visited_offsets:
                    raise ParsingError("Infinite loop exploit detected via malicious recursive DNS tracking pointer.")
                
                visited_offsets.add(pointer_target)
                
                if first_jump_offset is None:
                    first_jump_offset = offset + 2
                    
                offset = pointer_target
                continue
            
            # Handle regular label lengths safely
            offset += 1
            if length > 63:
                raise ParsingError(f"Malformed layout: DNS label length field exceeds 63 bytes ({length}).")
                
            label_data = DefensiveParser.safe_unpack(f"{length}s", data, offset)
            labels.append(label_data[0].decode('utf-8', errors='ignore'))
            offset += length

        final_offset = first_jump_offset if first_jump_offset is not None else offset
        return ".".join(labels), final_offset
