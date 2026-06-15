import socket
import struct


def format_bytes_to_hex_string(bytes_data):
    """Convert raw bytes to readable MAC address format (aa:bb:cc:dd:ee:ff)"""
    bytes_str = map('{:02x}'.format, bytes_data)
    return ':'.join(bytes_str)


def main():
    # STEP 1: OPEN THE UNFILTERED PIPELINE
    try:
        # 0x0003 corresponds to ETH_P_ALL (capture all link-layer protocols)
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("Error: You must run this script with sudo/root privileges!")
        return

    print("[-] Raw socket initialized. Listening for packets...\n")

    # STEP 2: THE INFINITE CAPTURE LOOP
    try:
        while True:
            raw_buffer, address_info = raw_socket.recvfrom(65535)

            # --- PARSE ETHERNET FRAME ---
            # Security Check: Ensure buffer has at least 14 bytes for Ethernet header
            if len(raw_buffer) < 14:
                continue

            ethernet_header_bytes = raw_buffer[0:14]
            dest_mac_raw, src_mac_raw, ethertype = struct.unpack('!6s6sH', ethernet_header_bytes)

            readable_dest_mac = format_bytes_to_hex_string(dest_mac_raw)
            readable_src_mac = format_bytes_to_hex_string(src_mac_raw)

            print("--- [ETHERNET FRAME] ---")
            print(f"Source MAC: {readable_src_mac}")
            print(f"Destination MAC: {readable_dest_mac}")

            # Check for standard IPv4 payload (0x0800)
            if ethertype == 0x0800:
                
                # --- PARSE IPv4 HEADER ---
                # Security Check: Ensure remaining buffer can accommodate minimum IP Header (20 bytes)
                if len(raw_buffer) < 34:
                    print("    [!] Malformed Packet: Truncated IP Header.")
                    print()
                    continue

                ip_header_bytes = raw_buffer[14:34]
                unpacked_ip = struct.unpack('!BBHHHBBH4s4s', ip_header_bytes)

                version_and_ihl = unpacked_ip[0]
                # Extract Internet Header Length (IHL) from the lower 4 bits
                ihl = version_and_ihl & 0xF
                # IHL represents the number of 32-bit (4-byte) words in the header
                ip_header_length = ihl * 4

                # Security Check: Standard IPv4 header must be at least 20 bytes
                if ip_header_length < 20 or len(raw_buffer) < (14 + ip_header_length):
                    print("    [!] Malformed Packet: Invalid IP Header Length.")
                    print()
                    continue

                protocol = unpacked_ip[6]
                raw_src_ip = unpacked_ip[8]
                raw_dest_ip = unpacked_ip[9]

                # Optimization: Use socket library for safer binary-to-string IP translation
                readable_src_ip = socket.inet_ntoa(raw_src_ip)
                readable_dest_ip = socket.inet_ntoa(raw_dest_ip)

                print("    --- [IPv4 PACKET] ---")
                print(f"    Source IP: {readable_src_ip}")
                print(f"    Destination IP: {readable_dest_ip}")
                print(f"    Protocol Number: {protocol}")

                # Check if protocol is TCP (6)
                if protocol == 6:
                    
                    # --- PARSE TCP SEGMENT ---
                    tcp_start_offset = 14 + ip_header_length
                    
                    # Security Check: Ensure there are at least 4 bytes available to read ports
                    if len(raw_buffer) < (tcp_start_offset + 4):
                        print("        [!] Malformed Packet: Truncated TCP Header ports.")
                        print()
                        continue

                    tcp_header_bytes = raw_buffer[tcp_start_offset : tcp_start_offset + 4]
                    src_port, dest_port = struct.unpack('!HH', tcp_header_bytes)

                    print("        --- [TCP SEGMENT] ---")
                    print(f"        Source Port: {src_port}")
                    print(f"        Destination Port: {dest_port}")

                else:
                    print("        --- [OTHER PROTOCOL] ---")
                    print("        Layer 4 protocol not parsed in this pass.")

            print()  # New line for the next captured packet

    except KeyboardInterrupt:
        print("\n[-] Packet capture stopped by user.")
        raw_socket.close()


if __name__ == "__main__":
    main()