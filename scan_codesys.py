import socket
import argparse
import string
import json


def get_local_ip(destination_ip):
    """Detect the local IP address used to reach the destination."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((destination_ip, 1))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None


def build_discovery_packet(local_ip):
    """
    Build the CODESYS UDP discovery packet.
    The 9th byte encodes the last octet of the source IP so the
    device knows which address to send its response to.
    
    Packet structure:
      c5 74        - CODESYS magic bytes
      40 03        - Discovery command
      00 20        - Length
      99 99        - Session ID
      03 XX        - XX = last octet of source IP (device replies to this IP)
      03 01        - Unknown
      02 c2        - Port 706 (CODESYS Gateway default port)
      00 04        - Unknown
      ee 77 00 00  - Unknown
    """
    last_octet = int(local_ip.split('.')[-1])
    payload = bytes([
        0xc5, 0x74,
        0x40, 0x03,
        0x00, 0x20,
        0x99, 0x99,
        0x03, last_octet,   # last octet of source IP — device replies to this address
        0x03, 0x01,
        0x02, 0xc2,
        0x00, 0x04,
        0xee, 0x77, 0x00, 0x00
    ])
    return payload


def parse_response(data, addr):
    """
    Parse a CODESYS discovery response.
    
    Fields are encoded as null-terminated strings starting at byte 60:
      - Device name, complete name, manufacturer : UTF-16 LE
      - MAC address                              : plain ASCII
    
    The parser detects encoding dynamically by checking whether
    the second byte of a sequence is 0x00 (UTF-16 pattern).
    """
    if len(data) <= 60:
        return None

    raw = data[60:]
    fields = []
    i = 0

    while i < len(raw) - 1:
        # UTF-16 LE detected: even byte is printable, odd byte is 0x00
        if i + 1 < len(raw) and raw[i + 1] == 0x00 and raw[i] != 0x00:
            # Read UTF-16 string until null terminator \x00\x00
            j = i
            while j + 1 < len(raw):
                if raw[j] == 0x00 and raw[j + 1] == 0x00:
                    break
                j += 2
            chunk = raw[i:j]
            try:
                decoded = chunk.decode('utf-16-le', errors='ignore').strip('\x00')
            except Exception:
                decoded = ''
            fields.append(decoded)
            i = j + 2  # skip the \x00\x00 terminator

        # Plain ASCII: read until single \x00
        elif raw[i] != 0x00:
            j = i
            while j < len(raw) and raw[j] != 0x00:
                j += 1
            chunk = raw[i:j]
            decoded = chunk.decode('ascii', errors='ignore')
            fields.append(decoded)
            i = j + 1  # skip the \x00 terminator

        else:
            i += 1  # skip isolated null byte

    return {
        "IP Address":    addr[0],
        "Device Name":   fields[0] if len(fields) > 0 else '',
        "Complete Name": fields[1] if len(fields) > 1 else '',
        "Manufacturer":  fields[2] if len(fields) > 2 else '',
        "MAC Address":   fields[3] if len(fields) > 3 else ''
    }


def discover(destination_ip, local_ip, display_format='table', timeout=3):
    """Send a discovery broadcast and collect responses until timeout."""
    payload = build_discovery_packet(local_ip)
    last_octet = int(local_ip.split('.')[-1])

    print(f"Local IP            : {local_ip} (last octet: 0x{last_octet:02X} = {last_octet})")
    print(f"Sending to          : {destination_ip}:1740")
    print(f"Listening on port   : 1743 ({timeout}s timeout)\n")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.bind(('', 1743))
    udp_socket.settimeout(timeout)

    # Send discovery packet
    udp_socket.sendto(payload, (destination_ip, 1740))

    messages = []
    try:
        while True:
            data, addr = udp_socket.recvfrom(512)
            result = parse_response(data, addr)
            if result:
                messages.append(result)
    except socket.timeout:
        pass
    finally:
        udp_socket.close()

    # Display results
    if display_format == 'json':
        print(json.dumps(messages, indent=2))
    else:
        headers = ["IP Address", "Device Name", "Complete Name", "Manufacturer", "MAC Address"]
        row_format = "{:<16} {:<20} {:<40} {:<20} {:<18}"
        print(row_format.format(*headers))
        print("─" * 116)
        for m in messages:
            print(row_format.format(
                m["IP Address"], m["Device Name"],
                m["Complete Name"], m["Manufacturer"], m["MAC Address"]
            ))
        if not messages:
            print("No CODESYS device detected.")
        else:
            print(f"\n{len(messages)} device(s) found.")


def main():
    parser = argparse.ArgumentParser(
        description='Discover CODESYS devices via UDP broadcast.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        'destination_ip',
        help="Target IP or broadcast address (e.g. 192.168.68.255)"
    )
    parser.add_argument(
        '--source-ip',
        default=None,
        help="Local IP to use as source (auto-detected if not specified)"
    )
    parser.add_argument(
        '--format', choices=['json', 'table'], default='table',
        help="Output format: table (default) or json"
    )
    parser.add_argument(
        '--timeout', type=int, default=3,
        help="Listening timeout in seconds (default: 3)"
    )
    args = parser.parse_args()

    # Resolve local IP
    if args.source_ip:
        local_ip = args.source_ip
        print(f"Source IP manually set: {local_ip}")
    else:
        local_ip = get_local_ip(args.destination_ip)
        if not local_ip:
            print("Could not detect local IP. Use --source-ip to specify it manually.")
            return

    discover(args.destination_ip, local_ip, args.format, args.timeout)


if __name__ == "__main__":
    main()
