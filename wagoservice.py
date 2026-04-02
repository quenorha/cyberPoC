import subprocess
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


def parse_payload(payload):
    """Parse semicolon-separated key=value pairs from device response."""
    parsed = {}
    for line in payload.split(';'):
        if '=' in line:
            key, value = line.split('=', 1)
            parsed[key.strip()] = value.strip()
    return parsed


def send_tcp_packet(ip_address, command, mac_address=''):
    """
    Send a command to a WAGO device on port 6626 and return parsed info.
    Commands: 'info' to query device details, 'restart' to reboot.
    """
    hex_data_mapping = {
        "restart": '8812320001000100000000000000000002000201',
        "info":    '8812020001000100000000000000000002000801'
    }

    if command not in hex_data_mapping:
        print(f"Unknown command '{command}'. Use 'info' or 'restart'.")
        return None

    packet_data = bytes.fromhex(hex_data_mapping[command])

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((ip_address, 6626))
            s.sendall(packet_data)
            response = s.recv(1024)

        ascii_response = response.decode('ascii', errors='replace')
        parsed_info = parse_payload(ascii_response)

        return {
            'ip':     ip_address,
            'mac':    mac_address,
            'psn':    parsed_info.get('PSN',    'N/A'),
            'sw_ver': parsed_info.get('SW-VER', 'N/A'),
            'sn':     parsed_info.get('SN',     'N/A')
        }

    except ConnectionRefusedError:
        return {'ip': ip_address, 'mac': mac_address, 'connection': 'refused'}
    except OSError as e:
        print(f"Error connecting to {ip_address}: {e}")
        return None


def discover_devices(network):
    """
    Use nmap to find hosts with port 6626 open on the given network.
    MAC address appears after the port line in nmap output, so we
    accumulate all fields per host block and flush on the next host.
    Returns a list of dicts with 'ip' and 'mac' keys.
    """
    devices = []
    try:
        result = subprocess.run(
            ['nmap', '-p', '6626', '--open', '-T4', network],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        output = result.stdout.decode('utf-8')

        ip_address = None
        port_open = False
        mac_address = ''

        for line in output.split('\n'):
            # New host block — flush previous if port was open
            if line.startswith('Nmap scan report for'):
                if ip_address and port_open:
                    devices.append({'ip': ip_address, 'mac': mac_address})
                raw = line.split(' ')[-1]
                ip_address = raw.strip('()')
                mac_address = ''
                port_open = False

            elif '6626/tcp open' in line:
                port_open = True

            elif 'MAC Address:' in line:
                parts = line.split()
                mac_address = parts[2] if len(parts) >= 3 else ''

        # Flush last host
        if ip_address and port_open:
            devices.append({'ip': ip_address, 'mac': mac_address})

    except FileNotFoundError:
        print("Error: nmap is not installed or not in PATH.")
    except Exception as e:
        print(f"Discovery error: {e}")

    return devices


def print_discovery_results(devices):
    """Query all discovered devices in parallel and print a formatted table."""
    COL = {
        'ip':     20,
        'mac':    19,
        'psn':    15,
        'sw_ver': 20,
        'sn':     45,
    }
    sep = '+' + '+'.join('-' * (w + 2) for w in COL.values()) + '+'
    header = (
        f"| {'IP Address':<{COL['ip']}} "
        f"| {'MAC Address':<{COL['mac']}} "
        f"| {'PSN':<{COL['psn']}} "
        f"| {'SW-VER':<{COL['sw_ver']}} "
        f"| {'SN':<{COL['sn']}} |"
    )

    print(sep)
    print(header)
    print(sep)

    # Query all devices in parallel
    results = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(send_tcp_packet, d['ip'], 'info', d['mac']): d['ip']
            for d in devices
        }
        for future in as_completed(futures):
            info = future.result()
            if info:
                results[info['ip']] = info

    # Print in original discovery order
    for device in devices:
        info = results.get(device['ip'])
        if not info:
            continue
        if info.get('connection') == 'refused':
            psn = sw_ver = sn = 'N/A'
        else:
            psn    = info['psn']
            sw_ver = info['sw_ver']
            sn     = info['sn']

        print(
            f"| {info['ip']:<{COL['ip']}} "
            f"| {info['mac']:<{COL['mac']}} "
            f"| {psn:<{COL['psn']}} "
            f"| {sw_ver:<{COL['sw_ver']}} "
            f"| {sn:<{COL['sn']}} |"
        )

    print(sep)
    print(f"{len(results)} device(s) found.")


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 wagoservice.py <command> <ip|network>")
        print("  python3 wagoservice.py discover 192.168.68.0/24")
        print("  python3 wagoservice.py restart  192.168.68.0/24")
        print("  python3 wagoservice.py restart  192.168.68.80")
        sys.exit(1)

    command = sys.argv[1]
    target  = sys.argv[2]

    if command == 'discover':
        devices = discover_devices(target)
        print_discovery_results(devices)

    elif command == 'restart':
        if '/' in target:
            # Network range: discover then restart all
            devices = discover_devices(target)
            for device in devices:
                info = send_tcp_packet(device['ip'], 'info')
                if info and info.get('connection') != 'refused':
                    print(f"Restarting {device['ip']} ...")
                    send_tcp_packet(device['ip'], 'restart')
        else:
            # Single device
            print(f"Restarting {target} ...")
            send_tcp_packet(target, 'restart')

    else:
        print(f"Unknown command '{command}'. Use 'discover' or 'restart'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
