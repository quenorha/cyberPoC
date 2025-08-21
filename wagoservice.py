import subprocess
import socket
import sys

def parse_payload(payload):
    lines = payload.split(';')
    parsed_data = {}
    for line in lines:
        if '=' in line:
            key, value = line.split('=', 1)
            parsed_data[key.strip()] = value.strip()
    return parsed_data

def send_tcp_packet(ip_address, command, mac_address=''):
    hex_data_mapping = {
        "restart": '8812320001000100000000000000000002000201',
        "info": '8812020001000100000000000000000002000801'
    }

    if command not in hex_data_mapping:
        print("Unknown command. Use 'info' or 'restart'.")
        return None

    packet_data = bytes.fromhex(hex_data_mapping[command])

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip_address, 6626))
            s.sendall(packet_data)
            response = s.recv(1024)

            hex_response = response.hex()
            ascii_response = response.decode('ascii', errors='replace')
            parsed_info = parse_payload(ascii_response)

            return {
                'ip': ip_address,
                'mac': mac_address,
                'psn': parsed_info.get('PSN', 'N/A'),
                'sw_ver': parsed_info.get('SW-VER', 'N/A'),
                'sn': parsed_info.get('SN', 'N/A')
            }

    except OSError as e:
        if e.errno == 111:  # Connection refused
            return {'ip': ip_address, 'mac': mac_address, 'connection': 'refused'}
        else:
            print(f"An error occurred with {ip_address}: {e}")
            return None

def discover_devices(network):
    devices = []
    try:
        result = subprocess.run(['nmap', '-p', '6626', '--open', network], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        output = result.stdout.decode('utf-8')
        lines = output.split('\n')

        ip_address = None
        mac_address = None

        for line in lines:
            if line.startswith('Nmap scan report for'):
                ip_address = line.split(' ')[-1]
            elif 'MAC Address: 00:30:DE' in line:
                mac_address = line.split(' ')[2] if len(line.split(' ')) > 2 else ''
            elif '6626/tcp open' in line:
                if ip_address and mac_address:
                    devices.append({'ip': ip_address, 'mac': mac_address})
                ip_address = None  # Reset for the next host

    except Exception as e:
        print(f"An error occurred during discovery: {e}")

    return devices

def print_discovery_results(devices):
    print("\n+---------------------+---------------------+---------------------+---------------------+---------------------+")
    print("| IP Address          | MAC Address         | PSN                 | SW-VER              | SN                  |")
    print("+---------------------+---------------------+---------------------+---------------------+---------------------+")

    for device in devices:
        device_info = send_tcp_packet(device['ip'], 'info', device['mac'])
        if device_info:
            if device_info.get('connection') == 'refused':
                print(f"| {device_info['ip']:<20} | {device_info['mac']:<19} | {'N/A':<19} | {'N/A':<19} | {'N/A':<19} |")
            else:
                print(f"| {device_info['ip']:<20} | {device_info['mac']:<19} | {device_info['psn']:<19} | {device_info['sw_ver']:<19} | {device_info['sn']:<19} |")

    print("+---------------------+---------------------+---------------------+---------------------+---------------------+")

if __name__ == "__main__":
    if len(sys.argv) == 3:
        command = sys.argv[1]
        target = sys.argv[2]
        
        if command == 'discover':
            devices = discover_devices(target)
            print_discovery_results(devices)
        elif command == 'restart':
            if '/' in target:  # Indicates it is a network, not a single IP
                devices = discover_devices(target)
                for device in devices:
                    result = send_tcp_packet(device['ip'], 'info')
                    if result and result.get('connection') != 'refused':
                        print(f"Restarting device at IP {device['ip']}")
                        send_tcp_packet(device['ip'], 'restart')
            else:
                print(f"Restarting single device at IP {target}")
                send_tcp_packet(target, 'restart')

    else:
        print("Usage: python3 wagoserviceport.py <command> <address/network>")