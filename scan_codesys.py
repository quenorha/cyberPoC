import socket
import argparse
import string
import json

def send_udp_broadcast(hex_message, destination_ip, source_port, destination_port=1740):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_socket.bind(('', source_port))
    message_bytes = bytes.fromhex(hex_message)
    udp_socket.sendto(message_bytes, (destination_ip, destination_port))
    udp_socket.close()

def listen_udp(port=1743, display_format='table'):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(('0.0.0.0', port))
    udp_socket.settimeout(3)  # Timeout de 10 secondes
    
    printable_chars = set(string.printable)

    messages = []

    try:
        while True:
            data, addr = udp_socket.recvfrom(512) 
            num_bytes = len(data)
            #print(f"Received {num_bytes} bytes from {addr[0]}.")

            if num_bytes > 60:
                # Slice relevant data part
                raw_message = data[60:num_bytes-1]
                parts = raw_message.split(b'\x00\x00')

                # Initialize variables
                devicename = ''
                completename = ''
                manufacturer = ''
                macaddress = ''

                # Assign parts to variables if available
                if len(parts) > 0:
                    devicename = parts[0].decode('ascii', errors='ignore')
                if len(parts) > 1:
                    completename = parts[1].decode('ascii', errors='ignore')
                if len(parts) > 2:
                    manufacturer = parts[2].decode('ascii', errors='ignore')
                if len(parts) > 3:
                    macaddress = parts[3].decode('ascii', errors='ignore')

                # Filter non-printable characters
                devicename = ''.join(filter(lambda x: x in printable_chars, devicename))
                completename = ''.join(filter(lambda x: x in printable_chars, completename))
                manufacturer = ''.join(filter(lambda x: x in printable_chars, manufacturer))
                macaddress = ''.join(filter(lambda x: x in printable_chars, macaddress))

                # Append message to list
                messages.append({
                    "IP Address": addr[0],
                    "Device Name": devicename,
                    "Complete Name": completename,
                    "Manufacturer": manufacturer,
                    "MAC Address": macaddress
                })

    except socket.timeout:

        # Display collected messages
        if display_format == 'json':
            print(json.dumps(messages, indent=2))
        elif display_format == 'table':
            # Create a simple text table
            headers = ["IP Address", "Device Name", "Complete Name", "Manufacturer", "MAC Address"]
            row_format = "{:<15} {:<20} {:<40} {:<25} {:<18}"
            # Print headers
            print(row_format.format(*headers))
            # Print each message data
            for message in messages:
                print(row_format.format(
                    message["IP Address"],
                    message["Device Name"],
                    message["Complete Name"],
                    message["Manufacturer"],
                    message["MAC Address"]
                ))

def main():
    parser = argparse.ArgumentParser(description='Sending UDP to discover CODESYS devices.')
    parser.add_argument('destination_ip', help="IP adress to discover devices : can be a broadcast address")
    parser.add_argument('--format', choices=['json', 'table'], default='table', help="Output format, can be either json or table")
    args = parser.parse_args()

    hex_message = "c57440030020999903c8030102c20004ee770000"  
    source_port = 1743  # Port source

    send_udp_broadcast(hex_message, args.destination_ip, source_port)
    listen_udp(source_port, args.format)

if __name__ == "__main__":
    main()