import csv
import subprocess
import socket
import struct
import time
from collections import defaultdict, deque

# Function to load rules from CSV file with error handling
def load_rules(filename):
    rules = []
    with open(filename, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            try:
                rules.append({
                    'RuleID': int(row['RuleID']),
                    'Direction': row['Direction'],
                    'SourceIP': row['SourceIP'],
                    'DestinationIP': row['DestinationIP'],
                    'SourcePort': row['SourcePort'],
                    'DestinationPort': row['DestinationPort'],
                    'Flags': row['Flags'],
                    'ThresholdCount': int(row['ThresholdCount']),
                    'ThresholdSeconds': int(row['ThresholdSeconds'].strip())
                })
            except ValueError as e:
                print(f"Error parsing row {row}: {e}")
    return rules

# Function to parse an IPv4 packet
def parse_ipv4_packet(packet_data):
    if len(packet_data) < 20:
        raise ValueError("Packet data is too short to contain an IPv4 header")
    
    ip_header = packet_data[14:34]  # Skip Ethernet header (14 bytes)
    ip_header_fields = struct.unpack("!BBHHHBBH4s4s", ip_header)
    version_ihl = ip_header_fields[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    header_length = ihl * 4
    source_ip = socket.inet_ntoa(ip_header_fields[8])
    destination_ip = socket.inet_ntoa(ip_header_fields[9])
    return source_ip, destination_ip, header_length

def drop_packet(packet_data):
    print("Packet Dropped")
# Function to parse a TCP packet
def parse_tcp_packet(packet_data, ip_header_length):
    tcp_header_offset = 14 + ip_header_length  # Skip Ethernet and IP headers
    if len(packet_data) < tcp_header_offset + 20:
        raise ValueError("Packet data is too short to contain a full TCP header")

    tcp_header = packet_data[tcp_header_offset:tcp_header_offset + 20]
    tcp_header_fields = struct.unpack("!HHLLBBHHH", tcp_header)
    source_port = tcp_header_fields[0]
    destination_port = tcp_header_fields[1]
    flags = tcp_header_fields[5]
    return source_port, destination_port, flags

# Function to block IP
def block_ip(ip_address):
    try:
       # subprocess.call(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])
        print(f"Blocked IP {ip_address}")
    except Exception as e:
        print(f"Error blocking IP {ip_address}: {e}")
    append_ip_to_file(ip_address)

# Load blocked IPs from the file
def load_blocked_ips():
    blocked_ips = set()
    try:
        with open('blocked_ip.txt', 'r') as file:
            for line in file:
                blocked_ips.add(line.strip())
    except FileNotFoundError:
        pass
    return blocked_ips

# Function to drop packet 
def dropp_packet(packet_data):
    # Extract the Ethernet header (first 14 bytes)
    eth_header = packet_data[:14]
    # Extract the source and destination MAC addresses
    src_mac, dest_mac = struct.unpack('!6s6s', eth_header[:12])

    # Create a new Ethernet packet with the same source and destination MAC addresses
    new_eth_packet = struct.pack('!6s6s', dest_mac, src_mac)

    # Create a new IP packet with the same source and destination IP addresses,
    # but with the Don't Fragment (DF) flag set and the IP header length (IHL) field set to 5
    new_ip_packet = b'\x45\x05\x00\x28\x00\x00\x40\x00\x40\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01'

    # Construct the new Ethernet packet with the new IP packet inside it
    dropped_packet = new_eth_packet + new_ip_packet

  # Send the dropped packet back to the network
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(('ens33', 0))
    s.send(dropped_packet)
    print("Packet dropped")

# Check if an IP is blocked
def is_ip_blocked(ip):
    blocked_ips = load_blocked_ips()
    return ip in blocked_ips

# Append an IP to the file if it's not already blocked
def append_ip_to_file(ip):
    if not is_ip_blocked(ip):
        with open('blocked_ip.txt', 'a') as file:
            file.write(f"{ip}\n")

# Function to analyze packets
def analyze_packet(packet_data, rules, packet_counters):
    try:
        source_ip, destination_ip, ip_header_length = parse_ipv4_packet(packet_data)
    except ValueError as e:
        print(f"Error parsing IP packet: {e}")
        return False

    try:
        source_port, destination_port, flags = parse_tcp_packet(packet_data, ip_header_length)
    except ValueError as e:
        print(f"Error parsing TCP packet: {e}")
        return False

    #print(f"Packet: Source IP {source_ip}, Destination IP {destination_ip}, Source Port {source_port}, Destination Port {destination_port}, Flags {flags}")

    current_time = time.time()

    for rule in rules:
        #print(f"Checking Rule: {rule}")
        if rule['Direction'] == 'inbound' and \
            (rule['SourceIP'] == '*' or source_ip.startswith(rule['SourceIP'])) and \
            (rule['DestinationIP'] == '*' or destination_ip.startswith(rule['DestinationIP'])) and \
            (rule['SourcePort'] == '*' or int(rule['SourcePort']) == source_port) and \
            (rule['DestinationPort'] == '*' or int(rule['DestinationPort']) == destination_port):

            rule_id = rule['RuleID']
            threshold_count = rule['ThresholdCount']
            threshold_seconds = rule['ThresholdSeconds']

            # Initialize counter and timestamps deque if not present
            if rule_id not in packet_counters:
                packet_counters[rule_id] = {
                    'count': 0,
                    'timestamps': deque()
                }

            packet_counters[rule_id]['timestamps'].append(current_time)
            packet_counters[rule_id]['count'] += 1

            # Remove timestamps outside the threshold window
            while packet_counters[rule_id]['timestamps'] and \
                    current_time - packet_counters[rule_id]['timestamps'][0] > threshold_seconds:
                packet_counters[rule_id]['timestamps'].popleft()
                packet_counters[rule_id]['count'] -= 1

            print(f"Rule ID {rule_id} - Packet Count: {packet_counters[rule_id]['count']}")

            if packet_counters[rule_id]['count'] >= threshold_count:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                alert_message = f"{timestamp} Attack-detected! Rule-ID::{rule_id} Source-IP::{source_ip} Destination-IP::{destination_ip}"
                print(alert_message)
                drop_packet(packet_data)
                del packet_counters[rule_id]
                with open('logs.txt', 'a') as logfile:
                    logfile.write(alert_message + '\n')

                if not is_ip_blocked(source_ip):
                    block_ip(source_ip)
                return True

    return False

# Load rules from CSV file
rules = load_rules('rules.csv')

# Initialize packet counts and timestamps
packet_counters = defaultdict(dict)

# Create a raw socket
raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

# Main loop for packet capture and analysis
try:
    print("IDS Running ...")
    while True:
        # Receive a packet
        packet_data, addr = raw_socket.recvfrom(65535)
        
        # Analyze the packet and detect DDoS attacks
        if analyze_packet(packet_data, rules, packet_counters):
            pass
except KeyboardInterrupt:
    print("Packet capture stopped.")
