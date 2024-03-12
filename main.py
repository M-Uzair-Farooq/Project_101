from scapy.all import sniff, IP, ICMP

def icmp_packet_summary(packet):
    if IP in packet and ICMP in packet:
        print(packet.summary())

interface_name = "Wi-Fi"

capture_filter = "icmp"

sniff(iface=interface_name, prn=icmp_packet_summary, filter=capture_filter)


