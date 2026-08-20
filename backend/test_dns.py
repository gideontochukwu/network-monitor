from scapy.all import sniff, DNS, DNSQR, conf

# Use your Wi-Fi interface
conf.iface = "Intel(R) Wireless-AC 9260 160MHz"

def packet_handler(packet):
    if packet.has(DNS) and packet.has(DNSQR):
        domain = packet[DNSQR].qname.decode('utf-8').rstrip('.')
        print(f"🌐 DNS Request: {domain}")

print("🔍 Listening for DNS requests... Press Ctrl+C to stop.")
sniff(filter="udp port 53", prn=packet_handler, count=0)