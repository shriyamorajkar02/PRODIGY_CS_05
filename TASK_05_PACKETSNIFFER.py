from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        print(f"Packet: {packet.summary()}")
        print(f"Source IP: {packet[IP].src} → Destination IP: {packet[IP].dst}")

# Start packet sniffing
print("Sniffing packets... Press Ctrl+C to stop.")
sniff(prn=packet_callback, count=10)  # Captures 10 packets
