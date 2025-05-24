# CodeAlpha_Packet_Tracer
# Basic Sniffer Packet Tracer using Phython.

# Import the sniff function from the scapy library
from scapy.all import sniff

# Define a function to process each packet that is captured
def process_packet(packet):
    # Check if the packet has an IP layer (means it's an IP packet)
    if packet.haslayer("IP"):
        # Get the source IP address from the IP layer
        src_ip = packet["IP"].src
        # Get the destination IP address from the IP layer
        dst_ip = packet["IP"].dst
        # Get the protocol number used (like TCP=6, UDP=17, etc.)
        protocol = packet.proto
        # Print the information in a readable format
        print(f"Source IP: {src_ip} → Destination IP: {dst_ip} | Protocol: {protocol}")

# Start sniffing network packets and call process_packet for each one
sniff(prn=process_packet)

