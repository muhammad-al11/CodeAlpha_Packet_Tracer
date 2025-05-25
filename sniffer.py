from scapy.all import sniff
def process_packet(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        protocol = packet.proto
        print(f"Source IP: {src_ip} → Destination IP: {dst_ip} | Protocol: {protocol}")
sniff(prn=process_packet)
