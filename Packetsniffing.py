from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(protocol, 'Other')
        print(f"\n[+] Packet: {src_ip} → {dst_ip} | Protocol: {proto_name}")

        if proto_name == 'TCP' and TCP in packet:
            tcp_layer = packet[TCP]
            print(f"    TCP Ports: {tcp_layer.sport} → {tcp_layer.dport}")
        elif proto_name == 'UDP' and UDP in packet:
            udp_layer = packet[UDP]
            print(f"    UDP Ports: {udp_layer.sport} → {udp_layer.dport}")
        elif proto_name == 'ICMP' and ICMP in packet:
            icmp_layer = packet[ICMP]
            print(f"    ICMP Type: {icmp_layer.type}")

        payload = bytes(packet[IP].payload)
        if payload:
            print(f"    Payload (first 32 bytes): {payload[:32].hex()}")

print("Starting packet capture... Press Ctrl+C to stop.")
sniff(filter="ip", prn=process_packet, store=False)
