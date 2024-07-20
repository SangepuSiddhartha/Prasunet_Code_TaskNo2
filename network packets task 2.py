from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] New Packet: {packet.summary()}")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        # Check for the payload
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"Payload: {bytes(tcp_layer.payload)}")
        
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            print(f"Payload: {bytes(udp_layer.payload)}")
        
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            print(f"Type: {icmp_layer.type}")
            print(f"Code: {icmp_layer.code}")
            print(f"Payload: {bytes(icmp_layer.payload)}")

def main():
    print("Starting packet sniffer...")
    # Start sniffing (you might need root/admin privileges to sniff network packets)
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
