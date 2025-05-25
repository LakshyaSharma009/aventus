from scapy.all import *

def process_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")

        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")

        else:
            print(f"IP Packet: {ip_src} -> {ip_dst}, Protocol: {proto}")

if __name__ == "__main__":
    interface = input("Enter the interface to sniff on (e.g., eth0 or wlan0): ")
    print("Starting packet sniffer...")
    try:
        sniff(iface=interface, prn=process_packet, store=False, filter="ip")
    except Exception as e:
        print(f"Error: {e}")
        #pip3 install scapy

