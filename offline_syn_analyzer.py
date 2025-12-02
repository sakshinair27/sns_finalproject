from scapy.all import rdpcap, TCP
from collections import defaultdict
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", required=True, help="PCAP file")
args = parser.parse_args()

packets = rdpcap(args.file)
syn_counts = defaultdict(int)

for pkt in packets:
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        src_ip = pkt[0][1].src
        syn_counts[src_ip] += 1

print("\n--- SYN Packet Summary ---")
for ip, count in syn_counts.items():
    print(f"{ip}: {count} SYN packets")

print("\n--- Alerts ---")
for ip, count in syn_counts.items():
    if count > 500:
        print(f"[ALERT] High SYN count detected from {ip}: {count} SYNs")
