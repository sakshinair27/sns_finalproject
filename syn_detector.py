from scapy.all import sniff, TCP
import time
from collections import defaultdict

SYN_COUNTS = defaultdict(int)
TIME_WINDOW = 5
THRESHOLD = 100
LAST_RESET = time.time()

def process_packet(packet):
    global LAST_RESET

    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        src_ip = packet[0][1].src
        SYN_COUNTS[src_ip] += 1

        if time.time() - LAST_RESET > TIME_WINDOW:
            print(f"\n--- SYN Counts in last {TIME_WINDOW}s ---")
            for ip, count in SYN_COUNTS.items():
                print(f"{ip}: {count} SYN packets")

                if count > THRESHOLD:
                    print(f"[ALERT] Possible SYN flood detected from {ip}!")

            SYN_COUNTS.clear()
            LAST_RESET = time.time()

print("Starting SYN Flood Detector...")
sniff(filter="tcp", prn=process_packet)
