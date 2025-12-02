#!/bin/bash
echo "[*] Starting SYN packet capture..."
sudo tcpdump -i any tcp[tcpflags] & tcp-syn != 0 -w capture.pcap
