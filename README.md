# sns_finalproject - Sakshi Nair (saknair)
** Lightweight On-Host Detection of SYN Flood Attacks **

1. **Project Overview** - SYN flood attacks remain one of the most common and effective forms of Denial-of-Service (DoS) attacks. They exploit the TCP three-way handshake, overwhelming a server or host with half-open connections.
This project implements a lightweight on-host detection system capable of monitoring SYN packet patterns in real time and raising alerts when suspicious behavior is observed. The goal is to design a simple, efficient, and deployable detector suitable for end-hosts, virtual machines, and small network environments.

2. **Objectives** - 
-> Detect abnormal spikes in SYN packets that indicate a SYN flood attack.
-> Provide a lightweight, host-based solution without requiring dedicated appliances.
-> Analyze both live traffic and offline datasets (.pcap files).
-> Produce an early-warning alert system for defending against resource exhaustion attacks.

3. **Detection Approach** - 
-> The detection method is based on threshold-based anomaly detection:
-> Count incoming SYN packets within a rolling time window.
-> Compare the count to a predefined or dynamically calculated threshold.
-> If the value exceeds the threshold, raise an alert indicating a potential attack.
-> Optionally track unique source IPs to highlight abnormal traffic sources.
-> This simple model is highly efficient and works well for demonstration and academic environments.

4. **Features** -
-> Real-time SYN packet monitoring using Scapy.
-> Offline analysis of .pcap files.
-> Customizable detection threshold.

5. **Installation** - 
Prerequisites - Python 3, Scapy library, Linux environment (recommended: SEED Labs Ubuntu 20.04 VM)

6. **Usage** -
-> Real-Time Detection
-> Analyze a PCAP File

7. **Example Output** -
[INFO] Monitoring incoming SYN packets...
[ALERT] Possible SYN flood detected! SYN count exceeded threshold.
[DETAILS] Total SYN packets in last interval: 185
[DETAILS] Unique source IPs observed: 12
Console-based alerts for suspected attacks.
Works on Linux-based SEED labs VMs (Attacker → Victim → Wireshark Monitor setup).
