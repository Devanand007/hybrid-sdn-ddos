from scapy.all import *
import time

VICTIM_IP = "192.168.10.50"
OUTPUT_PCAP = "attack_volume.pcap"

packets = []
pps = 2000        # HIGH
duration = 60     # 1 minute
interval = 1.0 / pps
total_packets = int(pps * duration)

base_time = time.time()

for i in range(total_packets):
    pkt = (
        Ether() /
        IP(src="172.16.0.1", dst=VICTIM_IP) /
        TCP(sport=44444, dport=80, flags="S")
    )
    pkt.time = base_time + i * interval
    packets.append(pkt)

wrpcap(OUTPUT_PCAP, packets)
print("attack_volume.pcap generated")
