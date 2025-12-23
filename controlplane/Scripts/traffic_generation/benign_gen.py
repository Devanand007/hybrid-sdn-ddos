import random
from scapy.all import IP, UDP, Raw, wrpcap

def random_payload(size=64):
    return bytes(random.getrandbits(8) for _ in range(size))

dst_ip = "1.0.0.1"     # SAME victim as attack
src_ip = "192.168.0.10"
src_port = 40000
dst_port = 40000

pkts = []

for _ in range(500):
    pkt = IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=src_port, dport=dst_port) / \
          Raw(random_payload())
    pkts.append(pkt)

wrpcap("benign.pcap", pkts)
print("[OK] benign.pcap generated (author-aligned)")
