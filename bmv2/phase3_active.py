from scapy.all import *
import random
import time

# ---------------- CONFIG ----------------
VICTIM_IP = "192.168.10.50"
DST_PORT = 80

NUM_PACKETS = 5000        # total packets in PCAP
PPS = 10                 # packets per second
OUTPUT_PCAP = "lemon_active.pcap"
# ----------------------------------------

packets = []

interval = 1.0 / PPS
base_time = time.time()

for i in range(NUM_PACKETS):
    # Random source IP (private range)
    src_ip = f"172.16.{random.randint(0,255)}.{random.randint(1,254)}"

    # Random source port
    src_port = random.randint(1024, 65535)

    pkt = (
        Ether() /
        IP(src=src_ip, dst=VICTIM_IP) /
        TCP(sport=src_port, dport=DST_PORT, flags="S")
    )

    pkt.time = base_time + i * interval
    packets.append(pkt)

print(f"[+] Generated {len(packets)} packets")
wrpcap(OUTPUT_PCAP, packets)
print(f"[+] Saved to {OUTPUT_PCAP}")
