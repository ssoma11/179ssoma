from scapy.all import AsyncSniffer, TCP, IP
from collections import defaultdict
from datetime import datetime, timedelta
import subprocess

attempts = defaultdict(list)
blocklist = set()
THRESH = 3
TIME_WINDOW = timedelta(seconds=60)

def block_ip(ip):
    if ip not in blocklist:
        print(f"[BLOCK] Blocking IP {ip}")
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", "22", "-j", "DROP"])
        blocklist.add(ip)

def packet_window(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        tcp = packet[TCP]
        ip = packet[IP]

        if tcp.dport == 22 or tcp.flags == 'S':
            src_ip = ip.src
            now = datetime.now()
            attempts[src_ip].append(now)

            attempts[src_ip] = [
                t for t in attempts[src_ip] if now - t <= TIME_WINDOW
            ]

            if len(attempts[src_ip]) >= THRESH and src_ip not in blocklist:
                print(f"[ALERT] {src_ip} made {THRESH} attempts in under 1 minute.")
                block_ip(src_ip)

sniffer = AsyncSniffer(filter="tcp port 22", prn=packet_callback, store=False)
sniffer.start()

import time
try:
    while True:
        time.sleep(60)
except KeyboardInterrupt:
    sniffer.stop()
