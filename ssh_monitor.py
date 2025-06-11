import time
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta

THRESH = 3
WINDOW = timedelta(minutes=1)
LOG = "/tmp/ssh_log.txt"
attempts = defaultdict(list)
blocklist = set()

def block_ip(ip):
    if ip not in blocklist:
        subprocess.call(["iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", "22", "-j", "DROP"])
        blocklist.add(ip)

def monitor():
    with open(LOG, "r") as f:
        f.seek() 

        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            if "IP" in line and "22" in line:
                try:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if ">" in part:
                            src_ip = parts[i-1].split('.')[0]
                            
                            now = datetime.now()
                            attempts[src_ip].append(now)
                            
                            temp = []
                            for timestamp in attempts[src_ip]:
                                if (now - timestamp) <= WINDOW:
                                    temp.append(timestamp)
                            attempts[src_ip] = temp
                            
                            if len(attempts[src_ip]) >= THRESH:
                                block_ip(src_ip)
                            break
                except Exception as e:
                    print(f"Error processing line: {line.strip()}. Error: {e}")

try:
    monitor()
except KeyboardInterrupt:
    print("Monitoring stopped")