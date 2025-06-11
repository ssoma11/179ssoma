import smtplib
from email.message import EmailMessage

from scapy.all import *

smtp_server = "smtp.gmail.com"
smtp_port = 587
username = "sanjana.somala@gmail.com"
password = "ghya vqgo lcep vcef"

msg = EmailMessage()
msg["Subject"] = "openwrt"
msg["From"] = username
msg["To"] = "ssoma011@ucr.edu"
msg.set_content("someone is repeatedly trying to access your router")

THRESH = 20  
LOGIN_THRESH = 3
syn_counts = {}
login_counts = {}

def detect(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].dport in 22: #ssh is on port 22
        src1 = pkt[IP].src
        syn_counts[src1] = syn_counts.get(src1,0) + 1
        if syn_counts[src] > LOGIN_THRESH:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(username, password)
                server.send_message(msg)

sniff(iface="eth0", prn=detect, filter="tcp")