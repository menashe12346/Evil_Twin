from scapy.all import *
import subprocess
import os

# הגדרות כלליות
INTERFACE = "wlp4s0f4u1"   # ממשק ה־WiFi ב־AP Mode
INTERNET_IFACE = "wlp2s0"    # ממשק שמוביל לאינטרנט (שנה ל־wlan0 אם צריך)
OFFERED_IP = "192.168.1.100"
SERVER_IP = "192.168.1.1"
SUBNET_MASK = "255.255.255.0"
LEASE_TIME = 3600

# ניהול sessions לפי MAC
session_store = {}

# בדיקת root
def check_root():
    if os.geteuid() != 0:
        print("[!] Must run as root. Use sudo.")
        exit(1)

# הפעלת IP forwarding אם לא פעיל
def enable_ip_forwarding():
    with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
        status = f.read().strip()
    if status != "1":
        print("[*] Enabling IP forwarding...")
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
    else:
        print("[*] IP forwarding already enabled.")

# הפעלת NAT אם לא פעיל כבר
def enable_nat():
    check_rule = subprocess.run(
        ["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", INTERNET_IFACE, "-j", "MASQUERADE"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    if check_rule.returncode != 0:
        print(f"[*] Enabling NAT on {INTERNET_IFACE}...")
        subprocess.run(
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", INTERNET_IFACE, "-j", "MASQUERADE"],
            check=True
        )
    else:
        print("[*] NAT already enabled.")

# זיהוי בקשת DHCP
def handle_dhcp(pkt):
    if not pkt.haslayer(DHCP):
        return

    mac = pkt[Ether].src
    xid = pkt[BOOTP].xid
    chaddr = pkt[BOOTP].chaddr
    dhcp_type = None

    for opt in pkt[DHCP].options:
        if opt[0] == 'message-type':
            dhcp_type = opt[1]

    if dhcp_type == 1:  # DHCPDISCOVER
        print(f"[+] DHCPDISCOVER from {mac}, xid={xid}")
        session_store[mac] = xid
        send_response(mac, xid, chaddr, msg_type="offer")

    elif dhcp_type == 3:  # DHCPREQUEST
        if mac not in session_store:
            print(f"[!] DHCPREQUEST from {mac} without matching OFFER")
            return
        print(f"[+] DHCPREQUEST from {mac}, xid={xid}")
        send_response(mac, xid, chaddr, msg_type="ack")

# שליחת OFFER / ACK
def send_response(mac, xid, chaddr, msg_type="offer"):
    ether = Ether(dst=mac, src=get_if_hwaddr(INTERFACE))
    ip = IP(src=SERVER_IP, dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(op=2, yiaddr=OFFERED_IP, siaddr=SERVER_IP, chaddr=chaddr, xid=xid, flags=0x8000)
    dhcp = DHCP(options=[
        ("message-type", msg_type),
        ("server_id", SERVER_IP),
        ("subnet_mask", SUBNET_MASK),
        ("router", SERVER_IP),
        ("name_server", "8.8.8.8"),
        ("lease_time", LEASE_TIME),
        ("end")
    ])
    packet = ether / ip / udp / bootp / dhcp
    sendp(packet, iface=INTERFACE, verbose=0)
    print(f"[>] Sent DHCP {msg_type.upper()} to {mac}")

# פונקציית main
def main():
    check_root()
    enable_ip_forwarding()
    enable_nat()
    print(f"[*] Listening for DHCP packets on {INTERFACE}...")
    sniff(filter="udp and (port 67 or 68)", iface=INTERFACE, prn=handle_dhcp)

if __name__ == "__main__":
    main()
