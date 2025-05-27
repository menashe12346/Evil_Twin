from scapy.all import *
import subprocess
import os

# הגדרות כלליות
INTERFACE = "wlp4s0f4u1"   # ממשק ה־WiFi ב־AP Mode (AP)
INTERNET_IFACE = "wlp2s0"  # ממשק שמוביל לאינטרנט
OFFERED_IP = "192.168.1.100"
SERVER_IP = "192.168.1.1"
SUBNET_MASK = "255.255.255.0"
LEASE_TIME = 3600

session_store = {}

def check_root():
    if os.geteuid() != 0:
        print("[!] Must run as root. Use sudo.")
        exit(1)

def assign_ip_to_ap():
    print(f"[*] Assigning {SERVER_IP}/24 to {INTERFACE}...")
    subprocess.run(["ip", "addr", "flush", "dev", INTERFACE])
    subprocess.run(["ip", "addr", "add", f"{SERVER_IP}/24", "dev", INTERFACE], check=True)
    subprocess.run(["ip", "link", "set", INTERFACE, "up"], check=True)

def enable_ip_forwarding():
    with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
        status = f.read().strip()
    if status != "1":
        print("[*] Enabling IP forwarding...")
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
    else:
        print("[*] IP forwarding already enabled.")

def enable_nat():
    result = subprocess.run(
        ["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", INTERNET_IFACE, "-j", "MASQUERADE"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    if result.returncode != 0:
        print(f"[*] Enabling NAT on {INTERNET_IFACE}...")
        subprocess.run(
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", INTERNET_IFACE, "-j", "MASQUERADE"],
            check=True
        )
    else:
        print("[*] NAT already enabled.")

def enable_forwarding_rules():
    # כלל: מ-AP החוצה
    fwd_out = subprocess.run(
        ["iptables", "-C", "FORWARD", "-i", INTERFACE, "-o", INTERNET_IFACE, "-j", "ACCEPT"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    if fwd_out.returncode != 0:
        print(f"[*] Allowing FORWARD from {INTERFACE} to {INTERNET_IFACE}...")
        subprocess.run(
            ["iptables", "-A", "FORWARD", "-i", INTERFACE, "-o", INTERNET_IFACE, "-j", "ACCEPT"],
            check=True
        )
    else:
        print("[*] Forward rule from AP to Internet already exists.")

    # כלל: תגובות חזרה מהאינטרנט
    fwd_in = subprocess.run(
        ["iptables", "-C", "FORWARD", "-i", INTERNET_IFACE, "-o", INTERFACE,
         "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    if fwd_in.returncode != 0:
        print(f"[*] Allowing FORWARD from {INTERNET_IFACE} to {INTERFACE} (responses)...")
        subprocess.run(
            ["iptables", "-A", "FORWARD", "-i", INTERNET_IFACE, "-o", INTERFACE,
             "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            check=True
        )
    else:
        print("[*] Reverse forward rule already exists.")

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

def main():
    check_root()
    assign_ip_to_ap()
    enable_ip_forwarding()
    enable_nat()
    enable_forwarding_rules()
    print(f"[*] Listening for DHCP packets on {INTERFACE}...")
    sniff(filter="udp and (port 67 or 68)", iface=INTERFACE, prn=handle_dhcp)

if __name__ == "__main__":
    main()
