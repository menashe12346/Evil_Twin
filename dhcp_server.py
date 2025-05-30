from scapy.all import *
import subprocess
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# Configuration
INTERFACE = "wlp4s0f4u1"   # AP WiFi interface
INTERNET_IFACE = "wlp2s0"  # Internet-facing interface
OFFERED_IP = "192.168.1.100"
SERVER_IP = "192.168.1.1"
SUBNET_MASK = "255.255.255.0"
LEASE_TIME = 3600

session_store = {}
authenticated_ips = set()

def check_root():
    if os.geteuid() != 0:
        print("[!] This script must be run as root.")
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
        print("[*] IP forwarding is already enabled.")

def enable_nat():
    result = subprocess.run(
        ["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", INTERNET_IFACE, "-j", "MASQUERADE"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    if result.returncode != 0:
        print(f"[*] Enabling NAT on {INTERNET_IFACE}...")
        subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", INTERNET_IFACE, "-j", "MASQUERADE"], check=True)
    else:
        print("[*] NAT is already configured.")

def enable_forwarding_rules():
    fwd_out = subprocess.run(
        ["iptables", "-C", "FORWARD", "-i", INTERFACE, "-o", INTERNET_IFACE, "-j", "ACCEPT"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    if fwd_out.returncode != 0:
        print(f"[*] Allowing forwarding from {INTERFACE} to {INTERNET_IFACE}...")
        subprocess.run(["iptables", "-A", "FORWARD", "-i", INTERFACE, "-o", INTERNET_IFACE, "-j", "ACCEPT"], check=True)

    fwd_in = subprocess.run(
        ["iptables", "-C", "FORWARD", "-i", INTERNET_IFACE, "-o", INTERFACE, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    if fwd_in.returncode != 0:
        print(f"[*] Allowing response forwarding from {INTERNET_IFACE} to {INTERFACE}...")
        subprocess.run(["iptables", "-A", "FORWARD", "-i", INTERNET_IFACE, "-o", INTERFACE, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=True)

def redirect_http_to_local():
    print("[*] Redirecting all HTTP traffic to captive portal...")
    subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", INTERFACE,
                    "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{SERVER_IP}:80"], check=True)

def block_unauthenticated():
    print("[*] Blocking all outgoing traffic by default...")
    subprocess.run(["iptables", "-I", "FORWARD", "-i", INTERFACE, "-o", INTERNET_IFACE, "-j", "REJECT"], check=True)

def allow_authenticated(ip):
    print(f"[*] Granting Internet access to authenticated user: {ip}")
    subprocess.run(["iptables", "-I", "FORWARD", "-s", ip, "-o", INTERNET_IFACE, "-j", "ACCEPT"], check=True)
    authenticated_ips.add(ip)

class CaptivePortalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"""
            <html><body>
            <h2>Welcome to the Captive Portal</h2>
            <form action='/login' method='POST'>
                Username: <input type='text' name='user'><br>
                Password: <input type='password' name='pass'><br>
                <input type='submit' value='Login'>
            </form>
            </body></html>
        """)

    def do_POST(self):
        if self.path == '/login':
            ip = self.client_address[0]
            allow_authenticated(ip)
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body><h2>Access granted</h2></body></html>")

def start_http_server():
    server = HTTPServer((SERVER_IP, 80), CaptivePortalHandler)
    print("[*] Captive portal HTTP server started on port 80")
    threading.Thread(target=server.serve_forever, daemon=True).start()

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
        ("name_server", SERVER_IP),
        ("lease_time", LEASE_TIME),
        ("url", f"http://{SERVER_IP}"),
        "end"
    ])
    packet = ether / ip / udp / bootp / dhcp
    sendp(packet, iface=INTERFACE, verbose=0)
    print(f"[>] Sent DHCP {msg_type.upper()} to {mac}")

def start_captive_portal(interface):
    check_root()
    assign_ip_to_ap()
    enable_ip_forwarding()
    enable_nat()
    enable_forwarding_rules()
    block_unauthenticated()
    redirect_http_to_local()
    start_http_server()
    print(f"[*] Listening for DHCP requests on {INTERFACE}...")
    sniff(filter="udp and (port 67 or 68)", iface=INTERFACE, prn=handle_dhcp)

# Example usage:
if __name__ == "__main__":
    start_captive_portal()
