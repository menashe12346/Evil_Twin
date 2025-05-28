from dnslib import DNSRecord, RR, A, QTYPE
from socketserver import UDPServer, BaseRequestHandler

CAPTIVE_IP = "192.168.1.1"
PORT = 53

class DNSHandler(BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)
        print(f"[*] DNS query for {qname} -> {CAPTIVE_IP}")

        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(CAPTIVE_IP), ttl=60))
        socket.sendto(reply.pack(), self.client_address)

if __name__ == "__main__":
    print(f"[*] Starting fake DNS server on port {PORT}, redirecting all domains to {CAPTIVE_IP}...")
    with UDPServer(("192.168.1.1", 53), DNSHandler) as server:
        server.serve_forever()
        