from scapy.all import *
from collections import defaultdict
from tabulate import tabulate
from manuf import manuf
import subprocess
import threading
import time
import os

def channel_hopper(interface, dwell=0.5, stop_event=None):
    """
    Changes the Wi-Fi channel every `dwell` seconds.
    If stop_event is provided, will exit when stop_event.is_set().
    """
    if not isinstance(dwell, (int, float)):
        raise TypeError(f"dwell must be a number, got {type(dwell)}")

    channels = {
        "2.4GHz": list(range(1, 15)),
        "5GHz": [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                 116, 120, 124, 128, 132, 136, 140, 144, 149, 153,
                 157, 161, 165],
        "6GHz": [1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49,
                 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97,
                 101, 105, 109, 113, 117, 121, 125, 129, 133, 137,
                 141, 145, 149, 153, 157, 161, 165, 169, 173, 177]
    }

    def hop():
        while stop_event is None or not stop_event.is_set():
            for ch_list in channels.values():
                for ch in ch_list:
                    os.system(f"iw dev {interface} set channel {ch} > /dev/null 2>&1")
                    time.sleep(dwell)
                    if stop_event and stop_event.is_set():
                        print("[*] Channel hopping stopped")
                        return

    t = threading.Thread(target=hop, daemon=True)
    t.start()
    return t

def scan_wifi_networks(iface, timeout=100):
    access_points = {}
    clients = defaultdict(dict)
    parser = manuf.MacParser()

    def countdown(seconds, stop_event):
        """מדפיס כל שניה כמה שניות נותרו לסיום הסריקה"""
        for remaining in range(seconds, 0, -1):
            if stop_event.is_set():
                break
            print(f"\r⏱  Scanning... {remaining:3d}s remaining", end='', flush=True)
            time.sleep(1)
        print("\r⏱  Scanning... done!")


    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype in [8, 5]:
                bssid = pkt[Dot11].addr2
                ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else "<Hidden>"
                channel = None
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 3:
                        channel = elt.info[0]
                        break
                    elt = elt.payload.getlayer(Dot11Elt)
                power = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else 0

                access_points[bssid] = {
                    "SSID": ssid,
                    "CH": channel or "?",
                    "PWR": power,
                    "ENC": "WPA2" if "RSNinfo" in pkt.summary() else "OPN",
                    "CIPHER": "CCMP",
                    "AUTH": "PSK"
                }

            if pkt.type == 2 or (pkt.type == 0 and pkt.subtype == 4):
                addr1 = pkt.addr1
                addr2 = pkt.addr2
                for ap in access_points:
                    if addr1 == ap or addr2 == ap:
                        client_mac = addr2 if addr1 == ap else addr1
                        if client_mac not in clients[ap]:
                            signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else None
                            vendor = parser.get_manuf(client_mac) or "Unknown"
                            clients[ap][client_mac] = {
                                "MAC": client_mac,
                                "RSSI": signal,
                                "Vendor": vendor
                            }

    print("[*] Starting channel hopping...")
    # start the internal hopper thread and keep its stop_event
    stop_event = threading.Event()
    hopper_thread = channel_hopper(iface, dwell=0.5, stop_event=stop_event)

    print("[*] Scanning Wi-Fi networks...\n")
    # השקת תצוגת הספירה לאחור
    timer_thread = threading.Thread(target=countdown, args=(timeout, stop_event), daemon=True)
    timer_thread.start()
   
    try:
        sniff(prn=packet_handler, iface=iface, timeout=timeout)
    except KeyboardInterrupt:
        pass

    stop_event.set()
    hopper_thread.join()
    timer_thread.join()
    print()  # קו ריק אחרי הספירה

    # Display networks
    table = []
    indexed_bssids = []
    for i, (bssid, data) in enumerate(access_points.items()):
        row = [
            i,
            bssid,
            data["PWR"],
            data["CH"],
            data["ENC"],
            data["CIPHER"],
            data["AUTH"],
            data["SSID"],
            len(clients.get(bssid, []))
        ]
        table.append(row)
        indexed_bssids.append(bssid)

    headers = ["#", "BSSID", "PWR", "CH", "ENC", "CIPHER", "AUTH", "SSID", "#Clients"]
    print("\n=== Wi-Fi Networks Found ===")
    print(tabulate(table, headers=headers, tablefmt="grid"))

    # Choose network
    try:
        choice = int(input("\n🔍 Choose network number to attack: "))
        selected_bssid = indexed_bssids[choice]
    except (ValueError, IndexError):
        print("❌ Invalid network selection.")
        return None, None, None

    """
    # Display clients
    selected_clients = list(clients[selected_bssid].values())
    client_table = []
    for i, c in enumerate(selected_clients):
        row = [
            i,
            c["MAC"],
            c["RSSI"] if c["RSSI"] is not None else "N/A",
            c["Vendor"]
        ]
        client_table.append(row)

    client_headers = ["#", "MAC Address", "RSSI", "Vendor"]
    print(f"\n📡 Clients connected to {selected_bssid} ({access_points[selected_bssid]['SSID']}):")
    print(tabulate(client_table, headers=client_headers, tablefmt="grid"))

    try:
        client_choice = int(input("\n👤 Choose client number: "))
        selected_client_mac = selected_clients[client_choice]["MAC"]
    except (ValueError, IndexError):
        print("❌ Invalid client selection.")
        return selected_bssid, None, None
    """

    selected_ssid = access_points[selected_bssid]['SSID']
    return selected_bssid, selected_ssid

if __name__ == "__main__":
    bssid, selected_ssid = scan_wifi_networks()
    print("✅ Selected BSSID:", bssid)
    print("✅ Selected SSID:", selected_ssid)
    #print("✅ Selected Client MAC:", client_mac)
