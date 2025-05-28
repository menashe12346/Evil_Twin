from scapy.all import *
from collections import defaultdict
from tabulate import tabulate
from manuf import manuf

def scan_wifi_networks(iface="wlp4s0f4u1", timeout=100):
    access_points = {}  # BSSID -> info
    clients = defaultdict(dict)  # BSSID -> MAC -> info
    parser = manuf.MacParser()

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            # Access point detection
            if pkt.type == 0 and pkt.subtype in [8, 5]:  # Beacon / ProbeResp
                bssid = pkt[Dot11].addr2
                ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else "<Hidden>"

                # Channel
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

            # Client detection
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

    print("[*] Scanning Wi-Fi networks... Press Ctrl+C to stop.\n")
    try:
        sniff(prn=packet_handler, iface=iface, timeout=timeout)
    except KeyboardInterrupt:
        pass

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
        choice = int(input("\n🔍 Choose network number to view clients: "))
        selected_bssid = indexed_bssids[choice]
    except (ValueError, IndexError):
        print("❌ Invalid network selection.")
        return None, None

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

    # Choose client
    try:
        client_choice = int(input("\n👤 Choose client number: "))
        selected_client_mac = selected_clients[client_choice]["MAC"]
    except (ValueError, IndexError):
        print("❌ Invalid client selection.")
        return selected_bssid, None
    
    selected_ssid = access_points[selected_bssid]['SSID']

    return selected_bssid, selected_ssid, selected_client_mac

if __name__ == "__main__":
    bssid, selected_ssid, client_mac = scan_wifi_networks()
    print("✅ Selected BSSID:", bssid)
    print("✅ Selected SSID:", selected_ssid)
    print("✅ Selected Client MAC:", client_mac)
