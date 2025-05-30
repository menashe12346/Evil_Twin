from scapy.all import *
import subprocess
import os
import time

INTERFACE = "wlp4s0f4u1"
SCAN_INTERVAL = 20  # seconds

def set_monitor_mode(interface):
    print(f"[*] Enabling monitor mode  on interface {interface} using ./set_monitor.sh...")
    subprocess.run(["./set_monitor.sh", interface], check=True)

def scan_wifi(interface, timeout=30):
    networks = {}

    def handler(pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore') if pkt[Dot11Elt].info else "<Hidden>"
            bssid = pkt[Dot11].addr3
            rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "N/A"

            if ssid not in networks:
                networks[ssid] = []
            networks[ssid].append({
                "BSSID": bssid,
                "RSSI": rssi
            })

    print(f"\n🔄 Scanning on interface {interface}...")
    sniff(iface=interface, prn=handler, timeout=timeout, store=0)
    return networks

def detect_evil_twin(networks):
    for ssid, entries in networks.items():
        unique_bssids = set(entry["BSSID"] for entry in entries)
        if len(unique_bssids) > 1:
            print(f"⚠️  Possible Evil Twin Detected for SSID '{ssid}'!")
            for entry in entries:
                print(f"    ➤ BSSID: {entry['BSSID']} | RSSI: {entry['RSSI']}")
            print("")

def main():
    set_monitor_mode(INTERFACE)
    print("📡 Starting Evil Twin detection loop...")
    try:
        while True:
            networks = scan_wifi(INTERFACE)
            detect_evil_twin(networks)
            print(f"⏳ Waiting {SCAN_INTERVAL} seconds before next scan...")
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print("\n🛑 Stopping scan due to Ctrl+C")

if __name__ == "__main__":
    main()
