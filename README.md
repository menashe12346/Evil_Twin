# 🔐 Evil Twin Attack & Defense Toolkit (Wi-Fi Pentest Project)

## 📚 Overview

This project demonstrates both **offensive** and **defensive** techniques involving *Evil Twin* Wi-Fi attacks. It contains two major components:

1. **Evil Twin Attack Toolkit**:
   - Sets up a fake Wi-Fi Access Point (AP) with the same SSID as a real one.
   - Scans for connected clients.
   - Allows targeted *Deauthentication (Deauth)* attacks to disconnect users.

2. **Evil Twin Defense Tool**:
   - Monitors nearby Wi-Fi networks in real-time.
   - Detects cloned SSIDs with different BSSIDs or signal anomalies.
   - Alerts the user.

---

## 📁 Project Structure

```
evil_twin/
├── attack/
│   ├── start_attack.py           # Main script to launch Evil Twin + Deauth attack
│   ├── start_hostapd.sh          # Bash script to configure and run hostapd
│   ├── hostapd.conf              # Config file for fake AP
│   ├── set_monitor.sh            # Switches adapter to monitor mode
│   ├── set_managed.sh            # Restores adapter to managed mode
│   ├── set_master.sh             # Switches adapter to monitor mode
│   ├── dhcp_server.sh            # start DHCP server and Captive Portal
│   └── find_target.py            # Scans and allows user to choose target client
│
├── defense/
│   └── identify_evil_twin_attack.py  # Real-time background scanner to detect cloned SSIDs

etc
rquriments.txt

```

---

## ⚙️ Requirements

- Linux OS (tested on Arch)
- Python 3.8+
- Wi-Fi adapter that supports:
  - Monitor mode
  - AP mode
  - Packet injection
- `hostapd` installed and accessible
- Python libraries:
  ```bash
  pip install -r requirements.txt
  ```
  Contents:
  ```
  scapy
  tabulate
  manuf
  ```

---

## 🧪 1. Evil Twin Attack Tool

### 🧷 Functionality:
- Sets up fake AP with desired SSID using `hostapd`.
- Sniffs nearby clients of real APs.
- Allows selecting a client and performing a `deauth` attack.

### ▶️ How to Run

```bash
cd attack
sudo python3 start_attack.py
```

You'll be guided through:
1. Interface selection and switching to monitor/AP mode.
2. SSID setup.
3. Scanning for connected clients.
4. Deauth attack.

### 🔧 Notes:
- `hostapd.conf` must match your desired settings (will be edited automatically).
- Use only on authorized networks for testing or lab environments!

---

## 🛡️ 2. Evil Twin Detection Tool

### 🧷 Functionality:
- Constantly scans all Wi-Fi networks.
- Detects duplicate SSIDs with different BSSIDs or suspicious signal strengths (RSSI).
- Flags anomalies and prints alerts to the screen.

### ▶️ How to Run

```bash
cd defense
sudo python3 identify_evil_twin_attack.py
```

### 🔒 Defense Strategy:
- Scans every few seconds using `Scapy` in monitor mode.
- Identifies SSIDs with more than one BSSID.
- Compares signal strength to detect possible fakes.
- Future extensions may include:
  - Automatic deauth of malicious AP.
  - Logging & notification integration.

---

## 🛠️ Installation & Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/menashe12346/evil_twin.git
   cd evil_twin
   ```

2. Install dependencies:
   ```bash
   sudo apt install hostapd
   pip install -r requirements.txt
   ```

3. Make shell scripts executable:
   ```bash
   chmod +x attack/*.sh
   ```

4. Run scripts with `sudo` (due to network interface manipulation).

---

## ⚠️ Legal Notice

> ⚠️ **Use responsibly!** This project is for educational purposes and ethical testing in legal environments (e.g., lab, CTF, bug bounty). Do **not** use this toolkit on networks or devices you don't own or have explicit permission to test.

---
