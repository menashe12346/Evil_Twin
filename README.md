# 🔐 Evil Twin Attack & Defense Toolkit (Wi-Fi Pentest Project)

## 📚 Overview

This project demonstrates both **offensive** and **defensive** techniques involving *Evil Twin* Wi-Fi attacks. It contains two major components:

1. **Evil Twin Attack Toolkit**:
   - Sets up a fake Wi-Fi Access Point (AP) with the same SSID as a real one.
   - Starts a captive portal and DHCP server.
   - Scans for connected clients.
   - Allows targeted *Deauthentication (Deauth)* attacks to disconnect users.
   - Wait for client to reconnect to fake AP
   - Capture credentials via login portal

2. **Evil Twin Defense Tool**:
   - Monitors nearby Wi-Fi networks in real-time.
   - Detects cloned SSIDs with different BSSIDs or signal anomalies.
   - Alerts the user.

---

## 📁 Project Structure

```
evil_twin/
├── attack/
│   ├── start_attack.py              # Main script to launch Evil Twin + Deauth attack
│   ├── start_network.sh             # Launch hostapd and captive portal
│   ├── dhcp_server.py               # DHCP server + HTTP portal
│   ├── find_target.py               # Scans and selects AP & client
│   ├── deauthentication_attack.py   # Sends deauth packets
│   ├── hostapd.conf                 # Config file for fake AP
│   ├── index.html                   # HTML captive portal page
│
├── change_interface_mode/
│   ├── set_monitor.sh               # Switch adapter to monitor mode
│   ├── set_master.sh                # Switch adapter to master/AP mode
│   └── set_managed.sh               # Restore adapter to managed mode
│
├── defense/
│   └── identify_evil_twin_attack.py # Real-time Evil Twin detection scanner
│
├── requirements.txt                 # Python dependencies
└── README.md
```

---

## ⚙️ Requirements

- Linux OS (tested on Arch/Ubuntu)
- Python 3.8+
- Wi-Fi adapter that supports:
  - Monitor mode
  - AP mode
  - Packet injection
- `hostapd` installed and accessible in PATH

---

## ▶️ How to Run

### 🧪 1. Evil Twin Attack Tool

```bash
cd attack
sudo python start_attack.py
```

This will:
1. Set interfaces to the required mode.
2. Ask you to choose a network.
3. Launch the fake AP.
4. Start captive portal on 192.168.1.1 & DHCP server.
5. Ask you to choose client to Launch the deauthentication attack on.
6. Capture credentials via login portal

---

### 🛡️ 2. Evil Twin Detection Tool

```bash
cd defense
sudo python identify_evil_twin_attack.py
```

You will see real-time alerts if Evil Twin behavior is detected.

---

## 🛠️ Installation & Setup

1. Clone the repository:
```bash
git clone https://github.com/menashe12346/evil_twin.git
cd evil_twin
```

2. Install system dependencies:
```bash
sudo apt install hostapd
```

3. Install Python requirements:
```bash
pip install -r requirements.txt
```

4. Make shell scripts executable:
```bash
chmod +x change_interface_mode/*.sh
chmod +x attack/start_network.sh
```

5. Run scripts with `sudo` due to the need for low-level access to network interfaces.

---

## ⚠️ Legal Notice

> ⚠️ **Use responsibly!** This project is intended for ethical hacking, security education, and testing in controlled lab environments. Never use these tools on unauthorized networks or devices. Make sure you have explicit permission.

---