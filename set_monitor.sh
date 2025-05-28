#!/bin/bash

INTERFACE="wlp4s0f4u1"

enable_monitor_mode() {

    if [[ -z "$INTERFACE" ]]; then
        echo "❌ Usage: enable_monitor_mode <interface>"
        exit 1
    fi

    echo "[*] Stopping interfering network services..."
    systemctl stop NetworkManager
    systemctl stop wpa_supplicant

    echo "[*] Bringing down interface $INTERFACE..."
    ip link set "$INTERFACE" down

    echo "[*] Setting $INTERFACE to monitor mode..."
    iw dev "$INTERFACE" set type monitor || iwconfig "$INTERFACE" mode monitor

    echo "[*] Bringing up interface $INTERFACE..."
    ip link set "$INTERFACE" up

    echo "[*] Bringing up interfering network services..."
    systemctl start NetworkManager
    systemctl start wpa_supplicant

    echo "[*] Current interface status:"
    iwconfig "$INTERFACE"

    echo "[✓] $INTERFACE is now in monitor mode."
}

# Entry point
enable_monitor_mode "$1"
