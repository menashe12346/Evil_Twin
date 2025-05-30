#!/bin/bash

enable_managed_mode() {
    INTERFACE="$1"

    if [[ -z "$INTERFACE" ]]; then
        echo "❌ Usage: enable_managed_mode <interface>"
        exit 1
    fi

    echo "[*] Stopping interfering network services..."
    systemctl stop NetworkManager
    systemctl stop wpa_supplicant

    echo "[*] Bringing down interface $INTERFACE..."
    ip link set "$INTERFACE" down

    echo "[*] Setting $INTERFACE to managed mode..."
    iw dev "$INTERFACE" set type managed || iwconfig "$INTERFACE" mode managed

    echo "[*] Bringing up interface $INTERFACE..."
    ip link set "$INTERFACE" up

    echo "[*] Bringing up interfering network services..."
    systemctl start NetworkManager
    systemctl start wpa_supplicant

    echo "[*] Current interface status:"
    iwconfig "$INTERFACE"

    echo "[✓] $INTERFACE is now in managed mode."
}

# Entry point
enable_managed_mode "$1"
