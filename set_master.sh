#!/bin/bash

INTERFACE="wlp4s0f4u1"

enable_master_mode() {

    if [[ -z "$INTERFACE" ]]; then
        echo "❌ Usage: enable_master_mode <interface>"
        exit 1
    fi

    echo "[*] Bringing down interface $INTERFACE..."
    ip link set "$INTERFACE" down

    echo "[*] Setting interface $INTERFACE to __ap (master) mode..."
    iw dev "$INTERFACE" set type __ap

    echo "[*] Bringing up interface $INTERFACE..."
    ip link set "$INTERFACE" up

    echo "[*] Current interface status:"
    iwconfig "$INTERFACE"

    echo "[✓] Interface $INTERFACE is now in '__ap' (master) mode."
}

# Entry point
enable_master_mode
