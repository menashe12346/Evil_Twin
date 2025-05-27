#!/bin/bash

# Replace this with the name of your wireless interface
INTERFACE="wlp4s0f4u1"
TYPE="monitor"

echo "[*] Stopping network services that may lock the interface..."
sudo systemctl stop NetworkManager
sudo systemctl stop wpa_supplicant

echo "[*] Bringing down interface $INTERFACE..."
sudo ip link set $INTERFACE down

echo "[*] Setting interface to $TYPE mode..."
sudo iw dev $INTERFACE set type $TYPE || sudo iwconfig $INTERFACE mode $TYPE

echo "[*] Bringing the interface back up..."
sudo ip link set $INTERFACE up
sudo systemctl start NetworkManager
sudo systemctl start wpa_supplicant

echo "[*] Current interface mode:"
iwconfig $INTERFACE

echo "[✓] Done. Verify that mode is '$TYPE'."
