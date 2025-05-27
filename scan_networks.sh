#!/bin/bash

# Replace this with the name of your wireless interface
INTERFACE="wlp2s0"

echo "[*] Scaning Networks..."
sudo iwlist $INTERFACE scan | grep ESSID
