#!/bin/bash

# Replace this with the name of your wireless interface
INTERFACE="wlp4s0f4u1"

echo "[*] Scaning Networks..."
sudo iwlist $INTERFACE scan | grep ESSID
