#!/bin/bash

echo "[*] Stopping any running dnsmasq processes..."
sudo killall dnsmasq 2>/dev/null

echo "[*] Assigning IP address to the interface..."
sudo ip addr add 192.168.1.1/24 dev wlp4s0f4u1 2>/dev/null

echo "[*] Starting dnsmasq with config: dnsmasq.conf"
sudo dnsmasq -C dnsmasq.conf
