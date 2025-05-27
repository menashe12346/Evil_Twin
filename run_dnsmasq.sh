#!/bin/bash

CONFIG="dnsmasq.conf"
INTERFACE="wlp4s0f4u1"
#INTERFACE="wlp2s0"
PID_FILE="/tmp/dnsmasq_pid.txt"

# Cleanup function (only before starting)
cleanup() {
    echo "🧹 Cleaning up dnsmasq processes..."

    # Kill known PID from previous run
    if [ -f "$PID_FILE" ]; then
        pid=$(cat "$PID_FILE")
        echo "🛑 Killing dnsmasq process: $pid"
        sudo kill -9 "$pid" 2>/dev/null
        rm -f "$PID_FILE"
    fi

    # Kill any additional dnsmasq processes
    pids=$(ps aux | grep '[d]nsmasq' | grep -v $$ | awk '{print $2}')
    if [ ! -z "$pids" ]; then
        echo "🛑 Killing additional dnsmasq processes: $pids"
        sudo kill -9 $pids
    fi

    echo "✅ dnsmasq cleanup complete."
}

### --- CLEANUP BEFORE START ---
echo "🔍 Cleaning old dnsmasq processes before starting..."
cleanup

### --- CONTINUE ---
echo "[*] Assigning IP address to the interface..."
sudo ip addr add 192.168.1.1/24 dev "$INTERFACE" 2>/dev/null

echo "[*] Starting dnsmasq with config: $CONFIG"
sudo dnsmasq -d -C "$CONFIG" &
echo $! > "$PID_FILE"
