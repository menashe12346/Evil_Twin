#!/bin/bash

CONFIG="hostapd.conf"
INTERFACE="wlp4s0f4u1"
PID_FILE="/tmp/hostapd_pid.txt"

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ Please run this script as root (use: sudo $0)"
   exit 1
fi

# Cleanup function to kill hostapd and reset interface
cleanup() {
    echo "🧹 Cleaning up hostapd processes..."
    
    # Kill known background process
    if [ -f "$PID_FILE" ]; then
        pid=$(cat "$PID_FILE")
        echo "🛑 Killing hostapd process: $pid"
        kill -9 "$pid" 2>/dev/null
        rm "$PID_FILE"
    fi

    # Also kill any leftover hostapd processes
    pids=$(ps aux | grep "$CONFIG" | grep -v grep | awk '{print $2}')
    if [ ! -z "$pids" ]; then
        echo "🛑 Killing additional hostapd processes: $pids"
        kill -9 $pids
    fi

    # Reset interface
    echo "🔄 Resetting interface: $INTERFACE"
    ip link set "$INTERFACE" down
    iw dev "$INTERFACE" set type managed
    ip link set "$INTERFACE" up

    echo "✅ Cleanup complete."
    exit 0
}

# Trap Ctrl+C, kill, background stop, and exit
trap cleanup SIGINT SIGTERM SIGTSTP

echo "🚀 Starting hostapd in background with config: $CONFIG"
hostapd "$CONFIG" &
echo $! > "$PID_FILE"

echo "💡 Type 'exit' to stop hostapd and clean up."
while true; do
    read -rp "> " input
    if [[ "$input" == "exit" ]]; then
        cleanup
    fi
done
