#!/bin/bash

CONFIG="hostapd.conf"
INTERFACE="wlp4s0f4u1"
PID_FILE="/tmp/hostapd_pid.txt"

start_hostapd() {
    SSID="$1"

    if [[ -z "$SSID" ]]; then
        echo "❌ Usage: start_hostapd <SSID>"
        return 1
    fi

    # Ensure the script is run as root
    if [[ $EUID -ne 0 ]]; then
        echo "❌ Please run this script as root (use: sudo $0)"
        return 1
    fi

    # Inject SSID into the config
    echo "📝 Updating SSID in $CONFIG to: $SSID"
    sed -i "s/^ssid=.*/ssid=$SSID/" "$CONFIG"

    # Define cleanup function
    cleanup() {
        echo "🧹 Cleaning up hostapd processes..."

        # Kill the known background process
        if [ -f "$PID_FILE" ]; then
            pid=$(cat "$PID_FILE")
            echo "🛑 Killing hostapd process: $pid"
            kill -9 "$pid" 2>/dev/null
            rm "$PID_FILE"
        fi

        # Kill any remaining hostapd processes
        pids=$(ps aux | grep "$CONFIG" | grep -v grep | awk '{print $2}')
        if [ ! -z "$pids" ]; then
            echo "🛑 Killing additional hostapd processes: $pids"
            kill -9 $pids
        fi

        # Reset the interface
        echo "🔄 Resetting interface: $INTERFACE"
        ip link set "$INTERFACE" down
        iw dev "$INTERFACE" set type managed
        ip link set "$INTERFACE" up

        echo "✅ Cleanup complete."
        exit 0
    }

    # Trap termination signals
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
}

# Example usage: pass SSID as argument to the script
start_hostapd "$1"
