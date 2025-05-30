#!/bin/bash

CONFIG="hostapd.conf"
PID_FILE="/tmp/hostapd_pid.txt"

start_hostapd() {
    INTERFACE="$1"
    SSID="$2"

    if [[ -z "$SSID" ]]; then
        echo "❌ Usage: start_hostapd <INTERFACE> <SSID>"
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

    # Inject INTERFACE into the config
    echo "📝 Updating INTERFACE in $CONFIG to: $INTERFACE"
    sed -i "s/^interface=.*/interface=$INTERFACE/" "$CONFIG"

    echo "🚀 Starting hostapd in background with config: $CONFIG"
    hostapd "$CONFIG" &
    echo $! > "$PID_FILE"
}

# Example usage: pass SSID as argument to the script
start_hostapd "$1"
