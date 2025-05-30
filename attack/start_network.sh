#!/bin/bash

CONFIG="hostapd.conf"
PID_FILE="hostapd.pid"

start_hostapd() {
    INTERFACE="$1"
    SSID="$2"

    if [[ -z "$INTERFACE" || -z "$SSID" ]]; then
        echo "❌ Usage: start_hostapd <INTERFACE> <SSID>"
        return 1
    fi

    if [[ $EUID -ne 0 ]]; then
        echo "❌ Please run this script as root (use: sudo $0)"
        return 1
    fi

    echo "📝 Updating INTERFACE in $CONFIG to: $INTERFACE"
    sed -i "s/^interface=.*/interface=$INTERFACE/" "$CONFIG"

    echo "📝 Updating SSID in $CONFIG to: $SSID"
    sed -i "s/^ssid=.*/ssid=$SSID/" "$CONFIG"

    echo "🚀 Starting hostapd in background with config: $CONFIG"
    hostapd "$CONFIG" &
    echo $! > "$PID_FILE"
}

if [[ "$1" == "run_function" && "$2" == "start_hostapd" ]]; then
    INTERFACE="$3"
    #SSID="$4 1"
    SSID="Menashe"
    start_hostapd "$INTERFACE" "$SSID"
    exit 0
fi
