#!/bin/bash

# הגדרות
INTERFACE_IN="wlp4s0f4u1"
INTERFACE_OUT="wlp2s0"
CAPTIVE_IP="192.168.1.1"

# ודא שהסקריפט רץ כ-root
if [[ $EUID -ne 0 ]]; then
   echo "❌ Please run this script as root (use: sudo $0)"
   exit 1
fi

echo "🧹 Cleaning old iptables rules..."
iptables -t nat -F PREROUTING
iptables -F FORWARD

add_if_not_exists() {
    local table=$1
    shift
    local rule=("$@")
    
    if iptables -t "$table" -C "${rule[@]}" 2>/dev/null; then
        echo "🔁 Rule already exists: iptables -t $table -A ${rule[*]}"
    else
        echo "➕ Adding rule: iptables -t $table -A ${rule[*]}"
        iptables -t "$table" -A "${rule[@]}"
    fi
}

# הפניית HTTP ל־192.168.1.1:80
add_if_not_exists nat -i "$INTERFACE_IN" -p tcp --dport 80 -j DNAT --to-destination "$CAPTIVE_IP:80"

# הפניית HTTPS ל־פורט 80
add_if_not_exists nat -i "$INTERFACE_IN" -p tcp --dport 443 -j REDIRECT --to-port 80

# הפניית DNS ל־192.168.1.1:53
add_if_not_exists nat -i "$INTERFACE_IN" -p udp --dport 53 -j DNAT --to-destination "$CAPTIVE_IP:53"

# חסום הכל מה-WiFi כלפי חוץ כברירת מחדל
add_if_not_exists filter -i "$INTERFACE_IN" -o "$INTERFACE_OUT" -j REJECT

# תן תשובות חוזרות מחוץ לרשת אל הלקוח
add_if_not_exists filter -i "$INTERFACE_OUT" -o "$INTERFACE_IN" -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "✅ iptables setup complete."
