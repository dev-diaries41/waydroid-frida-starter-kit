#!/bin/bash

port=8080

# User input
local=$1  # local for mitm traffic, router or Waydroid

# Disable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=0
sudo sysctl -w net.ipv6.conf.all.forwarding=0

# Re-enable IPv4 send redirects
sudo sysctl -w net.ipv4.conf.all.send_redirects=1

if [ "$local" = "-r" ]; then
    # Revert iptables rules for router-based traffic
    echo "Reverting proxy settings for router-based traffic (port 8080)..."
    sudo iptables -t nat -D PREROUTING -i wlp0s20f3 -p udp --dport 80 -j REDIRECT --to-port $port
    sudo iptables -t nat -D PREROUTING -i wlp0s20f3 -p udp --dport 443 -j REDIRECT --to-port $port
    sudo ip6tables -t nat -D PREROUTING -i wlp0s20f3 -p tcp --dport 80 -j REDIRECT --to-port $port
    sudo ip6tables -t nat -D PREROUTING -i wlp0s20f3 -p tcp --dport 443 -j REDIRECT --to-port $port
    echo "Router-based traffic proxy settings reverted."

elif [ "$local" = "-w" ]; then
    # Revert iptables rules for Waydroid VM-based traffic
    echo "Reverting proxy settings for Waydroid VM traffic..."
    sudo iptables -t nat -D PREROUTING -i waydroid0 -p tcp --dport 80 -j REDIRECT --to-port $port
    sudo iptables -t nat -D PREROUTING -i waydroid0 -p tcp --dport 443 -j REDIRECT --to-port $port
    sudo ip6tables -t nat -D PREROUTING -i waydroid0 -p tcp --dport 80 -j REDIRECT --to-port $port
    sudo ip6tables -t nat -D PREROUTING -i waydroid0 -p tcp --dport 443 -j REDIRECT --to-port $port
    adb shell settings put global http_proxy :0
    adb shell settings put global https_proxy :0
    echo "Waydroid VM traffic proxy settings reverted."

else
    echo "Invalid local argument. Use '-r' for router or '-w' for Waydroid VM."
    exit 1
fi

echo "Proxy settings reverted successfully."
sudo iptables -t nat -F
