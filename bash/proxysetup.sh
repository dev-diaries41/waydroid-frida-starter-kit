#!/bin/bash

# User input
local=$1 # local for mitm traffic running on same device, don't include to mitm a different device

# Setup based on: https://docs.mitmproxy.org/stable/howto-transparent/

# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Disable ICMP redirects
sudo sysctl -w net.ipv4.conf.all.send_redirects=0

if [ "$local" = "-r" ]; then # check if is via router
	echo "Setting all proxied router traffic for port 8080"
	sudo iptables -t nat -A PREROUTING -i wlp0s20f3 -p udp --dport 80 -j REDIRECT --to-port 8080
	sudo iptables -t nat -A PREROUTING -i wlp0s20f3 -p udp --dport 443 -j REDIRECT --to-port 8080
	sudo ip6tables -t nat -A PREROUTING -i wlp0s20f3 -p tcp --dport 80 -j REDIRECT --to-port 8080
	sudo ip6tables -t nat -A PREROUTING -i wlp0s20f3 -p tcp --dport 443 -j REDIRECT --to-port 8080
fi

if [ "$local" = "-w" ]; then # check if is local waydroid vm, simple
	echo "Waydroid VM traffic routed to port 8080"
	sudo iptables -t nat -A PREROUTING -i waydroid0 -p tcp --dport 80 -j REDIRECT --to-port 8080
	sudo iptables -t nat -A PREROUTING -i waydroid0 -p tcp --dport 443 -j REDIRECT --to-port 8080
	sudo ip6tables -t nat -A PREROUTING -i waydroid0 -p tcp --dport 80 -j REDIRECT --to-port 8080
	sudo ip6tables -t nat -A PREROUTING -i waydroid0 -p tcp --dport 443 -j REDIRECT --to-port 8080
	adb shell settings put global http_proxy "192.168.240.1:8080"
	adb shell settings put global https_proxy "192.168.240.1:8080"  
fi

echo "Setting ports 80, 443 to redirect to 8080. Finished"
sudo iptables -t nat -F