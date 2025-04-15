#!/bin/bash
# Combined Proxy Setup/Reset Script
# Usage:

port=8080

# Function to set up proxy settings
setup_proxy() {
    local mode="$1"
    echo "Starting proxy setup..."

    # Enable IP forwarding for IPv4 and IPv6
    sudo sysctl -w net.ipv4.ip_forward=1
    sudo sysctl -w net.ipv6.conf.all.forwarding=1

    # Disable ICMP redirects
    sudo sysctl -w net.ipv4.conf.all.send_redirects=0

    # (Optional) Flush any existing NAT rules before adding new ones
    sudo iptables -t nat -F

    if [ "$mode" = "-r" ]; then
        echo "Setting up router-based traffic redirection on interface wlp0s20f3..."
        sudo iptables -t nat -A PREROUTING -i wlp0s20f3 -p udp --dport 80 -j REDIRECT --to-port $port
        sudo iptables -t nat -A PREROUTING -i wlp0s20f3 -p udp --dport 443 -j REDIRECT --to-port $port
        sudo ip6tables -t nat -A PREROUTING -i wlp0s20f3 -p tcp --dport 80 -j REDIRECT --to-port $port
        sudo ip6tables -t nat -A PREROUTING -i wlp0s20f3 -p tcp --dport 443 -j REDIRECT --to-port $port
    elif [ "$mode" = "-w" ]; then
        echo "Setting up Waydroid VM traffic redirection on interface waydroid0..."
        sudo iptables -t nat -A PREROUTING -i waydroid0 -p tcp --dport 80 -j REDIRECT --to-port $port
        sudo iptables -t nat -A PREROUTING -i waydroid0 -p tcp --dport 443 -j REDIRECT --to-port $port
        sudo ip6tables -t nat -A PREROUTING -i waydroid0 -p tcp --dport 80 -j REDIRECT --to-port $port
        sudo ip6tables -t nat -A PREROUTING -i waydroid0 -p tcp --dport 443 -j REDIRECT --to-port $port
        adb shell settings put global http_proxy "192.168.240.1:$port"
        adb shell settings put global https_proxy "192.168.240.1:$port"
    else
        echo "Invalid mode. Use '-r' for router or '-w' for Waydroid VM."
        exit 1
    fi

    echo "Proxy setup complete."
}

# Function to reset proxy settings
reset_proxy() {
    local mode="$1"
    echo "Starting proxy reset..."

    # Disable IP forwarding for IPv4 and IPv6
    sudo sysctl -w net.ipv4.ip_forward=0
    sudo sysctl -w net.ipv6.conf.all.forwarding=0

    # Re-enable IPv4 send redirects
    sudo sysctl -w net.ipv4.conf.all.send_redirects=1

    if [ "$mode" = "-r" ]; then
        echo "Reverting router-based proxy settings on interface wlp0s20f3..."
        sudo iptables -t nat -D PREROUTING -i wlp0s20f3 -p udp --dport 80 -j REDIRECT --to-port $port
        sudo iptables -t nat -D PREROUTING -i wlp0s20f3 -p udp --dport 443 -j REDIRECT --to-port $port
        sudo ip6tables -t nat -D PREROUTING -i wlp0s20f3 -p tcp --dport 80 -j REDIRECT --to-port $port
        sudo ip6tables -t nat -D PREROUTING -i wlp0s20f3 -p tcp --dport 443 -j REDIRECT --to-port $port
        echo "Router-based proxy settings reverted."
    elif [ "$mode" = "-w" ]; then
        echo "Reverting Waydroid VM proxy settings on interface waydroid0..."
        sudo iptables -t nat -D PREROUTING -i waydroid0 -p tcp --dport 80 -j REDIRECT --to-port $port
        sudo iptables -t nat -D PREROUTING -i waydroid0 -p tcp --dport 443 -j REDIRECT --to-port $port
        sudo ip6tables -t nat -D PREROUTING -i waydroid0 -p tcp --dport 80 -j REDIRECT --to-port $port
        sudo ip6tables -t nat -D PREROUTING -i waydroid0 -p tcp --dport 443 -j REDIRECT --to-port $port
        adb shell settings put global http_proxy ":0"
        adb shell settings put global https_proxy ":0"
        echo "Waydroid VM proxy settings reverted."
    else
        echo "Invalid mode. Use '-r' for router or '-w' for Waydroid VM."
        exit 1
    fi

    # Flush the NAT table to remove any remaining proxy rules
    sudo iptables -t nat -F

    echo "Proxy reset complete."
}

# Ensure exactly two arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 {setup|reset} {-r|-w}"
    exit 1
fi

command="$1"
mode="$2"

case "$command" in
    setup)
        setup_proxy "$mode"
        ;;
    reset)
        reset_proxy "$mode"
        ;;
    *)
        echo "Invalid command. Use 'setup' or 'reset'."
        exit 1
        ;;
esac
