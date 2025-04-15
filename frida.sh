#!/bin/bash

check_device() {
  adb devices | grep -w "device" > /dev/null
  if [ $? -ne 0 ]; then
    echo "[ERROR] No device connected. Please connect a device and try again."
    exit 1
  fi
}

setup_venv() {
  echo "[INFO] Setting up virtual environment..."
  python3 -m venv venv
  source venv/bin/activate
  if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to create or activate virtual environment."
    exit 1
  fi
  echo "[INFO] Installing Frida tools..."
  pip install frida-tools
  if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to install Frida tools."
    exit 1
  fi
}

setup_frida_server() {
  echo "[INFO] Downloading Frida server..."
  FRIDA_VERSION="16.5.9"
  FRIDA_ARCH="android-x86_64"
  FRIDA_FILENAME="frida-server-${FRIDA_VERSION}-${FRIDA_ARCH}.xz"

  wget "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FRIDA_FILENAME}"
  if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to download Frida server."
    exit 1
  fi

  echo "[INFO] Decompressing Frida server..."
  unxz "${FRIDA_FILENAME}"
  if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to decompress Frida server."
    exit 1
  fi

  mv "frida-server-${FRIDA_VERSION}-${FRIDA_ARCH}" frida-server
  echo "[INFO] Pushing Frida server to device..."
  adb push frida-server /data/local/tmp/
  if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to push Frida server."
    exit 1
  fi

  echo "[INFO] Setting permissions for Frida server..."
  adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
  if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to set permissions for Frida server."
    exit 1
  fi
}

# Function to start the Frida server
start_frida_server() {
  echo "[INFO] Starting Frida server..."
  adb shell "su -c '/data/local/tmp/frida-server &'" &

  sleep 2  # Allow time for the server to start

  adb shell "ps | grep frida-server" > /dev/null
  if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to start Frida server."
    exit 1
  else
    echo "[INFO] Frida server started successfully."
  fi
}

# Function to stop the Frida server
stop_frida_server() {
  echo "[INFO] Stopping Frida server..."
  pid=$(adb shell "ps | grep frida-server" | awk '{print $2}')
  
  if [ -n "$pid" ]; then
    echo "[INFO] Found frida-server with PID: $pid"
    adb shell "su -c 'kill $pid'"
    echo "[INFO] Frida server stopped successfully."
  else
    echo "[ERROR] Frida server process not found."
  fi
}

case "$1" in
  -setup)
    check_device
    setup_venv
    setup_frida_server
    echo "[INFO] Setup completed successfully."
    ;;
  -start)
    check_device
    start_frida_server
    ;;
  -stop)
    check_device
    stop_frida_server
    ;;
  *)
    echo "Usage: $0 [-setup|-start|-stop]"
    echo "  -setup   Install Frida and set up the environment"
    echo "  -start   Start the Frida server"
    echo "  -stop    Stop the Frida server"
    exit 1
    ;;
esac

