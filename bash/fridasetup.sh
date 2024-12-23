#!/bin/bash

# Function to check if a device is connected
check_device() {
  adb devices | grep -w "device" > /dev/null
  if [ $? -ne 0 ]; then
    echo "[ERROR] No device connected. Please connect a device and try again."
    exit 1
  fi
}

# Function to create and activate a virtual environment
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

# Function to download and set up Frida server
setup_frida_server() {
  echo "[INFO] Downloading Frida server..."
  wget https://github.com/frida/frida/releases/download/16.5.9/frida-server-16.5.9-android-x86_64.xz
  if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to download Frida server."
    exit 1
  fi

  echo "[INFO] Decompressing Frida server..."
  unxz frida-server-16.5.9-android-x86_64.xz
  if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to decompress Frida server."
    exit 1
  fi

  mv frida-server-16.5.9-android-x86_64 frida-server
  echo "[INFO] Pushing Frida server to Waydroid..."
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


start_frida_server() {
  # Start the Frida server in the background using nohup or disown
  adb shell "su -c '/data/local/tmp/frida-server &'" &

  # Wait briefly to allow the server to start
  sleep 2

  # Check if Frida server is running
  adb shell "ps | grep frida-server" > /dev/null
  if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to start Frida server."
    exit 1
  else
    echo "[INFO] Frida server started successfully."
  fi
} 


# Main execution flow
check_device
setup_venv
setup_frida_server
start_frida_server

echo "[INFO] All steps completed successfully. You can now inject your Frida script using the following command:"
echo "frida -U -f <app_package_name> -l /path/to/your/script.js --no-pause"
exit 0
