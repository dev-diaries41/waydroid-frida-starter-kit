#!/bin/bash

check_device() {
  adb devices | grep -w "device" > /dev/null
  if [ $? -ne 0 ]; then
    echo "[ERROR] No device connected. Please connect a device and try again."
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


stop_frida_server() {
  # Get the PID of frida-server
  pid=$(adb shell "ps | grep frida-server" | awk '{print $2}')
  
  # Check if a PID was found
  if [ -n "$pid" ]; then
    echo "Found frida-server with PID: $pid"
    
    # Kill the process
    adb shell "su -c 'kill $pid'"
    echo "Process with PID $pid has been killed."
  else
    echo "frida-server process not found."
  fi
}

# Check if the correct flag was provided
if [ "$1" == "-start" ]; then
  check_device
  start_frida_server
elif [ "$1" == "-stop" ]; then
  check_device
  stop_frida_server
else
  echo "Usage: $0 [-start|-stop]"
  echo "  -start   Start the Frida server"
  echo "  -stop    Stop the Frida server"
  exit 1
fi
