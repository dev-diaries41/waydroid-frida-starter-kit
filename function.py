import frida
import sys
import json
import os
import time 

OUTPUT_PATH = f"output/function_trace_output_{time.time().__ceil__()}.txt"
SCRIPT_PATH = "scripts/functions.js"
APP_PACKAGE_NAME = "Indie U"

def on_message(message, data):
    if message['type'] == 'send':
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        with open(OUTPUT_PATH, "a") as file:
            file.write(json.dumps(message['payload'], indent=4) + "\n")
        print(f"[*] Data saved to {OUTPUT_PATH}")
    else:
        print(f"[!] Error: {message}")

try:
    # Connect to the device
    device = frida.get_usb_device()
    print(f"[+] Connected to device: {device.name}")

    # Attach to the app
    session = device.attach(APP_PACKAGE_NAME)
    print(f"[+] Attached to app: {APP_PACKAGE_NAME}")

    # Load the Frida script
    with open(SCRIPT_PATH) as f:
        script = session.create_script(f.read())
    print(f"[+] Loaded script from {SCRIPT_PATH}")

    # Set message handler
    script.on("message", on_message)
    script.load()
    print("[*] Script successfully injected and running...")

    # Keep the script running
    sys.stdin.read()

except frida.ProcessNotFoundError:
    print(f"[!] App {APP_PACKAGE_NAME} not found. Make sure it's running.")
except FileNotFoundError:
    print(f"[!] Script file {SCRIPT_PATH} not found.")
except Exception as e:
    print(f"[!] Unexpected error: {e}")
