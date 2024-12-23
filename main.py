import frida
import sys
import json
import os

# List of script paths to load
# SCRIPT_PATHS = [ "scripts/ssl.js", "scripts/react.js",  "scripts/alerts.js"]
SCRIPT_PATHS = [ "scripts/storage.js",  "scripts/rn.js"]

APP_PACKAGE_NAME = "Frida Play"
OUTPUT_PATH = f"output/{APP_PACKAGE_NAME.lower().replace(' ', '')}_request_output.txt"

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

    # Load each script
    for script_path in SCRIPT_PATHS:
        with open(script_path) as f:
            script = session.create_script(f.read())
        print(f"[+] Loaded script from {script_path}")

        # Set message handler for each script
        script.on("message", on_message)
        script.load()
        print(f"[*] Script {script_path} successfully injected and running...")

    # Keep the script running
    sys.stdin.read()

except frida.ProcessNotFoundError:
    print(f"[!] App {APP_PACKAGE_NAME} not found. Make sure it's running.")
except FileNotFoundError:
    print(f"[!] One or more script files not found.")
except Exception as e:
    print(f"[!] Unexpected error: {e}")
