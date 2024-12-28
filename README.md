# Waydroid Frida Starter Kit

This repository provides a comprehensive set of tools and information to start pentesting Android applications using Frida. It's specifically designed for use with **Waydroid**, but the included scripts can also be adapted for other Android devices or emulators with minimal adjustments. I focused on waydroid because it provides the perfect development environment pentesting and also when i was starting to pentest android apps myself, i noticed there was little information about doing it using waydroid.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Burp suite proxy](#burp-suite-proxy)
- [Bash Scripts](#bash-scripts)
- [Frida Scripts](#frida-scripts)

## Prerequisites

Before using this kit, ensure the following are installed on your system:

- **ADB** (Android Debug Bridge)  
  Required to interact with Android devices and emulators.  
  Install via:
  ```bash
  sudo apt install android-tools
  ```

- **Waydroid**  
  A container-based Android system for Linux distributions.  
  Follow the [Waydroid installation guide](https://waydro.id/) for your specific distribution.

- **Rooted Device**
  Folllow these [instructions](https://github.com/casualsnek/waydroid_script) to root waydroid using magisk.

## Installation

1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/dev-diaries41/waydroid-frida-starter-kit.git
   cd waydroid-frida-starter-kit
   ```

2. Ensure that **ADB** and **Waydroid** are properly installed and running.


## Burp suite proxy

Follow the [Burp suite instructions](https://portswigger.net/burp/documentation/desktop/mobile/config-android-device) here to configure a proxy listener (step 1). Step 2 in the burp suite instructions can be skipped, use the proxysetup.sh script below instead. Once you have downloaded your certificate by following the instruction in step 3 you will need to do the following:

1. Find out the hash of the certificate subject name using the older algorithm as used by OpenSSL before version 1.0.0:

```bash
$ openssl x509 -subject_hash_old -in Portswigger.der | head -1
13acab12
```

2. Create the /system/etc/security/cacerts/ directory on the overlay FS:
```bash
$ sudo mkdir -p /var/lib/waydroid/overlay/system/etc/security/cacerts/
```

3. Copy the certificate, renaming it to the hash from step 1, with .0 appended, and set the proper permissions for it:

```bash
$ sudo cp my-ca-cert.pem /var/lib/waydroid/overlay/system/etc/security/cacerts/13acab12.0
$ sudo chmod 644 /var/lib/waydroid/overlay/system/etc/security/cacerts/13acab12.0
```

Make sure to replace `Portswigger.der` with the actual path to the .der file you exported from Burpsuite and replace `13acab12` with the acutal hash produced in step 1. You may need to restart waydroid.

## Bash Scripts

The `bash/` directory includes various scripts designed to manage the Frida server and proxy settings on Waydroid.

### Available Scripts

- **fridasetup.sh**  
  Installs and sets up the Frida server on Waydroid.
  
- **fridaserver.sh**  
  Starts or stops the Frida server on the Waydroid container based on the corresponding flag -start or -stop.

- **proxysetup.sh**  
  Configures the proxy settings to route traffic through Frida, enabling interaction with apps.
  
- **proxyrevert.sh**  
  Reverts any proxy settings back to default after testing.


### Usage Example

1. **Setup Frida Server on Waydroid**  
   Run the `fridasetup.sh` script to install the necessary Frida server on your Waydroid container.
   ```bash
   ./bash/fridasetup.sh
   ```

2. **Start the Frida Server**  
   Start the Frida server on Waydroid using:
   ```bash
   ./bash/fridaserver.sh -start
   ```

3. **Stop the Frida Server**  
   To stop the Frida server, use:
   ```bash
   ./bash/fridaserver.sh -stop
   ```

4. **Configure Proxy**  
   Set up proxy settings to route traffic through Frida. You can configure the proxy for either router-based traffic or Waydroid VM-based traffic by using the `-r` or `-w` flags:

   - For router-based traffic (local network):
     ```bash
     ./bash/proxysetup.sh -r
     ```

   - For Waydroid VM-based traffic:
     ```bash
     ./bash/proxysetup.sh -w
     ```

5. **Revert Proxy Settings**  
   If you need to revert the proxy settings, use the following commands:

   - To revert router traffic proxy settings:
     ```bash
     ./bash/proxyrevert.sh -r
     ```

   - To revert Waydroid VM traffic proxy settings:
     ```bash
     ./bash/proxyrevert.sh -w
     ```


## Frida Scripts

The `scripts/` directory contains various Frida scripts designed to assist in pentesting Android applications.

