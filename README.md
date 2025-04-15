# Waydroid Frida Starter Kit

This repository provides a comprehensive set of tools and information to start pentesting Android applications using Frida. It's specifically designed for use with **Waydroid**, but the included scripts can also be adapted for other Android devices or emulators with minimal adjustments. I focused on waydroid because it provides the perfect development environment for pentesting and also when i was starting to pentest android apps myself, i noticed there was little information about doing it using waydroid.

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
$ sudo cp Portswigger.der /var/lib/waydroid/overlay/system/etc/security/cacerts/13acab12.0
$ sudo chmod 644 /var/lib/waydroid/overlay/system/etc/security/cacerts/13acab12.0
```

Make sure to replace `Portswigger.der` with the actual path to the .der file you exported from Burpsuite and replace `13acab12` with the acutal hash produced in step 1. You may need to restart waydroid.

## Bash Scripts

The `bash/` directory includes various scripts designed to manage the Frida server and proxy settings on Waydroid.


Here's your updated **README** reflecting the merged **proxy.sh** script:  

---

### **Available Scripts**  

- **frida.sh**  
  Manages the Frida server on Waydroid, including setup, starting, and stopping.  

- **proxy.sh**  
  Configures and resets proxy settings for routing traffic through Frida, either via a **router** (`-r`) or **Waydroid VM** (`-w`).  

---

### **Usage**  

#### **1. Setup Frida Server on Waydroid**  
Run the `frida.sh` script with the `-setup` flag to install the necessary Frida server on your Waydroid container.  
```bash
./frida.sh -setup
```

#### **2. Start the Frida Server**  
Start the Frida server on Waydroid:  
```bash
./frida.sh -start
```

#### **3. Stop the Frida Server**  
To stop the Frida server, use:  
```bash
./frida.sh -stop
```

#### **4. Setup Proxy for Traffic Interception**  
To redirect traffic through Frida, use:  
- **Router-based traffic redirection**  
  ```bash
  ./proxy.sh setup -r
  ```
- **Waydroid VM traffic redirection**  
  ```bash
  ./proxy.sh setup -w
  ```

#### **5. Reset Proxy Settings**  
To revert proxy settings back to default, use:  
- **Reset router-based proxy settings**  
  ```bash
  ./proxy.sh reset -r
  ```
- **Reset Waydroid VM proxy settings**  
  ```bash
  ./proxy.sh reset -w
  ```

---


## Frida Scripts

The `scripts/` directory contains various Frida scripts designed to assist in pentesting Android applications.

