# Mosquitto Broker Setup & Security Verification Guide

This guide details how to initialize, configure, and verify the Mosquitto MQTT broker on Windows for AegisAgent.

---

## 1. Create User Passwords

Open a command prompt in the project root directory and create the `passwd` file:

```cmd
# Create password file with first user (aegis_gateway) - prompts for password interactively
mosquitto_passwd -c mosquitto/passwd aegis_gateway

# Add second user (esp32_device) - prompts for password interactively (without -b flag)
mosquitto_passwd mosquitto/passwd esp32_device
```

---

## 2. Start Mosquitto Broker

Launch Mosquitto with verbose logging using the custom configuration file:

```cmd
mosquitto -c mosquitto/mosquitto.conf -v
```

Expected Startup Output:
```
mosquitto version 2.0.x starting
Config loaded from mosquitto/mosquitto.conf.
Opening ipv4 listen socket on port 1883.
```

---

## 3. Verify Access Control List (ACL) Enforcement

### A. Test Anonymous Connection (Must be Refused)
```cmd
mosquitto_sub -t "aegis/#"
```
*Expected Output*: Connection refused (Not authorized).

### B. Test Gateway Publishing (Allowed)
```cmd
mosquitto_pub -u aegis_gateway -P <CHOOSE-A-STRONG-PASSWORD> -t "aegis/cmd/esp32-01" -m "{\"command\":\"light_on\"}"
```
*Expected Output*: Message published successfully.

### C. Test Unauthorized Device Publishing to Command Topic (Refused by ACL)
```cmd
mosquitto_pub -u esp32_device -P <CHOOSE-A-STRONG-PASSWORD> -t "aegis/cmd/esp32-01" -m "{\"command\":\"light_on\"}"
```
*Expected Output*: Connection or publish rejected by ACL rules (`esp32_device` is read-only on `aegis/cmd/#`).

### D. Test Device Status Publishing (Allowed)
```cmd
mosquitto_pub -u esp32_device -P <CHOOSE-A-STRONG-PASSWORD> -t "aegis/status/esp32-01" -m "online"
```
*Expected Output*: Message published successfully (`esp32_device` has write permissions on `aegis/status/#`).
