# Real Hardware Checklist (ESP32)

1. Verify broker/port connectivity (`mosquitto` reachable on configured `broker_host:broker_port` or ESP32 USB serial detected).
2. Confirm header chip shows **Hardware connected** and Gate 8 displays **Device** (not Virtual Home / simulated).
3. Safe command check: send `"Turn on the light"` -> physical LED turns on, Console rail settles green (`Allowed.`).
4. High-risk approval check: send `"Unlock the front door"` and `"Sound the alarm"` -> 60 s approval card required before actuation (Deny leaves device unchanged).
5. Unreachable check: unplug ESP32 or stop broker -> chip shows **Hardware unreachable** and tools reply `"The device could not be reached. Nothing was changed."`
6. Audit check: open **Audit Log** and click **Verify chain** -> confirm `hardware_command` / `hardware_unreachable` entries recorded and SHA-256 chain verifies cleanly.
