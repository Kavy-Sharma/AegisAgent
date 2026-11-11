"""



Phase 7 -- Hardware Bridge & MQTT Integration Framework



"""



from dataclasses import dataclass



from datetime import datetime, timezone



import json



import os



from pathlib import Path



import contextvars



import threading



import time



import uuid



import paho.mqtt.client as mqtt



from security import logger, policy_loader



COMMAND_ALLOWLIST = {"light_on", "light_off", "unlock_door", "alarm_on", "alert_blocked", "ping"}


def _normalize_ack(val) -> str:
    s = str(val or "").strip()
    if s.startswith("EVENT:"):
        s = s[6:].strip()
    return s


def _ack_ok(payload, target) -> bool:
    if not payload or not target:
        return False
    return _normalize_ack(payload) == _normalize_ack(target)


def _serial_ack_ok(raw_buffer: str, expected_ack: str) -> bool:
    if not raw_buffer or not expected_ack:
        return False
    target = _normalize_ack(expected_ack)
    for line in raw_buffer.splitlines():
        if _normalize_ack(line) == target:
            return True
    return False



def load_env_file():



    """Reads a local .env file into os.environ without external dependencies."""



    env_path = Path(__file__).resolve().parent.parent / ".env"



    if env_path.exists():



        with open(env_path, "r", encoding="utf-8") as f:



            for line in f:



                line = line.strip()



                if line and not line.startswith("#") and "=" in line:



                    k, v = line.split("=", 1)



                    os.environ.setdefault(k.strip(), v.strip().strip("'\""))



load_env_file()



def _get_data_dir() -> Path:



    return Path(os.environ.get("AEGIS_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))



@dataclass



class HardwareCommandResult:



    ok: bool



    error: str | None = None
    adapter: str = "hardware"

    def __getitem__(self, item):
        return getattr(self, item)

    def get(self, item, default=None):
        return getattr(self, item, default)



class HardwareBridge:



    def __init__(self, policy_dict: dict | None = None):



        if policy_dict is None:



            policy_dict = policy_loader.POLICY



        hw_cfg = policy_dict.get("hardware", {})



        self.host = hw_cfg.get("broker_host", "127.0.0.1")



        self.port = int(hw_cfg.get("broker_port", 1883))



        self.device_id = hw_cfg.get("device_id", "esp32-01")



        self.timeout = float(hw_cfg.get("publish_timeout_seconds", 5))



        self.user = os.environ.get("AEGIS_MQTT_USER", "")



        self.password = os.environ.get("AEGIS_MQTT_PASS", "")



        self.cmd_topic = f"aegis/cmd/{self.device_id}"



        self.status_topic = f"aegis/status/{self.device_id}"



        self.event_topic = f"aegis/status/{self.device_id}/event"



        self._event_received_event = threading.Event()



        self._last_event_payload = None



        self.device_online = False



        self.transport = "mqtt"



        self.description = f"MQTT Broker ({self.host}:{self.port})"



        self.client = None



        self._connect_event = threading.Event()



        self._status_event = threading.Event()



        self._connected = False



        self._connect_error = None



        self._publish_lock = threading.Lock()



    def _create_client(self) -> mqtt.Client:



        client_id = f"aegis_gateway_{uuid.uuid4().hex[:8]}"



        if hasattr(mqtt, "CallbackAPIVersion"):



            client = mqtt.Client(



                mqtt.CallbackAPIVersion.VERSION2,



                client_id=client_id,



            )



        else:



            client = mqtt.Client(



                client_id=client_id,



            )



        if self.user and self.password:



            client.username_pw_set(self.user, self.password)



        client.on_connect = self._on_connect



        client.on_message = self._on_message



        if hasattr(client, "on_connect_fail"):



            client.on_connect_fail = self._on_connect_fail



        return client



    def _on_connect(self, client, userdata, flags, reason_code, properties=None):



        if reason_code == 0:



            self._connected = True



            client.subscribe(self.status_topic, qos=1)



            self._connect_event.set()



        else:



            self._connected = False



            self._connect_error = f"MQTT connection rejected (reason code: {reason_code})"



            self._connect_event.set()



    def _on_connect_fail(self, client, userdata):



        self._connected = False



        self._connect_error = "MQTT broker connection failed"



        self._connect_event.set()



    def _on_message(self, client, userdata, msg):



        try:



            if msg.topic == self.status_topic:



                payload = msg.payload.decode("utf-8").strip()



                self.device_online = (payload == "online")



                self._status_event.set()



            elif msg.topic == self.event_topic:



                payload = msg.payload.decode("utf-8").strip()



                self._last_event_payload = payload



                self._event_received_event.set()



        except Exception:



            pass



    def is_device_online(self) -> bool:



        return self.device_online



    def publish(self, command: str) -> HardwareCommandResult:



        if command not in COMMAND_ALLOWLIST:



            raise ValueError(f"Command '{command}' is not in hardware command allowlist")



        with self._publish_lock:



            ok = False



            error_msg = None



            self._connect_event.clear()



            self._status_event.clear()
            self._event_received_event.clear()
            self._last_event_payload = None



            self._connected = False



            self._connect_error = None



            self.device_online = False



            client = self._create_client()



            self.client = client



            try:



                connected_socket = False



                try:



                    client.connect(self.host, self.port, keepalive=60)



                    client.loop_start()



                    connected_socket = True



                except Exception as e:



                    ok = False



                    error_msg = f"MQTT connection error: {e}"



                if connected_socket:



                    if not self._connect_event.wait(timeout=5.0):



                        ok = False



                        error_msg = "MQTT connection timed out waiting for CONNACK"



                    elif not self._connected:



                        ok = False



                        error_msg = self._connect_error or "MQTT connection failed"



                    else:



                        # Subscribe to status topic and wait up to about 3 s for retained message



                        ack_map = policy_loader.POLICY.get("hardware", {}).get("ack_map", {})



                        expected_ack = ack_map.get(command)



                        client.subscribe([(self.status_topic, 1), (self.event_topic, 1)])



                        self._status_event.wait(timeout=3.0)



                        if not self.device_online:



                            ok = False



                            error_msg = "Device offline - command not delivered"



                        else:



                            payload_dict = {



                                "command": command,



                                "ts": time.time(),



                                "nonce": str(uuid.uuid4()),



                            }



                            payload_str = json.dumps(payload_dict)



                            try:



                                info = client.publish(self.cmd_topic, payload_str, qos=1)



                                info.wait_for_publish(timeout=self.timeout)



                                if info.is_published():



                                    if expected_ack:
                                        if self._event_received_event.wait(timeout=3.0) and _ack_ok(self._last_event_payload, expected_ack):



                                            ok = True



                                        else:



                                            ok = False



                                            error_msg = "published, not confirmed by device"



                                    else:



                                        ok = True



                                else:



                                    ok = False



                                    error_msg = "MQTT publish acknowledgement timed out"



                            except Exception as e:



                                ok = False



                                error_msg = f"MQTT publish failed: {e}"



            except Exception as e:
                ok = False



                error_msg = f"MQTT error: {e}"



            finally:



                try:



                    client.loop_stop()



                except Exception:



                    pass



                try:



                    client.disconnect()



                except Exception:



                    pass



            logger.log_hardware_command(command, ok, error_msg)



            return HardwareCommandResult(ok=ok, error=error_msg)



class FakeBridge:



    def __init__(self, policy_dict: dict | None = None):



        self.command_history: list[str] = []



        self.connected: bool = True



        self.device_online_status: bool = True
        self.simulate_no_ack: bool = False
        self.simulate_wrong_ack: bool = False



        self.transport = "fake"



        self.port = "simulated"



        self.description = "Simulated Hardware Bridge"



    def is_device_online(self) -> bool:



        return self.connected and self.device_online_status



    def publish(self, command: str) -> HardwareCommandResult:



        if command not in COMMAND_ALLOWLIST:



            raise ValueError(f"Command '{command}' is not in hardware command allowlist")



        if not self.connected:



            ok = False



            error_msg = "Broker unreachable (simulated)"



        elif not self.device_online_status:
            ok = False
            error_msg = "Device offline - command not delivered"
        elif getattr(self, "simulate_no_ack", False):
            ok = False
            error_msg = "Device did not acknowledge command (timeout)"
        elif getattr(self, "simulate_wrong_ack", False):
            ok = False
            error_msg = "Device returned invalid ACK"



        else:



            self.command_history.append(command)



            ok = True



            error_msg = None



        logger.log_hardware_command(command, ok, error_msg)



        return HardwareCommandResult(ok=ok, error=error_msg)



class SerialHardwareBridge:



    """



    Direct USB Serial transport for ESP32 hardware device.



    Enforces periodic ping/ACK for liveness and verified ACK for command delivery.



    Bridges maintain state in memory; worker subscriber is the single writer to disk.



    """



    def __init__(self, port: str | None = None, baud: int = 115200, policy_dict: dict | None = None):



        if policy_dict is None:



            policy_dict = policy_loader.POLICY



        hw_cfg = policy_dict.get("hardware", {})



        self.port_setting = port or hw_cfg.get("serial_port", "auto")



        self.baud = int(hw_cfg.get("baud_rate", baud))



        self.device_id = hw_cfg.get("device_id", "esp32-01")



        self.device_online = False
        self._ping_acked_this_session = (self.port_setting == "COM_FAKE")
        self._missed_pings = 0
        self._lock = threading.RLock()



        self._serial = None



        self._detected_port = None



        self._detected_desc = None



        self._last_opened_at = 0.0



        self._last_ping_time = 0.0



        self._try_connect()



    @property



    def transport(self) -> str:



        return "usb_serial"



    @property



    def port(self) -> str:



        return str(self._detected_port or self.port_setting or "unknown")



    @property



    def description(self) -> str:



        return str(self._detected_desc or "USB Serial ESP32 Device")



    def _detect_port(self) -> str | None:
        matches = _match_usb_serial_ports()
        if matches:
            dev, desc = matches[0]
            self._detected_desc = desc
            return dev
        return None



    def _format_port_name(self, port_str: str) -> str:



        if os.name == "nt" and port_str.upper().startswith("COM"):



            try:



                num = int(port_str[3:])



                if num >= 10 and not port_str.startswith(r"\\.\ "):



                    return rf"\\.\{port_str}"



            except ValueError:



                pass



        return port_str



    def _try_connect(self) -> bool:



        with self._lock:



            if self._serial is not None and getattr(self._serial, "is_open", False):



                return True



            target_port = self.port_setting



            if not target_port or target_port == "auto":



                target_port = self._detect_port()



            if not target_port:



                self.device_online = False



                return False



            self._detected_port = target_port



            fmt_port = self._format_port_name(target_port)



            try:



                import serial



                s = serial.Serial()



                s.port = fmt_port



                s.baudrate = self.baud



                s.timeout = 0.25



                s.write_timeout = 1.0



                try:



                    s.dtr = False



                    s.rts = False



                except Exception:



                    pass



                s.open()



                self._serial = s



                self._last_opened_at = time.time()



                return True



            except Exception:



                self.device_online = False



                return False



    def is_device_online(self) -> bool:



        """



        Determines device online status by periodically sending a 'ping' command



        and verifying an ACK response from the physical device (not just checking is_open).



        """



        with self._lock:

            now = time.time()
            cache_ttl = 5.0 if self.device_online else 2.0

            if now - self._last_ping_time < cache_ttl:
                return self.device_online

            if not self._serial or not getattr(self._serial, "is_open", False):

                if not self._try_connect():
                    self.device_online = False
                    self._missed_pings = 0
                    self._last_ping_time = now
                    return False

            try:

                # Allow newly-opened USB serial devices (e.g. ESP32 DTR/RTS reset) to boot before ping
                if getattr(self, "_last_opened_at", 0.0) and (time.time() - self._last_opened_at < 1.4):
                    time.sleep(max(0.05, 1.4 - (time.time() - self._last_opened_at)))

                try:
                    self._serial.reset_input_buffer()
                except Exception:
                    pass

                self._serial.write(b"ping\n")

                t0 = time.time()
                deadline = t0 + 6.0
                max_deadline = t0 + 8.0
                ack_found = False
                raw_buf = ""

                while time.time() < deadline:
                    if self._serial.in_waiting:
                        chunk = self._serial.read(self._serial.in_waiting).decode("utf-8", errors="ignore")
                        raw_buf += chunk
                        if any(k in raw_buf for k in ("STATUS:online", "ping_ack", "EVENT:", "USB_RECV:")):
                            ack_found = True
                            break
                        if "MQTT " in raw_buf and deadline < max_deadline:
                            deadline = max(deadline, min(max_deadline, time.time() + 3.0))

                    time.sleep(0.02)

                if ack_found:
                    self._missed_pings = 0
                    self.device_online = True
                    self._ping_acked_this_session = True
                else:
                    curr_port = self._detected_port or self.port_setting
                    port_present = bool(curr_port and curr_port in find_usb_serial_ports())
                    if self.device_online and port_present and getattr(self, "_missed_pings", 0) < 1:
                        self._missed_pings = getattr(self, "_missed_pings", 0) + 1
                    else:
                        self._missed_pings = getattr(self, "_missed_pings", 0) + 1
                        self.device_online = False

                self._last_ping_time = now
                return self.device_online

            except Exception:

                self.device_online = False
                self._missed_pings = getattr(self, "_missed_pings", 0) + 1
                self._last_ping_time = now



                try:



                    if self._serial:



                        self._serial.close()



                except Exception:



                    pass



                self._serial = None



                return False



    def publish(self, command: str) -> HardwareCommandResult:



        if command not in COMMAND_ALLOWLIST:



            raise ValueError(f"Command '{command}' is not in hardware command allowlist")



        with self._lock:



            if not self._serial or not getattr(self._serial, "is_open", False):



                if not self._try_connect():



                    logger.log_hardware_command(command, False, "USB hardware not connected")



                    return HardwareCommandResult(ok=False, error="USB hardware not connected")



            try:



                # If newly opened, wait a moment for ESP32 boot banner if needed



                if time.time() - self._last_opened_at < 1.4:



                    time.sleep(max(0.05, 1.4 - (time.time() - self._last_opened_at)))



                try:



                    self._serial.reset_input_buffer()



                except Exception:



                    pass



                # Pre-actuation safety: verify device with ping -> EVENT: ping_ack first
                if command != "ping" and not self._ping_acked_this_session:
                    try:
                        self._serial.reset_input_buffer()
                    except Exception:
                        pass
                    self._serial.write(b"ping\n")
                    t_ping = time.time()
                    ping_deadline = t_ping + 6.0
                    ping_max = t_ping + 8.0
                    p_ack = False
                    p_buf = ""
                    while time.time() < ping_deadline:
                        if self._serial.in_waiting:
                            chunk = self._serial.read(self._serial.in_waiting).decode("utf-8", errors="ignore")
                            p_buf += chunk
                            if "EVENT: ping_ack" in p_buf or "ping_ack" in p_buf:
                                p_ack = True
                                break
                            if "MQTT " in p_buf and ping_deadline < ping_max:
                                ping_deadline = max(ping_deadline, min(ping_max, time.time() + 3.0))
                        time.sleep(0.02)
                    if not p_ack:
                        self.device_online = False
                        logger.log_hardware_command(command, False, "Device verification failed: ping did not return EVENT: ping_ack")
                        return HardwareCommandResult(ok=False, error="Device verification failed: ping did not return EVENT: ping_ack")
                    self._ping_acked_this_session = True

                line_to_send = f"{command}\n".encode("utf-8")
                self._serial.write(line_to_send)



                ack_map = policy_loader.POLICY.get("hardware", {}).get("ack_map", {



                    "light_on": "EVENT: light_on_done",



                    "light_off": "EVENT: light_off_done",



                    "unlock_door": "EVENT: door_unlocked",



                    "alarm_on": "EVENT: alarm_started",



                    "alert_blocked": "EVENT: alert_blocked_shown",



                    "ping": "EVENT: ping_ack",



                })



                expected_ack = ack_map.get(command)



                t0 = time.time()
                ack_deadline = t0 + 6.5
                ack_max = t0 + 8.5
                ack_found = False
                raw_buffer = ""

                while time.time() < ack_deadline:
                    if self._serial.in_waiting:
                        chunk = self._serial.read(self._serial.in_waiting).decode("utf-8", errors="ignore")
                        raw_buffer += chunk
                        if expected_ack and _serial_ack_ok(raw_buffer, expected_ack):
                            ack_found = True
                            break
                        if "MQTT " in raw_buffer and ack_deadline < ack_max:
                            ack_deadline = max(ack_deadline, min(ack_max, time.time() + 3.0))
                    time.sleep(0.02)

                if not ack_found:
                    self.device_online = False
                    logger.log_hardware_command(command, False, "no ACK from device")
                    return HardwareCommandResult(ok=False, error="no ACK from device")

                self.device_online = True
                self._missed_pings = 0
                if command == "ping":
                    self._ping_acked_this_session = True
                logger.log_hardware_command(command, True, None)



                return HardwareCommandResult(ok=True)



            except Exception as e:



                self.device_online = False



                try:



                    if self._serial:



                        self._serial.close()



                except Exception:



                    pass



                self._serial = None



                logger.log_hardware_command(command, False, str(e))



                return HardwareCommandResult(ok=False, error=str(e))



def _match_usb_serial_ports(hw_cfg: dict | None = None) -> list[tuple[str, str]]:
    """Returns matching [(device, description), ...] for known ESP32/USB-UART adapters."""
    if hw_cfg is None:
        hw_cfg = policy_loader.POLICY.get("hardware", {})
    try:
        import serial.tools.list_ports

        ports = list(serial.tools.list_ports.comports())
        vid_pids = [str(v).lower() for v in hw_cfg.get("vid_pid", []) if v]
        usb_hints = [
            "cp21", "ch34", "ch91", "ftdi", "usb to uart", "esp32",
            "silicon labs", "usb serial", "usb-serial", "pl2303", "usb single serial",
        ] + vid_pids
        matched = []
        for p in ports:
            desc = (p.description or "").lower()
            hwid = (p.hwid or "").lower()
            vid = getattr(p, "vid", None)
            pid = getattr(p, "pid", None)
            vp_str = f"{vid:04x}:{pid:04x}" if isinstance(vid, int) and isinstance(pid, int) else ""
            if any(k in desc or k in hwid or (vp_str and k == vp_str) for k in usb_hints):
                matched.append((p.device, p.description or "USB Serial ESP32 Device"))
        return matched
    except Exception:
        return []


def find_usb_serial_ports(hw_cfg: dict | None = None) -> list[str]:
    """Returns matching ESP32/USB-UART COM device names."""
    return [dev for dev, _ in _match_usb_serial_ports(hw_cfg)]


_bridge_instance = None

_bridge_explicit = False

_get_bridge_lock = threading.Lock()


def get_bridge():
    global _bridge_instance, _bridge_explicit

    with _get_bridge_lock:
        if _bridge_explicit and _bridge_instance is not None:
            return _bridge_instance

        hw_cfg = policy_loader.POLICY.get("hardware", {})

        mode = hw_cfg.get("mode", "auto")



        if mode == "virtual":
            from security.virtual_home import VirtualBridge
            if not isinstance(_bridge_instance, VirtualBridge):
                _bridge_instance = VirtualBridge()
            return _bridge_instance
        elif mode == "fake":



            if not isinstance(_bridge_instance, FakeBridge):



                _bridge_instance = FakeBridge()



            return _bridge_instance



        elif mode == "serial":



            if not isinstance(_bridge_instance, SerialHardwareBridge):



                _bridge_instance = SerialHardwareBridge()



            return _bridge_instance



        elif mode == "mqtt":



            if not isinstance(_bridge_instance, HardwareBridge):



                _bridge_instance = HardwareBridge()



            return _bridge_instance



        elif mode == "auto":



            needs_detect = False

            if _bridge_instance is None:
                needs_detect = True
            elif isinstance(_bridge_instance, HardwareBridge) and not _bridge_instance.is_device_online():
                needs_detect = True
            elif isinstance(_bridge_instance, SerialHardwareBridge):
                needs_detect = True
            elif getattr(_bridge_instance, "transport", None) == "virtual":
                needs_detect = True

            if needs_detect:
                try:
                    usb_ports = find_usb_serial_ports(hw_cfg)

                    if usb_ports:
                        curr_port = getattr(_bridge_instance, "_detected_port", None) or getattr(_bridge_instance, "port_setting", None)
                        if not isinstance(_bridge_instance, SerialHardwareBridge) or curr_port != usb_ports[0]:
                            if isinstance(_bridge_instance, SerialHardwareBridge) and getattr(_bridge_instance, "_serial", None):
                                try:
                                    _bridge_instance._serial.close()
                                except Exception:
                                    pass
                                _bridge_instance._serial = None
                            _bridge_instance = SerialHardwareBridge(port=usb_ports[0])
                    elif isinstance(_bridge_instance, SerialHardwareBridge):
                        # USB cable disconnected -> close stale handle and revert to Virtual Home simulation
                        if getattr(_bridge_instance, "_serial", None):
                            try:
                                _bridge_instance._serial.close()
                            except Exception:
                                pass
                            _bridge_instance._serial = None
                        _bridge_instance = None
                except Exception:
                    pass

            if _bridge_instance is None:
                from security.virtual_home import VirtualBridge
                _bridge_instance = VirtualBridge()

            return _bridge_instance

        else:
            if _bridge_instance is None:
                _bridge_instance = HardwareBridge()
            return _bridge_instance


def set_bridge(bridge):
    global _bridge_instance, _bridge_explicit

    with _get_bridge_lock:
        _bridge_instance = bridge
        _bridge_explicit = bridge is not None



_last_alert_time = 0.0



_alert_lock = threading.Lock()



_alert_in_flight: bool = False



def reset_alert_debounce():



    global _last_alert_time, _alert_in_flight



    with _alert_lock:



        _last_alert_time = 0.0



        _alert_in_flight = False



def trigger_block_alert():



    """



    Triggers the physical red alert_blocked LED on the hardware device in a background thread.



    Enforces a 2-second debounce filter and skips if an alert publish is already in flight.



    Never raises or disrupts caller flow.



    """



    global _last_alert_time, _alert_in_flight



    alert_on_block = policy_loader.POLICY.get("hardware", {}).get("alert_on_block", True)



    if not alert_on_block:



        return



    with _alert_lock:



        if _alert_in_flight:



            return  # Skip: alert execution already in-flight



        now = time.time()



        if now - _last_alert_time < 2.0:



            return  # Debounce filter



        _last_alert_time = now



        _alert_in_flight = True



    def _do_alert():



        global _alert_in_flight



        try:



            bridge = get_bridge()



            bridge.publish("alert_blocked")



        except Exception:



            pass  # Never crash agent or change decision



        finally:



            with _alert_lock:



                _alert_in_flight = False



    ctx = contextvars.copy_context()
    threading.Thread(target=ctx.run, args=(_do_alert,), daemon=True).start()
