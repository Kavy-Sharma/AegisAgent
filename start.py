"""
Phase 8B -- AegisAgent System Launcher & Supervisor

WHAT THIS FILE DOES:
Starts and supervises all AegisAgent runtime services as child processes:
1. Mosquitto MQTT broker (if hardware.mode is mqtt and executable exists)
2. Agent Worker process (agent/worker.py)
3. Hand-built Flask Web Application Server (web.server bound to 127.0.0.1:8501)
4. Opens default browser to http://127.0.0.1:8501 on initial startup
5. Watches data/env_switch.json to cleanly restart worker + server on environment switch.
"""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

parser = argparse.ArgumentParser(description="AegisAgent System Launcher")
parser.add_argument("--env", choices=["smart_home", "office"], default=None, help="Active environment (smart_home | office)")
parser.add_argument("--no-browser", action="store_true", help="Do not auto-open browser window on startup")
cli_args, _ = parser.parse_known_args()
if cli_args.env:
    os.environ["AEGIS_ENV"] = cli_args.env

VALID_ENVS = ("smart_home", "office")
env_val = os.environ.get("AEGIS_ENV", "smart_home")
if env_val not in VALID_ENVS:
    print(f"[ERROR] Unknown environment: '{env_val}'. Must be 'smart_home' or 'office'.")
    sys.exit(1)
os.environ["AEGIS_ENV"] = env_val

import security.policy_loader
import security.signing
import web.guards


def _get_data_dir() -> Path:
    env_dir = os.environ.get("AEGIS_DATA_DIR")
    return Path(env_dir) if env_dir else (ROOT_DIR / "data")


def _wait_port_free(port: int, timeout: float = 6.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                time.sleep(0.15)
        except OSError:
            return


def _stop_children(procs: list[tuple[str, subprocess.Popen]]) -> None:
    for name, p in procs:
        if p.poll() is not None:
            continue
        try:
            p.terminate()
            p.wait(timeout=4)
            print(f"[STOPPED] {name}")
        except Exception:
            try:
                p.kill()
                p.wait(timeout=2)
                print(f"[KILLED] {name}")
            except Exception:
                pass


def _clear_pending_state(data_dir: Path) -> None:
    for sub in (data_dir / "approvals" / "pending", data_dir / "chat" / "inbox"):
        if not sub.exists():
            continue
        for f in sub.glob("*.json"):
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass


def _warm_ollama_async() -> None:
    def _warm():
        try:
            import ollama
            from agent.agent import MODEL
            ollama.chat(
                model=MODEL,
                messages=[{"role": "user", "content": "hi"}],
                options={"num_predict": 8},
                keep_alive="30m",
            )
        except Exception:
            pass

    threading.Thread(target=_warm, daemon=True, name="ollama-warmup").start()


def _start_runtime_children(env_name: str, web_url: str, open_browser: bool) -> list[tuple[str, subprocess.Popen]]:
    procs: list[tuple[str, subprocess.Popen]] = []
    child_env = os.environ.copy()
    child_env["AEGIS_ENV"] = env_name

    try:
        worker_proc = subprocess.Popen([sys.executable, "-m", "agent.worker"], cwd=str(ROOT_DIR), env=child_env)
        procs.append(("Agent Worker", worker_proc))
        print(f"[STATUS] Agent Worker ({env_name}) : RUNNING (PID {worker_proc.pid})")
    except Exception as e:
        print(f"[ERROR] Failed to start Agent Worker: {e}")

    try:
        web_proc = subprocess.Popen([sys.executable, "-m", "web.server"], cwd=str(ROOT_DIR), env=child_env)
        procs.append(("Flask Web App", web_proc))
        print(f"[STATUS] Flask Web Server ({env_name}) : RUNNING (PID {web_proc.pid}) -> {web_url}")
    except Exception as e:
        print(f"[ERROR] Failed to start Flask Web Server: {e}")

    server_ready = False
    poll_start = time.time()
    while time.time() - poll_start < 30.0:
        try:
            with urllib.request.urlopen(f"{web_url}/", timeout=1.0) as resp:
                if resp.status in (200, 302):
                    server_ready = True
                    break
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.3)

    if server_ready:
        _warm_ollama_async()
        if open_browser:
            try:
                webbrowser.open(web_url)
            except Exception:
                pass
    else:
        print(f"[ERROR] Flask Web Server did not respond at {web_url} within 30 seconds.")

    return procs


def _read_switch_request(switch_file: Path, last_ts: float) -> tuple[str, float] | None:
    if not switch_file.exists():
        return None
    try:
        raw = switch_file.read_text(encoding="utf-8").strip()
        if not raw:
            return None
        data = json.loads(raw)
        target = data.get("target_env")
        ts = float(data.get("timestamp", 0.0))
        if target in VALID_ENVS and ts > last_ts:
            return target, ts
    except Exception:
        return None
    return None


def main():
    active_env = env_val
    port = int(os.environ.get("AEGIS_PORT", "8501"))
    web_url = f"http://127.0.0.1:{port}"
    data_dir = _get_data_dir()
    switch_file = data_dir / "env_switch.json"

    # Remove any leftover switch marker from previous sessions so startup --env always wins
    try:
        switch_file.unlink(missing_ok=True)
    except Exception:
        pass

    print("=" * 65)
    print(" AegisAgent System Launcher ".center(65, "="))
    print("=" * 65)

    env_display = "Office Assistant" if active_env == "office" else "Smart Home"
    print(f"[STATUS] Environment          : {env_display.upper()} ({active_env})")

    # Initialize / verify AEGIS_DASH_SECRET and AEGIS_WEB_SECRET once before launching children
    security.signing.get_secret()
    web.guards.get_web_secret()

    policy = security.policy_loader.POLICY
    hw_cfg = policy.get("hardware", {})
    mode = hw_cfg.get("mode", "fake")
    mosquitto_exe = hw_cfg.get("mosquitto_exe", r"C:\Program Files\mosquitto\mosquitto.exe")

    infra_procs: list[tuple[str, subprocess.Popen]] = []
    if mode == "mqtt":
        if Path(mosquitto_exe).exists():
            try:
                conf_path = str(ROOT_DIR / "mosquitto" / "mosquitto.conf")
                p = subprocess.Popen([mosquitto_exe, "-c", conf_path])
                infra_procs.append(("Mosquitto MQTT Broker", p))
                print(f"[STATUS] Mosquitto Broker     : RUNNING (PID {p.pid})")
            except Exception as e:
                print(f"[NOTE] Could not start Mosquitto broker: {e}")
        else:
            print(f"[NOTE] Mosquitto executable not found at '{mosquitto_exe}'. Skipping.")
    elif mode == "auto":
        print("[STATUS] Hardware Mode        : AUTO (Direct USB Plug-and-Play active, broker not required)")
    elif mode == "serial":
        print("[STATUS] Hardware Mode        : SERIAL (Direct USB Cable active, broker not required)")
    else:
        print("[STATUS] Hardware Mode        : FAKE (Mosquitto not required)")

    no_browser = bool(cli_args.no_browser or os.environ.get("AEGIS_NO_BROWSER") == "1")
    runtime_procs = _start_runtime_children(active_env, web_url, open_browser=(not no_browser))

    print("-" * 65)
    print("All services initialized. Press Ctrl+C to terminate all services.")
    print("-" * 65)

    last_switch_ts = time.time() - 1.0
    try:
        while True:
            req = _read_switch_request(switch_file, last_switch_ts)
            if req is not None:
                target_env, req_ts = req
                last_switch_ts = req_ts
                try:
                    switch_file.unlink(missing_ok=True)
                except Exception:
                    pass
                print(f"[SWITCH] Restarting services for environment '{target_env}'...")
                _stop_children(runtime_procs)
                _wait_port_free(port)
                _clear_pending_state(data_dir)
                active_env = target_env
                os.environ["AEGIS_ENV"] = active_env
                runtime_procs = _start_runtime_children(active_env, web_url, open_browser=False)
                continue

            for name, p in runtime_procs:
                ret = p.poll()
                if ret is not None:
                    print(f"[WARN] Service '{name}' exited with code {ret}")
            time.sleep(0.3)
    except KeyboardInterrupt:
        print("\n\n[SHUTDOWN] Terminating child services...")
        _stop_children(runtime_procs + infra_procs)
        print("[SHUTDOWN] All services stopped cleanly.")


if __name__ == "__main__":
    main()
