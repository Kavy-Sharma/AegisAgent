"""
Phase 8A — AegisAgent System Launcher

WHAT THIS FILE DOES:
Starts and supervises all AegisAgent runtime services as child processes:
1. Mosquitto MQTT broker (if hardware.mode is mqtt and executable exists)
2. Agent Worker process (agent/worker.py)
3. Streamlit Security Operations Dashboard (dashboard/app.py bound to 127.0.0.1)
4. Opens default browser to http://127.0.0.1:8501
5. Displays a clean status line per service and coordinates graceful shutdown on Ctrl+C.
"""

from pathlib import Path
import subprocess
import sys
import time
import webbrowser

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import security.policy_loader


def main():
    print("=" * 65)
    print(" AegisAgent System Launcher ".center(65, "="))
    print("=" * 65)

    policy = security.policy_loader.POLICY
    hw_cfg = policy.get("hardware", {})
    mode = hw_cfg.get("mode", "fake")
    mosquitto_exe = hw_cfg.get("mosquitto_exe", r"C:\Program Files\mosquitto\mosquitto.exe")

    procs: list[tuple[str, subprocess.Popen]] = []

    # 1. Mosquitto MQTT Broker
    if mode == "mqtt":
        if Path(mosquitto_exe).exists():
            try:
                conf_path = str(ROOT_DIR / "mosquitto" / "mosquitto.conf")
                p = subprocess.Popen([mosquitto_exe, "-c", conf_path])
                procs.append(("Mosquitto MQTT Broker", p))
                print(f"[STATUS] Mosquitto Broker     : RUNNING (PID {p.pid})")
            except Exception as e:
                print(f"[NOTE] Could not start Mosquitto broker: {e}")
        else:
            print(f"[NOTE] Mosquitto executable not found at '{mosquitto_exe}'. Skipping.")
    else:
        print("[STATUS] Hardware Mode        : FAKE (Mosquitto not required)")

    # 2. Agent Worker Service
    try:
        worker_proc = subprocess.Popen([sys.executable, "-m", "agent.worker"], cwd=str(ROOT_DIR))
        procs.append(("Agent Worker", worker_proc))
        print(f"[STATUS] Agent Worker         : RUNNING (PID {worker_proc.pid})")
    except Exception as e:
        print(f"[ERROR] Failed to start Agent Worker: {e}")

    # 3. Streamlit Dashboard
    dash_url = "http://127.0.0.1:8501"
    try:
        dash_cmd = [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            "dashboard/app.py",
            "--server.address",
            "127.0.0.1",
            "--server.headless",
            "true",
        ]
        dash_proc = subprocess.Popen(dash_cmd, cwd=str(ROOT_DIR))
        procs.append(("Streamlit Dashboard", dash_proc))
        print(f"[STATUS] Streamlit Dashboard  : RUNNING (PID {dash_proc.pid}) -> {dash_url}")
    except Exception as e:
        print(f"[ERROR] Failed to start Streamlit Dashboard: {e}")

    print("-" * 65)
    print("All services initialized. Press Ctrl+C to terminate all services.")
    print("-" * 65)

    # Open browser
    time.sleep(2.0)
    try:
        webbrowser.open(dash_url)
    except Exception:
        pass

    try:
        while True:
            # Check if any child process terminated prematurely
            for name, p in procs:
                ret = p.poll()
                if ret is not None:
                    print(f"[WARN] Service '{name}' exited with code {ret}")
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n\n[SHUTDOWN] Terminating child services...")
        for name, p in procs:
            try:
                p.terminate()
                p.wait(timeout=3)
                print(f"[STOPPED] {name}")
            except Exception:
                try:
                    p.kill()
                    print(f"[KILLED] {name}")
                except Exception:
                    pass
        print("[SHUTDOWN] All services stopped cleanly.")


if __name__ == "__main__":
    main()
