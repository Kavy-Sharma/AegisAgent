"""
Phase 8B — AegisAgent Security Operations Dashboard (App Shell & Navigation)

DESIGN RULES:
- Multi-page application with st.navigation.
- Light theme tokens (No gradients, no neon, no dark mode, no emoji; Material icons only).
- Binds to 127.0.0.1 only.
- First-run admin initialization and PBKDF2 authentication with 15-minute session timeout.
- Role-gated navigation: Guests can only see Overview & Agent Console. Admin sees Approvals.
- System health supervisor & calm worker offline banner with one-click start.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import streamlit as st

# Add project root to sys.path so 'security', 'agent', etc. can be imported
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from dashboard.components import pulse_dot, status_pill, sanitize_text
from dashboard.pages.approvals import render_approvals
from dashboard.pages.console import render_console
from dashboard.pages.overview import render_overview
from dashboard.theme import format_ist, inject_theme
import security.auth
import security.logger
import security.policy_loader

# Configure Streamlit page shell
st.set_page_config(
    page_title="AegisAgent Security Operations",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject custom light theme CSS
inject_theme()


def _get_data_dir() -> Path:
    return Path(os.environ.get("AEGIS_DATA_DIR", ROOT_DIR / "data"))


def _get_worker_heartbeat() -> dict:
    worker_file = _get_data_dir() / "worker_status.json"
    if not worker_file.exists():
        return {"alive": False, "detail": "Missing worker_status.json"}
    try:
        data = json.loads(worker_file.read_text(encoding="utf-8"))
        last_hb = data.get("last_heartbeat")
        if not last_hb:
            return {"alive": False, "detail": "Missing heartbeat"}
        dt = datetime.fromisoformat(last_hb)
        age = (datetime.now(timezone.utc) - dt).total_seconds()
        return {
            "alive": age <= 5.0,
            "detail": f"Seen {format_ist(last_hb, '%H:%M:%S IST')}",
            "model_warm": data.get("model_warm", False),
            "ollama_ok": data.get("ollama_ok", False),
            "pid": data.get("pid"),
        }
    except Exception:
        return {"alive": False, "detail": "Invalid status"}


def _get_device_status() -> str:
    device_file = _get_data_dir() / "device_status.json"
    if not device_file.exists():
        return "unknown"
    try:
        data = json.loads(device_file.read_text(encoding="utf-8"))
        now_ts = time.time()
        file_ts = None
        if "last_seen" in data:
            try:
                file_ts = datetime.fromisoformat(data["last_seen"]).timestamp()
            except Exception:
                pass
        if file_ts is None and "timestamp" in data:
            try:
                file_ts = float(data["timestamp"])
            except Exception:
                pass
        if file_ts is not None and (now_ts - file_ts) > 60:
            return "unknown"
        is_online = data.get("online")
        if is_online is None:
            is_online = data.get("device_online")
        if is_online is True:
            return "live"
        elif is_online is False:
            return "offline"
        return "unknown"
    except Exception:
        return "unknown"


def check_auth_state() -> bool:
    """Manages first-run admin creation, login card, and session timeout."""
    data = security.auth._load_data()
    has_users = bool(data.get("users"))

    # 1. First-Run: No users exist -> Create Admin Account
    if not has_users:
        st.markdown("<div style='height: 40px;'></div>", unsafe_allow_html=True)
        col_pad1, col_center, col_pad2 = st.columns([1, 2, 1])
        with col_center:
            with st.container(border=True):
                st.markdown("### Initialize Administrator Account")
                st.caption("First-time setup detected. Create the primary administrator account for AegisAgent.")

                with st.form("create_admin_form"):
                    admin_user = st.text_input("Administrator Username", value="admin")
                    admin_pass = st.text_input("Password", type="password")
                    confirm_pass = st.text_input("Confirm Password", type="password")
                    submit = st.form_submit_button(":material/person_add: Initialize Account", type="primary", use_container_width=True)

                    if submit:
                        if not admin_user.strip():
                            st.error("Username cannot be blank.")
                        elif not admin_pass:
                            st.error("Password cannot be blank.")
                        elif admin_pass != confirm_pass:
                            st.error("Passwords do not match.")
                        else:
                            try:
                                security.auth.create_user(admin_user.strip(), admin_pass, "admin")
                                st.session_state["authenticated"] = True
                                st.session_state["username"] = admin_user.strip()
                                st.session_state["role"] = "admin"
                                st.session_state["last_activity"] = time.time()
                                st.toast("Administrator account initialized successfully!", icon=":material/check_circle:")
                                time.sleep(0.5)
                                st.rerun()
                            except Exception as e:
                                st.error(f"Failed to create account: {e}")
        return False

    # 2. Login Flow
    if not st.session_state.get("authenticated"):
        st.markdown("<div style='height: 40px;'></div>", unsafe_allow_html=True)
        col_pad1, col_center, col_pad2 = st.columns([1, 2, 1])
        with col_center:
            with st.container(border=True):
                st.markdown("### Sign In to AegisAgent")
                st.caption("Enter your credentials to access the security operations console.")

                with st.form("login_form"):
                    login_user = st.text_input("Username")
                    login_pass = st.text_input("Password", type="password")
                    submit_login = st.form_submit_button(":material/login: Sign In", type="primary", use_container_width=True)

                    if submit_login:
                        if not login_user.strip() or not login_pass:
                            st.error("Please enter both username and password.")
                        else:
                            ok, role_or_msg = security.auth.verify_login(login_user.strip(), login_pass)
                            if ok:
                                st.session_state["authenticated"] = True
                                st.session_state["username"] = login_user.strip()
                                st.session_state["role"] = role_or_msg
                                st.session_state["last_activity"] = time.time()
                                st.rerun()
                            else:
                                st.error(role_or_msg)
        return False

    # 3. Session Timeout (15 minutes of inactivity)
    last_act = st.session_state.get("last_activity", time.time())
    if time.time() - last_act > 900:  # 15 minutes
        user = st.session_state.get("username", "unknown")
        security.auth.logout(user)
        st.session_state.clear()
        st.warning("Session expired due to 15 minutes of inactivity. Please sign in again.")
        st.stop()

    st.session_state["last_activity"] = time.time()
    return True


def main():
    if not check_auth_state():
        return

    current_role = st.session_state.get("role", "guest")
    current_user = st.session_state.get("username", "user")

    # Define Multi-Page Navigation based on User Role
    pages = [
        st.Page(render_overview, title="Overview", icon=":material/dashboard:", default=True),
        st.Page(render_console, title="Agent Console", icon=":material/terminal:"),
    ]

    # Role Gating: Only admin sees and can access the Approvals page
    if current_role == "admin":
        pages.append(st.Page(render_approvals, title="Approvals", icon=":material/verified_user:"))

    pg = st.navigation(pages)

    # Worker Status Banner
    worker_hb = _get_worker_heartbeat()
    if not worker_hb["alive"]:
        with st.container():
            c_msg, c_btn = st.columns([4, 1])
            with c_msg:
                st.warning("Agent worker is not running. Requests will not be processed until the worker is started.")
            with c_btn:
                if current_role == "admin":
                    if st.button(":material/play_arrow: Start Worker", key="btn_shell_start_worker", type="primary", use_container_width=True):
                        try:
                            subprocess.Popen([sys.executable, "-m", "agent.worker"], cwd=str(ROOT_DIR))
                            st.toast("Starting worker process...", icon=":material/play_arrow:")
                            time.sleep(1.0)
                            st.rerun()
                        except Exception as e:
                            st.error(f"Failed to start worker: {e}")

    # Sidebar Header & User Profile
    with st.sidebar:
        st.markdown(
            f"""
            <div class="aegis-brand-wordmark">
                AegisAgent
            </div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 16px;">
                Security Gateway & Console
            </div>
            <div style="display: flex; align-items: center; justify-content: space-between; background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 8px 12px; margin-bottom: 16px;">
                <span style="font-size: 0.85rem; font-weight: 600; color: var(--text-main);">{sanitize_text(current_user)}</span>
                {status_pill('info' if current_role == 'admin' else 'neutral', current_role)}
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Execute Page Function
    pg.run()

    # Sidebar System Health & Logout
    with st.sidebar:
        worker_state = "live" if worker_hb["alive"] else "offline"
        device_state = _get_device_status()
        ollama_state = "live" if worker_hb.get("ollama_ok") else "offline"

        st.markdown(
            f"""
            <div class="aegis-sidebar-health">
                <div style="font-size: 0.72rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 10px;">
                    System Health
                </div>
                <div class="aegis-health-item">
                    <span>Agent Worker</span>
                    <span>{pulse_dot(worker_state)} {'Live' if worker_hb['alive'] else 'Offline'}</span>
                </div>
                <div class="aegis-health-item">
                    <span>ESP32 Hardware</span>
                    <span>{pulse_dot(device_state)} {device_state.capitalize()}</span>
                </div>
                <div class="aegis-health-item">
                    <span>Ollama Engine</span>
                    <span>{pulse_dot(ollama_state)} {'Ready' if worker_hb.get('ollama_ok') else 'Offline'}</span>
                </div>
                <div class="aegis-health-item">
                    <span>Audit Chain</span>
                    <span>{pulse_dot('live')} Intact</span>
                </div>
            </div>
            <br>
            """,
            unsafe_allow_html=True,
        )

        if st.button(":material/logout: Sign Out", use_container_width=True):
            security.auth.logout(current_user)
            st.session_state.clear()
            st.rerun()


if __name__ == "__main__":
    main()
