"""
Phase 8 — AegisAgent Security Operations Dashboard (Streamlit)

DESIGN RULES:
- Separate process from the agent. Bound to 127.0.0.1 only.
  Run command: streamlit run dashboard/app.py --server.address 127.0.0.1
- The dashboard NEVER writes to the audit log and NEVER touches hardware.
- It only reads logs/audit_log.jsonl and writes data/approvals/decisions/<request_id>.json.
- FAIL CLOSED: no decision, dashboard closed, or any error means DENY.
- All attacker-controllable text is escaped or rendered via st.code, never raw HTML/markdown.
"""

from datetime import datetime, timezone, timedelta
import html
import json
import os
from pathlib import Path
import sys
import time
import uuid

# Add project root to sys.path so 'security' package can be imported when run via Streamlit
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pandas as pd
import streamlit as st

import security.signing
from security.verify_log import check_audit_log_status

# Root paths
LOG_FILE = Path(os.environ.get("AEGIS_LOG_FILE", ROOT_DIR / "logs" / "audit_log.jsonl"))
DATA_DIR = Path(os.environ.get("AEGIS_DATA_DIR", ROOT_DIR / "data"))
APPROVALS_DIR = Path(os.environ.get("AEGIS_APPROVALS_DIR", DATA_DIR / "approvals"))
PENDING_DIR = APPROVALS_DIR / "pending"
DECISIONS_DIR = APPROVALS_DIR / "decisions"
DEVICE_STATUS_FILE = DATA_DIR / "device_status.json"

# Ensure directories exist
PENDING_DIR.mkdir(parents=True, exist_ok=True)
DECISIONS_DIR.mkdir(parents=True, exist_ok=True)

# Streamlit Page Configuration
st.set_page_config(
    page_title="AegisAgent Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling
st.markdown(
    """
    <style>
    .metric-card {
        background-color: #1e293b;
        border-radius: 8px;
        padding: 16px;
        border: 1px solid #334155;
    }
    .badge-allow {
        background-color: #065f46;
        color: #34d399;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-block {
        background-color: #991b1b;
        color: #f87171;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-review {
        background-color: #92400e;
        color: #fbbf24;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-gray {
        background-color: #374151;
        color: #9ca3af;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def load_audit_events() -> list[dict]:
    """Reads logs/audit_log.jsonl defensively without crashing on malformed lines."""
    if not LOG_FILE.exists():
        return []

    events = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if isinstance(entry, dict):
                        events.append(entry)
                except Exception:
                    continue  # Skip malformed lines defensively
    except Exception:
        return []
    return events


def get_device_status(events: list[dict] | None = None) -> str:
    """
    Returns 'online', 'offline', or 'unknown'.
    Unknown if data/device_status.json is missing or older than 60s with no retained state.
    Does NOT infer status from hardware_command audit events.
    """
    if not DEVICE_STATUS_FILE.exists():
        return "unknown"

    try:
        data = json.loads(DEVICE_STATUS_FILE.read_text(encoding="utf-8"))
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
            return "online"
        elif is_online is False:
            return "offline"
        return "unknown"
    except Exception:
        return "unknown"


def write_decision_file(request_id: str, request_hash: str, approved: bool):
    """Atomically writes signed data/approvals/decisions/<request_id>.json."""
    decided_at = datetime.now(timezone.utc).isoformat()
    sig_payload = {
        "approved": approved,
        "decided_at": decided_at,
        "request_hash": request_hash,
        "request_id": request_id,
    }
    sig = security.signing.sign(sig_payload)

    decision_data = {
        "request_id": request_id,
        "approved": approved,
        "request_hash": request_hash,
        "decided_at": decided_at,
        "decided_by": "dashboard_operator",
        "reason": "Approved by dashboard operator" if approved else "Denied by dashboard operator",
        "signature": sig,
    }
    decision_file = DECISIONS_DIR / f"{request_id}.json"
    tmp_file = DECISIONS_DIR / f"{request_id}.tmp.{uuid.uuid4().hex[:6]}"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(decision_data, indent=2))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_file, decision_file)
    except Exception as e:
        if tmp_file.exists():
            try:
                tmp_file.unlink()
            except Exception:
                pass
        st.error(f"Failed to record decision: {e}")


@st.fragment(run_every="2s")
def render_dashboard():
    events = load_audit_events()

    # Calculate metrics
    total_events = len(events)
    allow_count = 0
    block_count = 0
    injection_count = 0
    approvals_approved = 0
    approvals_denied = 0
    approvals_timed_out = 0

    for ev in events:
        dec = str(ev.get("decision", "")).upper()
        if dec == "ALLOW":
            allow_count += 1
        elif dec == "BLOCK":
            block_count += 1

        if ev.get("event") == "injection_check":
            injection_count += 1
        elif ev.get("event") == "approval_decision":
            if ev.get("approved") is True:
                approvals_approved += 1
            elif ev.get("timed_out") is True:
                approvals_timed_out += 1
            else:
                approvals_denied += 1

    device_status = get_device_status(events)
    if device_status == "online":
        device_badge = "Online 🟢"
    elif device_status == "offline":
        device_badge = "Offline 🔴"
    else:
        device_badge = "Unknown ⚪"

    # --- Header ---
    col_title, col_audit = st.columns([3, 1])
    with col_title:
        st.title("🛡️ AegisAgent Security Operations")
        st.caption("Live Gateway Telemetry & Human-in-the-Loop Approval Console (Bound to 127.0.0.1)")

    with col_audit:
        st.write("**Audit Trail Integrity**")
        if st.button("🔍 Verify audit chain"):
            ok, msg = check_audit_log_status()
            if ok:
                st.success(f"✅ {msg}")
            else:
                st.error(f"❌ {msg}")

    st.divider()

    # --- Header Metrics Row ---
    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Total Events", total_events)
    m2.metric("ALLOW Decisions", allow_count)
    m3.metric("BLOCK Decisions", block_count)
    m4.metric("Injection Checks", injection_count)
    m5.metric("Approvals (A/D/T)", f"{approvals_approved}/{approvals_denied}/{approvals_timed_out}")
    m6.metric("ESP32 Device", device_badge)

    st.markdown("<br>", unsafe_allow_html=True)

    # --- Pending Approvals Panel ---
    st.subheader("⚠️ Pending Human Approvals")
    pending_files = list(PENDING_DIR.glob("*.json"))
    valid_pending = []
    now_dt = datetime.now(timezone.utc)

    for p_file in pending_files:
        try:
            content = p_file.read_text(encoding="utf-8").strip()
            if not content:
                continue
            req_data = json.loads(content)
            valid_pending.append(req_data)
        except Exception:
            continue

    if not valid_pending:
        st.info("No pending approvals at this time. Gateway is operating normally.")
    else:
        for req in valid_pending:
            req_id = req.get("request_id", "unknown")
            req_hash = req.get("request_hash", "")
            expires_at_str = req.get("expires_at", "")
            seconds_left = 0
            is_expired = True

            if expires_at_str:
                try:
                    exp_dt = datetime.fromisoformat(expires_at_str)
                    diff = (exp_dt - now_dt).total_seconds()
                    seconds_left = max(0, int(diff))
                    is_expired = seconds_left <= 0
                except Exception:
                    is_expired = True

            with st.container(border=True):
                c_info, c_action = st.columns([3, 1])
                with c_info:
                    st.markdown(f"**Request ID:** `{html.escape(req_id)}`")
                    st.markdown(
                        f"**Kind:** `{html.escape(str(req.get('kind', '')))}` | "
                        f"**Tool:** `{html.escape(str(req.get('tool', 'None')))}` | "
                        f"**Risk:** `{html.escape(str(req.get('risk', 'HIGH')))}`"
                    )

                    reasons = req.get("reasons", [])
                    if reasons:
                        st.markdown(f"**Reasons:** {html.escape(', '.join(reasons))}")

                    args = req.get("args", {})
                    st.markdown("**Arguments:**")
                    st.code(json.dumps(args, indent=2), language="json")

                    if is_expired:
                        st.error("⏳ EXPIRED — Request cannot be approved.")
                    else:
                        st.warning(f"⏱️ Countdown: **{seconds_left}s remaining** before automatic fail-closed timeout.")

                with c_action:
                    st.write("**Operator Decision**")
                    if st.button("✅ Approve", key=f"app_{req_id}", disabled=is_expired, type="primary"):
                        write_decision_file(req_id, req_hash, approved=True)
                        st.rerun()

                    if st.button("❌ Deny", key=f"deny_{req_id}", disabled=is_expired):
                        write_decision_file(req_id, req_hash, approved=False)
                        st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # --- Trend Chart (Last 30 Minutes) ---
    st.subheader("📈 Decision Trends (Last 30 Minutes)")
    now_minute = now_dt.replace(second=0, microsecond=0)
    minutes_list = [now_minute - timedelta(minutes=i) for i in range(29, -1, -1)]
    minute_keys = [m.strftime("%H:%M") for m in minutes_list]

    chart_data = {m_str: {"ALLOW": 0, "BLOCK": 0, "REVIEW": 0} for m_str in minute_keys}

    thirty_mins_ago = now_dt - timedelta(minutes=30)
    for ev in events:
        ts_str = ev.get("timestamp")
        if not ts_str:
            continue
        try:
            ev_dt = datetime.fromisoformat(ts_str)
            if ev_dt < thirty_mins_ago:
                continue
            ev_m_key = ev_dt.strftime("%H:%M")
            if ev_m_key in chart_data:
                dec = str(ev.get("decision", "")).upper()
                if dec in ("ALLOW", "BLOCK", "REVIEW"):
                    chart_data[ev_m_key][dec] += 1
        except Exception:
            continue

    df_chart = pd.DataFrame(
        [
            {"Minute": m_str, "ALLOW": counts["ALLOW"], "BLOCK": counts["BLOCK"], "REVIEW": counts["REVIEW"]}
            for m_str, counts in chart_data.items()
        ]
    )

    st.bar_chart(
        df_chart,
        x="Minute",
        y=["ALLOW", "BLOCK", "REVIEW"],
        color=["#22c55e", "#ef4444", "#f59e0b"],
        stack=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)

    # --- Live Feed (Last 50 Audit Events) ---
    st.subheader("📋 Live Audit Feed (Last 50 Events)")
    last_50 = list(reversed(events[-50:]))

    if not last_50:
        st.caption("No audit events recorded yet.")
    else:
        table_rows = []
        for ev in last_50:
            ts = ev.get("timestamp", "")
            try:
                dt_obj = datetime.fromisoformat(ts)
                time_display = dt_obj.strftime("%H:%M:%S")
            except Exception:
                time_display = ts[:19]

            ev_type = ev.get("event") or ("tool_decision" if "tool" in ev else "unknown")
            tool_or_role = ev.get("tool") or ev.get("command") or ev.get("role") or "-"

            dec = str(ev.get("decision", "-")).upper()
            if dec == "ALLOW":
                dec_html = '<span class="badge-allow">ALLOW</span>'
            elif dec == "BLOCK":
                dec_html = '<span class="badge-block">BLOCK</span>'
            elif dec == "REVIEW":
                dec_html = '<span class="badge-review">REVIEW</span>'
            elif ev.get("approved") is True:
                dec_html = '<span class="badge-allow">APPROVED</span>'
            elif ev.get("approved") is False:
                dec_html = '<span class="badge-block">DENIED</span>'
            elif ev.get("ok") is True:
                dec_html = '<span class="badge-allow">OK</span>'
            elif ev.get("ok") is False:
                dec_html = '<span class="badge-block">FAILED</span>'
            else:
                dec_html = '<span class="badge-gray">-</span>'

            raw_reason = (
                ev.get("reason")
                or ev.get("error")
                or (f"Score: {ev.get('score')}" if "score" in ev else "")
                or (f"Old: {ev.get('old_role')} -> New: {ev.get('new_role')}" if ev_type == "role_change" else "")
                or "-"
            )
            reason_clean = html.escape(str(raw_reason))
            if len(reason_clean) > 200:
                reason_clean = reason_clean[:200] + "..."

            table_rows.append(
                f"<tr>"
                f"<td><code>{html.escape(time_display)}</code></td>"
                f"<td><code>{html.escape(ev_type)}</code></td>"
                f"<td><code>{html.escape(str(tool_or_role))}</code></td>"
                f"<td>{dec_html}</td>"
                f"<td>{reason_clean}</td>"
                f"</tr>"
            )

        table_html = f"""
        <table style="width:100%; border-collapse: collapse; font-size: 0.9rem;">
            <thead>
                <tr style="border-bottom: 2px solid #334155; text-align: left;">
                    <th style="padding: 8px;">Time (UTC)</th>
                    <th style="padding: 8px;">Event Type</th>
                    <th style="padding: 8px;">Tool / Target</th>
                    <th style="padding: 8px;">Decision</th>
                    <th style="padding: 8px;">Details / Reason</th>
                </tr>
            </thead>
            <tbody>
                {''.join(table_rows)}
            </tbody>
        </table>
        """
        st.markdown(table_html, unsafe_allow_html=True)


# Render dashboard with auto-refresh every 2 seconds
render_dashboard()
