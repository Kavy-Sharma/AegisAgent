"""
Phase 8B — Dashboard Page: Human-In-The-Loop Approvals (Admin Only)

WHAT THIS PAGE DOES:
Provides a secure review and decision interface for HIGH-risk tool calls:
- Enforces role gating: administrators only.
- Displays pending approval cards with arguments, risks, reasons, and countdown.
- Displays prominent warning strips if the session triggered prompt injection.
- Writes HMAC-SHA256 SIGNED decision files for fail-closed validation.
- Displays filterable decision history table (last 50 approvals).
- Tracks newly arrived requests with in-page visual highlights.
"""

from datetime import datetime, timezone
import html
import json
import os
from pathlib import Path
import time
import streamlit as st

from dashboard.components import empty_state, page_header, section_header, status_pill, sanitize_text
from dashboard.theme import format_ist
import security.signing

ROOT_DIR = Path(__file__).resolve().parent.parent.parent


def _get_data_dir() -> Path:
    return Path(os.environ.get("AEGIS_DATA_DIR", ROOT_DIR / "data"))


def _get_log_file() -> Path:
    return Path(os.environ.get("AEGIS_LOG_FILE", ROOT_DIR / "logs" / "audit_log.jsonl"))


def _write_signed_decision(request_id: str, request_hash: str, approved: bool, decided_by: str):
    decisions_dir = _get_data_dir() / "approvals" / "decisions"
    decisions_dir.mkdir(parents=True, exist_ok=True)

    decided_at = datetime.now(timezone.utc).isoformat()
    sig_payload = {
        "approved": approved,
        "decided_at": decided_at,
        "request_hash": request_hash,
        "request_id": request_id,
    }
    sig = security.signing.sign(sig_payload)

    data = {
        "approved": approved,
        "decided_at": decided_at,
        "decided_by": decided_by,
        "reason": f"Approved by administrator ({decided_by})" if approved else f"Denied by administrator ({decided_by})",
        "request_hash": request_hash,
        "request_id": request_id,
        "signature": sig,
    }

    decision_file = decisions_dir / f"{request_id}.json"
    tmp_file = decisions_dir / f"{request_id}.tmp.{time.time()}"
    with open(tmp_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, indent=2))
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(tmp_file, decision_file)


def _load_approval_history() -> list[dict]:
    log_file = _get_log_file()
    if not log_file.exists():
        return []
    history = []
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("event") == "approval_decision":
                        history.append(entry)
                except Exception:
                    continue
    except Exception:
        return []
    return history


def render_approvals():
    # 1. Enforce Role Gating in code
    user_role = st.session_state.get("role", "guest")
    if user_role != "admin":
        st.error("Access Denied: The Approvals console is restricted to administrators.")
        st.stop()

    page_header("Human-In-The-Loop Approvals", "Cryptographic authorization console for high-risk operations")

    if "seen_approval_ids" not in st.session_state:
        st.session_state["seen_approval_ids"] = set()

    pending_dir = _get_data_dir() / "approvals" / "pending"
    pending_files = sorted(pending_dir.glob("*.json")) if pending_dir.exists() else []

    pending_requests = []
    now_utc = datetime.now(timezone.utc)

    for p_file in pending_files:
        try:
            content = p_file.read_text(encoding="utf-8").strip()
            if not content:
                continue
            req = json.loads(content)
            pending_requests.append(req)
        except Exception:
            continue

    section_header(f"Pending Authorization Queue ({len(pending_requests)})")

    if not pending_requests:
        empty_state(":material/verified_user:", "Queue Clear", "No approval requests currently require administrator authorization.")
    else:
        for req in pending_requests:
            req_id = req.get("request_id", "unknown")
            req_hash = req.get("request_hash", "")
            expires_at_str = req.get("expires_at", "")
            created_at_str = req.get("created_at", "")
            reasons = req.get("reasons", [])
            args = req.get("args", {})
            tool = req.get("tool", "unknown")
            risk = req.get("risk", "HIGH")

            # Check if newly arrived for visual highlight
            is_new = req_id not in st.session_state["seen_approval_ids"]
            st.session_state["seen_approval_ids"].add(req_id)
            card_class = "aegis-card aegis-highlight-arrival" if is_new else "aegis-card"

            # Check expiration
            seconds_left = 0
            is_expired = True
            if expires_at_str:
                try:
                    exp_dt = datetime.fromisoformat(expires_at_str)
                    diff = (exp_dt - now_utc).total_seconds()
                    seconds_left = max(0, int(diff))
                    is_expired = seconds_left <= 0
                except Exception:
                    is_expired = True

            # Injection warning detection
            has_injection_warning = any("injection" in str(r).lower() or "suspicion" in str(r).lower() for r in reasons)

            with st.container():
                st.markdown(f'<div class="{card_class}">', unsafe_allow_html=True)
                col_info, col_actions = st.columns([3, 1])

                with col_info:
                    st.markdown(
                        f"""
                        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                            <span style="font-size: 1.1rem; font-weight: 700; color: var(--text-main);">{sanitize_text(tool)}</span>
                            {status_pill('warn', risk)}
                            <span style="font-size: 0.8rem; color: var(--text-muted);">Request ID: <code>{sanitize_text(req_id[:12])}...</code></span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    if has_injection_warning:
                        st.markdown(
                            """
                            <div style="background-color: var(--warn-bg); border-left: 4px solid var(--warn-text); padding: 8px 12px; margin: 8px 0; border-radius: 4px; font-weight: 600; font-size: 0.85rem; color: var(--warn-text);">
                                WARNING: This session previously triggered prompt injection suspicion! Review arguments carefully.
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                    if reasons:
                        st.markdown("**Reasons:**")
                        for r in reasons:
                            st.markdown(f"- {sanitize_text(r)}")

                    st.markdown("**Tool Arguments:**")
                    st.code(json.dumps(args, indent=2), language="json")

                    created_ist = format_ist(created_at_str, "%H:%M:%S IST")
                    st.caption(f"Created: {created_ist}")

                with col_actions:
                    st.markdown("**Administrator Decision**")
                    if is_expired:
                        st.error("Expired — Request cannot be authorized.")
                    else:
                        st.info(f"Countdown: **{seconds_left}s** remaining")
                        progress_val = max(0.0, min(1.0, seconds_left / 30.0))
                        st.progress(progress_val)

                        username = st.session_state.get("username", "admin")
                        if st.button(":material/check_circle: Approve", key=f"app_{req_id}", type="primary", use_container_width=True):
                            _write_signed_decision(req_id, req_hash, approved=True, decided_by=username)
                            st.toast("Approved action.", icon=":material/check_circle:")
                            time.sleep(0.3)
                            st.rerun()

                        if st.button(":material/cancel: Deny", key=f"deny_{req_id}", use_container_width=True):
                            _write_signed_decision(req_id, req_hash, approved=False, decided_by=username)
                            st.toast("Denied action.", icon=":material/cancel:")
                            time.sleep(0.3)
                            st.rerun()

                st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<br><hr><br>", unsafe_allow_html=True)

    # 2. Decision History Table
    section_header("Approval Decision History", "Audit log of the last 50 human authorization events")
    history_events = _load_approval_history()
    recent_history = list(reversed(history_events[-50:]))

    if not recent_history:
        st.caption("No historical approval decisions recorded yet.")
    else:
        filter_col, _ = st.columns([2, 3])
        with filter_col:
            filter_choice = st.selectbox(
                "Filter by outcome:",
                ["All", "Approved Only", "Denied Only", "Timed Out Only"],
                key="approval_filter",
            )

        filtered_items = []
        for ev in recent_history:
            approved = ev.get("approved")
            timed_out = ev.get("timed_out")

            if filter_choice == "Approved Only" and approved is not True:
                continue
            if filter_choice == "Denied Only" and (approved is True or timed_out is True):
                continue
            if filter_choice == "Timed Out Only" and timed_out is not True:
                continue
            filtered_items.append(ev)

        table_rows = []
        for ev in filtered_items:
            ts_ist = format_ist(ev.get("timestamp"), "%Y-%m-%d %H:%M:%S IST")
            approved = ev.get("approved")
            timed_out = ev.get("timed_out")

            if approved is True:
                outcome_pill = status_pill("ok", "APPROVED")
            elif timed_out is True:
                outcome_pill = status_pill("warn", "TIMED OUT")
            else:
                outcome_pill = status_pill("danger", "DENIED")

            decided_by = sanitize_text(ev.get("decided_by", "unknown"))
            req_id_short = sanitize_text(str(ev.get("request_id", ""))[:12])
            reason = sanitize_text(ev.get("reason", "None"), max_len=120)

            row_html = f"""
            <tr style="border-bottom: 1px solid var(--border-subtle);">
                <td style="padding: 10px 8px; font-size: 0.82rem; color: var(--text-muted);">{ts_ist}</td>
                <td style="padding: 10px 8px;"><code>{req_id_short}...</code></td>
                <td style="padding: 10px 8px;">{outcome_pill}</td>
                <td style="padding: 10px 8px; font-size: 0.85rem; color: var(--text-main); font-weight: 500;">{decided_by}</td>
                <td style="padding: 10px 8px; font-size: 0.82rem; color: var(--text-muted);">{reason}</td>
            </tr>
            """
            table_rows.append(row_html)

        html_history = f"""
        <div style="background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: 14px; overflow: hidden; box-shadow: var(--shadow-card);">
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="background: var(--bg-app); border-bottom: 1px solid var(--border-subtle); text-align: left;">
                        <th style="padding: 10px 8px; font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Timestamp (IST)</th>
                        <th style="padding: 10px 8px; font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Request ID</th>
                        <th style="padding: 10px 8px; font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Outcome</th>
                        <th style="padding: 10px 8px; font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Decided By</th>
                        <th style="padding: 10px 8px; font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Reason</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(table_rows)}
                </tbody>
            </table>
        </div>
        """
        st.markdown(html_history, unsafe_allow_html=True)
