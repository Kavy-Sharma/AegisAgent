"""
Phase 8B -- Dashboard Page: Overview

WHAT THIS PAGE DOES:
Displays high-level gateway telemetry, 4 KPI cards with hourly deltas,
decisions over time (Altair 30m stacked bar), top triggered rules (Altair horizontal bar),
recent alerts (last 8 BLOCK/REVIEW events), and a System Health panel.
Auto-refreshes every 2 seconds via st.fragment.
"""

from datetime import datetime, timezone, timedelta
import html
import json
import os
from pathlib import Path
import time
import altair as alt
import pandas as pd
import streamlit as st

from dashboard.components import kpi, page_header, pulse_dot, section_header, status_pill, sanitize_text
from dashboard.theme import COLOR_OK, COLOR_DANGER, COLOR_WARN, COLOR_ACCENT, format_ist, style_altair_chart
from security.verify_log import check_audit_log_status

ROOT_DIR = Path(__file__).resolve().parent.parent.parent


def _get_log_file() -> Path:
    return Path(os.environ.get("AEGIS_LOG_FILE", ROOT_DIR / "logs" / "audit_log.jsonl"))


def _get_data_dir() -> Path:
    return Path(os.environ.get("AEGIS_DATA_DIR", ROOT_DIR / "data"))


def _load_events() -> list[dict]:
    log_file = _get_log_file()
    if not log_file.exists():
        return []
    events = []
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                    if isinstance(ev, dict):
                        events.append(ev)
                except Exception:
                    continue
    except Exception:
        return []
    return events


import security.health


def _get_device_status_info() -> tuple[str, str]:
    health = security.health.get_system_health()
    dev = health["device"]
    st_val = dev["status"]
    if st_val == "online":
        seen_str = format_ist(dev.get("last_seen"), "%H:%M:%S IST") if dev.get("last_seen") else "retained"
        return "online", f"Active (seen {seen_str})"
    elif st_val == "offline":
        return "offline", "Device reported offline"
    return "unknown", "Broker disconnected / no status"


def _get_worker_status_info() -> dict:
    health = security.health.get_system_health()
    w = health["worker"]
    last_hb = w.get("last_heartbeat")
    detail = f"PID {w.get('pid', '?')} (seen {format_ist(last_hb, '%H:%M:%S IST')})" if last_hb else w.get("detail", "Not running")
    return {
        "alive": w["alive"],
        "busy": w.get("busy", False),
        "detail": detail,
        "model_warm": w.get("model_warm", False),
        "ollama_ok": w.get("ollama_ok", False),
        "pid": w.get("pid"),
    }


@st.fragment(run_every="2s")
def _render_overview_content():
    events = _load_events()
    now_utc = datetime.now(timezone.utc)
    one_hour_ago = now_utc - timedelta(hours=1)
    two_hours_ago = now_utc - timedelta(hours=2)

    # Calculate metrics & hourly deltas
    reqs_last_hour = 0
    reqs_prev_hour = 0
    blocks_last_hour = 0
    blocks_prev_hour = 0

    for ev in events:
        ts_str = ev.get("timestamp")
        if not ts_str:
            continue
        try:
            ev_dt = datetime.fromisoformat(ts_str)
            dec = str(ev.get("decision", "")).upper()
            if ev_dt >= one_hour_ago:
                reqs_last_hour += 1
                if dec == "BLOCK":
                    blocks_last_hour += 1
            elif ev_dt >= two_hours_ago:
                reqs_prev_hour += 1
                if dec == "BLOCK":
                    blocks_prev_hour += 1
        except Exception:
            continue

    req_delta = reqs_last_hour - reqs_prev_hour
    req_delta_str = f"{req_delta:+d} vs prev hr" if reqs_prev_hour > 0 or reqs_last_hour > 0 else "0 vs prev hr"

    block_delta = blocks_last_hour - blocks_prev_hour
    block_delta_str = f"{block_delta:+d} vs prev hr" if blocks_prev_hour > 0 or blocks_last_hour > 0 else "0 vs prev hr"

    # Pending approvals count
    pending_dir = _get_data_dir() / "approvals" / "pending"
    pending_files = list(pending_dir.glob("*.json")) if pending_dir.exists() else []
    pending_count = len(pending_files)

    device_status, device_hint = _get_device_status_info()

    # --- 1. KPI Cards Row ---
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        kpi("Requests (Past Hour)", reqs_last_hour, delta=req_delta_str, icon=":material/speed:")
    with c2:
        kpi("Blocked Attacks", blocks_last_hour, delta=block_delta_str, icon=":material/block:")
    with c3:
        kpi("Pending Approvals", pending_count, delta="Real-time queue", icon=":material/verified_user:")
    with c4:
        dev_badge = "Online" if device_status == "online" else ("Offline" if device_status == "offline" else "Unknown")
        dev_delta = f"{pulse_dot(device_status)} {device_hint}"
        kpi("ESP32 Device", dev_badge, delta=dev_delta, icon=":material/memory:")

    st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)

    # --- 2. Altair Charts Row ---
    col_chart_left, col_chart_right = st.columns([3, 2])

    with col_chart_left:
        section_header("Decisions Over Time", "30-minute rolling breakdown per minute")
        # Generate 30 minute buckets
        now_minute = now_utc.replace(second=0, microsecond=0)
        minute_buckets = [now_minute - timedelta(minutes=i) for i in range(29, -1, -1)]
        minute_keys = [m.strftime("%H:%M") for m in minute_buckets]

        bucket_data = {m: {"ALLOW": 0, "BLOCK": 0, "REVIEW": 0} for m in minute_keys}
        thirty_mins_ago = now_utc - timedelta(minutes=30)

        for ev in events:
            ts_str = ev.get("timestamp")
            if not ts_str:
                continue
            try:
                ev_dt = datetime.fromisoformat(ts_str)
                if ev_dt < thirty_mins_ago:
                    continue
                # Map to IST minute label
                m_key = format_ist(ev_dt, "%H:%M")
                dec = str(ev.get("decision", "")).upper()
                if dec in bucket_data.get(m_key, {}):
                    bucket_data[m_key][dec] += 1
            except Exception:
                continue

        chart_rows = []
        for m_key in minute_keys:
            chart_rows.append({"Minute": m_key, "Decision": "ALLOW", "Count": bucket_data[m_key]["ALLOW"]})
            chart_rows.append({"Minute": m_key, "Decision": "BLOCK", "Count": bucket_data[m_key]["BLOCK"]})
            chart_rows.append({"Minute": m_key, "Decision": "REVIEW", "Count": bucket_data[m_key]["REVIEW"]})

        df_timeline = pd.DataFrame(chart_rows)

        color_scale = alt.Scale(
            domain=["ALLOW", "BLOCK", "REVIEW"],
            range=[COLOR_OK, COLOR_DANGER, COLOR_WARN],
        )

        timeline_chart = (
            alt.Chart(df_timeline)
            .mark_bar(cornerRadiusTopLeft=3, cornerRadiusTopRight=3)
            .encode(
                x=alt.X("Minute:N", title="Minute (IST)", axis=alt.Axis(labelAngle=-45)),
                y=alt.Y("Count:Q", title="Decisions"),
                color=alt.Color("Decision:N", scale=color_scale, legend=alt.Legend(title="Decision")),
                tooltip=["Minute", "Decision", "Count"],
            )
            .properties(height=260)
        )
        st.altair_chart(style_altair_chart(timeline_chart), use_container_width=True)

    with col_chart_right:
        section_header("Top Triggered Rules", "Prompt injection detection frequency")
        rule_counts = {}
        for ev in events:
            if ev.get("event") == "injection_check":
                for r_id in ev.get("rule_ids", []):
                    rule_counts[r_id] = rule_counts.get(r_id, 0) + 1

        if not rule_counts:
            st.info("No detection rules triggered yet.")
        else:
            df_rules = pd.DataFrame(
                [{"Rule": k, "Triggers": v} for k, v in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:6]]
            )
            rules_chart = (
                alt.Chart(df_rules)
                .mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4, color=COLOR_ACCENT)
                .encode(
                    x=alt.X("Triggers:Q", title="Count"),
                    y=alt.Y("Rule:N", sort="-x", title=None),
                    tooltip=["Rule", "Triggers"],
                )
                .properties(height=260)
            )
            st.altair_chart(style_altair_chart(rules_chart), use_container_width=True)

    st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)

    # --- 3. Bottom Row: Recent Alerts & System Health ---
    col_alerts, col_health = st.columns([3, 2])

    with col_alerts:
        section_header("Recent Security Alerts", "Last 8 BLOCK or REVIEW security decisions")
        alert_events = [
            ev for ev in reversed(events)
            if str(ev.get("decision", "")).upper() in ("BLOCK", "REVIEW")
            or ev.get("approved") is False
        ][:8]

        if not alert_events:
            st.caption("No security alerts recorded. System operating in clean state.")
        else:
            table_rows = []
            for ev in alert_events:
                ts = format_ist(ev.get("timestamp"), "%H:%M:%S IST")
                dec = str(ev.get("decision", "")).upper()
                if not dec and ev.get("approved") is False:
                    dec = "DENIED"

                pill_kind = "danger" if dec in ("BLOCK", "DENIED") else "warn"
                pill_html = status_pill(pill_kind, dec)

                target = ev.get("tool") or ev.get("event") or "message"
                raw_reason = ev.get("reason") or ev.get("error") or f"Score: {ev.get('score', 0):.2f}"
                safe_reason = sanitize_text(raw_reason, max_len=120)

                row_html = f"""
                <tr style="border-bottom: 1px solid var(--border-subtle);">
                    <td style="padding: 10px 8px; font-size: 0.82rem; color: var(--text-muted);">{ts}</td>
                    <td style="padding: 10px 8px;">{pill_html}</td>
                    <td style="padding: 10px 8px; font-size: 0.85rem; font-weight: 600; color: var(--text-main);">{sanitize_text(target, max_len=30)}</td>
                    <td style="padding: 10px 8px; font-size: 0.82rem; color: var(--text-muted);">{safe_reason}</td>
                </tr>
                """
                table_rows.append(row_html)

            html_table = f"""
            <div style="background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: 14px; overflow: hidden; box-shadow: var(--shadow-card);">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: var(--bg-app); border-bottom: 1px solid var(--border-subtle); text-align: left;">
                            <th style="padding: 10px 8px; font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Time (IST)</th>
                            <th style="padding: 10px 8px; font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Decision</th>
                            <th style="padding: 10px 8px; font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Target</th>
                            <th style="padding: 10px 8px; font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Reason</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(table_rows)}
                    </tbody>
                </table>
            </div>
            """
            st.markdown(html_table, unsafe_allow_html=True)

    with col_health:
        section_header("System Health & Veracity", "Runtime subsystem integrity & verification")
        worker_info = _get_worker_status_info()
        w_state = "live" if worker_info["alive"] else "offline"
        w_text = f"Online ({worker_info['detail']})" if worker_info["alive"] else "Offline"

        d_state = "live" if device_status == "online" else ("offline" if device_status == "offline" else "unknown")

        st.markdown(
            f"""
            <div style="background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: 14px; padding: 18px; box-shadow: var(--shadow-card); margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <span style="font-size: 0.85rem; font-weight: 600; color: var(--text-main);">Agent Worker</span>
                    <span style="font-size: 0.82rem; color: var(--text-muted);">{pulse_dot(w_state)} {w_text}</span>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <span style="font-size: 0.85rem; font-weight: 600; color: var(--text-main);">ESP32 Bridge</span>
                    <span style="font-size: 0.82rem; color: var(--text-muted);">{pulse_dot(d_state)} {device_status.capitalize()}</span>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <span style="font-size: 0.85rem; font-weight: 600; color: var(--text-main);">Ollama Engine</span>
                    <span style="font-size: 0.82rem; color: var(--text-muted);">{pulse_dot('live' if worker_info.get('ollama_ok') else 'offline')} {'Model Warm' if worker_info.get('model_warm') else 'Checking'}</span>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-size: 0.85rem; font-weight: 600; color: var(--text-main);">Audit Chain</span>
                    <span style="font-size: 0.82rem; color: var(--text-muted);">{pulse_dot('live')} SHA-256 Chained</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if st.button(":material/verified_user: Verify Audit Chain", use_container_width=True):
            h = security.health.get_system_health(force_audit_check=True)
            is_intact = h["audit_chain"]["intact"]
            msg = h["audit_chain"]["message"]
            if is_intact:
                st.success(f"Audit Integrity Verified: {msg}")
            else:
                st.error(f"Integrity Alert: {msg}")


def render_overview():
    page_header("System Overview", "Live security gateway telemetry & operations console")
    _render_overview_content()
