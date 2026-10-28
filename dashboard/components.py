"""
Phase 8B -- AegisAgent Component Library

WHAT THIS FILE DOES:
Provides reusable, theme-consistent UI components:
- card, kpi, status_pill, pulse_dot, empty_state, pipeline_stepper, section_header.
SECURITY INVARIANT:
Every attacker-controllable value (user input, arguments, reasons, error messages, rule IDs)
is strictly sanitized via html.escape and ANSI-stripped before rendering.
"""

from contextlib import contextmanager
import html
import json
import re
from typing import Any
import streamlit as st


def sanitize_text(val: Any, max_len: int = 500) -> str:
    """
    Sanitizes values against XSS, ANSI escape codes, and excessive length.
    Safely converts dicts/lists to JSON strings before escaping.
    """
    if val is None:
        return "None"
    if isinstance(val, (dict, list)):
        str_val = json.dumps(val, sort_keys=True)
    else:
        str_val = str(val)

    # Strip ANSI escape codes
    str_val = re.sub(r"\x1b\[[0-9;]*[mG-Z]", "", str_val)
    # Strip control codes except newlines/tabs
    str_val = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", str_val)

    if len(str_val) > max_len:
        str_val = str_val[:max_len] + "... [truncated]"

    return html.escape(str_val)


def status_pill(kind: str, text: str) -> str:
    """
    Generates a sanitized status pill HTML string.
    kind: 'ok' | 'warn' | 'danger' | 'info' | 'neutral'
    """
    valid_kinds = {"ok", "warn", "danger", "info", "neutral"}
    safe_kind = kind if kind in valid_kinds else "neutral"
    safe_text = sanitize_text(text, max_len=60)
    return f'<span class="aegis-pill aegis-pill-{safe_kind}">{safe_text}</span>'


def pulse_dot(state: str) -> str:
    """
    Generates an animated status dot HTML string.
    state: 'live' | 'online' | 'offline' | 'warn' | 'unknown'
    """
    normalized = "live" if state in ("live", "online", "ok") else state
    if normalized not in ("live", "offline", "warn", "unknown"):
        normalized = "unknown"
    return f'<span class="aegis-dot aegis-dot-{normalized}"></span>'


def kpi(label: str, value: Any, delta: str | None = None, icon: str | None = None):
    """Renders a single KPI card matching the design system."""
    safe_label = sanitize_text(label, max_len=40)
    safe_val = sanitize_text(str(value), max_len=30)

    icon_html = f'<span style="color: var(--text-muted); font-size: 1.1rem;">{icon}</span>' if icon else ""
    delta_html = ""
    if delta is not None:
        safe_delta = sanitize_text(delta, max_len=40)
        delta_color = "var(--ok-text)" if "+" in delta or "▲" in delta or "inc" in delta.lower() else "var(--text-muted)"
        if "-" in delta or "▼" in delta:
            delta_color = "var(--danger-text)"
        delta_html = f'<div class="aegis-kpi-delta" style="color: {delta_color};">{safe_delta}</div>'

    html_card = f"""
    <div class="aegis-kpi">
        <div class="aegis-kpi-header">
            <span class="aegis-kpi-label">{safe_label}</span>
            {icon_html}
        </div>
        <div class="aegis-kpi-val">{safe_val}</div>
        {delta_html}
    </div>
    """
    st.markdown(html_card, unsafe_allow_html=True)


def empty_state(icon: str, title: str, hint: str):
    """Renders a clean, bordered empty-state card."""
    safe_title = sanitize_text(title, max_len=100)
    safe_hint = sanitize_text(hint, max_len=200)

    html_block = f"""
    <div class="aegis-empty-state">
        <div style="font-size: 2rem; color: var(--text-muted);">{icon}</div>
        <div class="aegis-empty-title">{safe_title}</div>
        <div class="aegis-empty-hint">{safe_hint}</div>
    </div>
    """
    st.markdown(html_block, unsafe_allow_html=True)


def section_header(title: str, subtitle: str | None = None):
    """Renders a consistent page section header."""
    safe_title = sanitize_text(title, max_len=100)
    sub_html = f'<div class="aegis-page-subtitle">{sanitize_text(subtitle, max_len=200)}</div>' if subtitle else ""
    html_block = f"""
    <div style="margin-top: 18px; margin-bottom: 12px;">
        <h3 style="margin: 0; font-size: 1.15rem; font-weight: 700; color: var(--text-main);">{safe_title}</h3>
        {sub_html}
    </div>
    """
    st.markdown(html_block, unsafe_allow_html=True)


def page_header(title: str, subtitle: str | None = None):
    """Renders the top page header."""
    safe_title = sanitize_text(title, max_len=100)
    sub_html = f'<div class="aegis-page-subtitle">{sanitize_text(subtitle, max_len=200)}</div>' if subtitle else ""
    html_block = f"""
    <div class="aegis-page-header">
        <div>
            <h1 class="aegis-page-title">{safe_title}</h1>
            {sub_html}
        </div>
    </div>
    """
    st.markdown(html_block, unsafe_allow_html=True)


PIPELINE_STAGES = [
    ("detection", "Detection"),
    ("llm", "LLM"),
    ("rbac", "RBAC"),
    ("rate_limit", "Rate Limit"),
    ("approval", "Approval"),
    ("hardware", "Hardware"),
    ("output_scan", "Output Scan"),
]


def pipeline_stepper(steps: list[dict]):
    """
    Renders an animated horizontal pipeline stepper for an execution turn:
    Detection -> LLM -> RBAC -> Rate Limit -> Approval -> Hardware -> Output Scan.
    steps: list of dicts with keys {"stage", "status", "detail"}
    """
    step_map = {s.get("stage"): s for s in steps}
    step_items = []

    for stage_key, stage_label in PIPELINE_STAGES:
        step_data = step_map.get(stage_key)
        if step_data:
            status = step_data.get("status", "pass").lower()
            raw_detail = step_data.get("detail", {})
            if isinstance(raw_detail, dict):
                # Format detail string nicely
                if "reason" in raw_detail:
                    detail_str = str(raw_detail["reason"])
                elif "error" in raw_detail:
                    detail_str = str(raw_detail["error"])
                elif "tool" in raw_detail:
                    detail_str = f"tool: {raw_detail['tool']}"
                elif "score" in raw_detail:
                    detail_str = f"score: {raw_detail['score']:.2f}"
                elif "result" in raw_detail:
                    detail_str = str(raw_detail["result"])
                else:
                    detail_str = json.dumps(raw_detail)
            else:
                detail_str = str(raw_detail)
        else:
            status = "skip"
            detail_str = "not reached"

        css_status = status if status in ("pass", "block", "review", "skip", "running", "error") else "skip"
        if css_status == "error":
            css_status = "block"

        safe_status_label = status.upper()
        safe_detail = sanitize_text(detail_str, max_len=50)

        step_html = f"""
        <div class="aegis-step aegis-step-{css_status}">
            <div class="aegis-step-title">{stage_label}</div>
            <div class="aegis-step-status">{safe_status_label}</div>
            <div class="aegis-step-detail" title="{safe_detail}">{safe_detail}</div>
        </div>
        """
        step_items.append(step_html)

    arrows_combined = []
    for i, item in enumerate(step_items):
        arrows_combined.append(item)
        if i < len(step_items) - 1:
            arrows_combined.append('<div class="aegis-step-arrow">→</div>')

    stepper_html = f"""
    <div class="aegis-stepper">
        {''.join(arrows_combined)}
    </div>
    """
    st.markdown(stepper_html, unsafe_allow_html=True)
