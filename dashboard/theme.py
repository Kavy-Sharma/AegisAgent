"""
Phase 8B -- AegisAgent Design System Tokens, Altair Theme & Time Formatting
"""

from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo
import altair as alt
import streamlit as st

# IST ZoneInfo for India Standard Time
IST_TZ = ZoneInfo("Asia/Kolkata")

# Color Tokens (Light Theme Only -- No Gradients, No Neon)
COLOR_BACKGROUND = "#F6F5F2"
COLOR_SURFACE = "#FFFFFF"
COLOR_BORDER = "#E7E5E0"
COLOR_TEXT = "#1C1B19"
COLOR_MUTED = "#6B6860"
COLOR_ACCENT = "#0F766E"      # Deep teal
COLOR_ACCENT_SOFT = "#E6F2F0"

# Status Colors
COLOR_OK = "#15803D"
COLOR_OK_BG = "#ECFDF3"
COLOR_WARN = "#B45309"
COLOR_WARN_BG = "#FEF6E7"
COLOR_DANGER = "#B91C1C"
COLOR_DANGER_BG = "#FEF0EF"
COLOR_INFO = "#1D4ED8"
COLOR_INFO_BG = "#EEF4FF"

_CSS_PATH = Path(__file__).resolve().parent / "static" / "style.css"


def inject_theme():
    """Reads and injects dashboard/static/style.css into Streamlit."""
    if _CSS_PATH.exists():
        css = _CSS_PATH.read_text(encoding="utf-8")
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def format_ist(dt_val: str | datetime | float | int | None, format_str: str = "%Y-%m-%d %H:%M:%S IST") -> str:
    """
    Converts a UTC datetime, ISO string, or timestamp into Asia/Kolkata (IST).
    Labels explicitly with 'IST'. Returns 'N/A' on failure/empty.
    """
    if not dt_val:
        return "N/A"
    try:
        if isinstance(dt_val, (int, float)):
            dt = datetime.fromtimestamp(dt_val, tz=timezone.utc)
        elif isinstance(dt_val, str):
            dt = datetime.fromisoformat(dt_val)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        elif isinstance(dt_val, datetime):
            dt = dt_val
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        else:
            return str(dt_val)
        return dt.astimezone(IST_TZ).strftime(format_str)
    except Exception:
        return str(dt_val)


def style_altair_chart(chart: alt.Chart) -> alt.Chart:
    """
    Applies AegisAgent design system tokens to Altair charts:
    clean borders, thin gridlines, muted labels, top-right legend, tooltips.
    """
    return (
        chart.configure_view(
            strokeWidth=0,
            fill="#FFFFFF",
        )
        .configure_axis(
            labelFont='-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
            titleFont='-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
            labelColor=COLOR_MUTED,
            titleColor=COLOR_MUTED,
            gridColor=COLOR_BORDER,
            gridWidth=0.8,
            domainColor=COLOR_BORDER,
            tickColor=COLOR_BORDER,
        )
        .configure_legend(
            orient="top-right",
            labelFont='-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
            titleFont='-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
            labelColor=COLOR_MUTED,
            titleColor=COLOR_TEXT,
            fillColor="#FFFFFF",
            strokeColor=COLOR_BORDER,
            cornerRadius=6,
            padding=8,
        )
    )
