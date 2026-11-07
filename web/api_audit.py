"""
Audit Log Web API & High-Performance Streaming Reader
Admin-only endpoints for the Tamper-Evident Audit Log page.
Strict CSP compliance: parameterized, formula-protected CSV, isolated copy-only tamper lab.
"""

from datetime import datetime, timezone, timedelta
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import Any, Generator

from flask import Blueprint, Response, current_app, jsonify, request, send_file
from security.logger import get_log_file, _file_lock
from security.verify_log import (
    check_audit_log_status,
    create_anchor,
    export_anchor_line,
    check_anchor_line
)
from web.guards import role_required, csrf_protect

audit_bp = Blueprint("audit_bp", __name__)

# In-memory rate limiting for tamper demo (max 15 operations / min per IP)
_tamper_rate_limits: dict[str, list[float]] = {}


def _check_tamper_rate_limit(client_ip: str) -> bool:
    try:
        from flask import current_app
        if current_app and current_app.config.get("TESTING") and not current_app.config.get("TEST_RATE_LIMIT"):
            return True
    except Exception:
        pass
    now = time.time()
    history = _tamper_rate_limits.setdefault(client_ip, [])
    # Keep only requests within the last 60 seconds
    _tamper_rate_limits[client_ip] = [t for t in history if now - t < 60.0]
    if len(_tamper_rate_limits[client_ip]) >= 15:
        return False
    _tamper_rate_limits[client_ip].append(now)
    return True


def format_plain_summary(entry: dict[str, Any]) -> str:
    """
    Template-based plain-English explanation of the audit record.
    Deterministic, human-readable, NO LLM.
    """
    event = entry.get("event")
    tool = entry.get("tool")
    decision = str(entry.get("decision", "")).upper()
    reason = entry.get("reason", "")
    args = entry.get("args") or {}
    role = entry.get("role", entry.get("decided_by", "system"))

    # 1. Direct tool decisions
    if tool:
        tool_clean = tool.replace("_", " ")
        if decision == "BLOCK":
            if "mismatch" in reason.lower() or "read" in reason.lower():
                return f"Blocked: User only asked to read, but payload attempted '{tool}'."
            return f"Blocked: {role.title()} attempted '{tool_clean}' ({reason or 'denied by policy'})."
        elif decision == "ALLOW":
            arg_str = ", ".join(f"{k}={v}" for k, v in list(args.items())[:2])
            suffix = f" with {arg_str}" if arg_str else ""
            return f"Allowed: Executed '{tool_clean}'{suffix} ({reason or 'authorized'})."
        elif decision in ("REVIEW", "WAITING"):
            return f"Waiting: High-risk operation '{tool_clean}' held for human supervisor approval."
        elif decision == "ERROR":
            return f"Error: Tool '{tool_clean}' failed ({reason or 'execution error'})."

    # 2. Injection scanner checks
    if event == "injection_check":
        score = entry.get("score", 0.0)
        source = entry.get("source", "input")
        rule_ids = entry.get("rule_ids") or []
        if decision == "BLOCK":
            rules_str = f" [Rules: {', '.join(rule_ids)}]" if rule_ids else ""
            return f"Blocked: Prompt injection caught in {source} (score: {score:.2f}){rules_str}."
        return f"Passed: Content verified safe from prompt injection (score: {score:.2f})."

    # 3. Human Approval Workflow
    if event == "approval_request":
        tool_req = entry.get("tool", "action")
        risk = entry.get("risk", "HIGH")
        return f"Approval Request: High-risk {risk} operation '{tool_req}' queued for human decision."

    if event == "approval_decision":
        tool_dec = entry.get("tool") or "operation"
        decider = entry.get("decided_by", "supervisor")
        approved = entry.get("approved", False)
        timed_out = entry.get("timed_out", False)
        if timed_out:
            return f"Expired: Request for '{tool_dec}' timed out without supervisor response."
        if approved:
            return f"Approved: Human operator ({decider}) confirmed '{tool_dec}'."
        return f"Rejected: Human operator ({decider}) denied '{tool_dec}' ({entry.get('reason', 'declined')})."

    # 4. Hardware commands
    if event == "hardware_command":
        cmd = entry.get("command", "command")
        ok = entry.get("ok", False)
        adapter = entry.get("adapter", "hardware")
        if ok:
            return f"Hardware Executed: Physical command '{cmd}' dispatched to {adapter}."
        return f"Hardware Failed: Command '{cmd}' failed ({entry.get('error', 'no response')})."

    # 5. Security events & Authentications
    if event == "login_failure":
        return f"Security Alert: Failed login attempt for username '{entry.get('username', 'unknown')}'."
    if event == "login_success":
        return f"Auth: User '{entry.get('username', role)}' logged in successfully."
    if event == "logout":
        return f"Auth: User '{entry.get('username', role)}' logged out."
    if event == "role_change":
        return f"Policy: Role switched from '{entry.get('old_role')}' to '{entry.get('new_role')}'."

    # 6. Attack Lab Simulations
    if event == "attack_lab_run":
        sc_id = entry.get("scenario_id", "simulation")
        stopped_at = entry.get("stopped_at", "gateway")
        return f"Attack Lab: Scenario '{sc_id}' simulated; safely stopped at {stopped_at}."

    # 7. Fallback
    base_text = event or "System Event"
    detail_text = reason or decision or "Logged to hash chain"
    return f"{base_text.replace('_', ' ').title()}: {detail_text}."


def _parse_utc_iso(ts_str: str) -> datetime | None:
    if not ts_str:
        return None
    try:
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.fromisoformat(ts_str)
    except Exception:
        return None


def _matches_filters(
    entry: dict[str, Any],
    dec_upper: str | None,
    role_lower: str | None,
    src_lower: str | None,
    q_lower: str | None,
    start_dt: datetime | None,
    end_dt: datetime | None,
) -> bool:
    """Evaluates an audit entry against active filter parameters."""
    # 1. Decision Filter
    entry_dec = str(entry.get("decision", entry.get("ok", ""))).upper()
    if dec_upper:
        if dec_upper in ("ALLOWED", "ALLOW") and entry_dec not in ("ALLOW", "ALLOWED", "TRUE", "OK"):
            return False
        elif dec_upper in ("BLOCKED", "BLOCK") and entry_dec not in ("BLOCK", "BLOCKED", "DENY", "FALSE"):
            return False
        elif dec_upper in ("WAITING", "WAIT") and entry_dec not in ("REVIEW", "WAITING", "PENDING"):
            return False
        elif dec_upper in ("ERROR", "FAIL") and entry_dec not in ("ERROR", "FAIL"):
            return False
        elif dec_upper not in ("ALLOWED", "ALLOW", "BLOCKED", "BLOCK", "WAITING", "WAIT", "ERROR", "FAIL") and entry_dec != dec_upper:
            return False

    # 2. Role / Actor Filter
    entry_role = str(entry.get("role", entry.get("decided_by", "system"))).lower()
    if role_lower and role_lower != "all":
        if role_lower not in entry_role:
            return False

    # 3. Source Filter
    entry_src = str(entry.get("source", "real")).lower()
    if "scenario_id" in entry or entry.get("event") == "attack_lab_run":
        entry_src = "attack_lab"
    if src_lower and src_lower != "all":
        if src_lower == "real" and entry_src not in ("real", "hardware", "user"):
            return False
        elif src_lower == "attack_lab" and "attack" not in entry_src:
            return False
        elif src_lower == "virtual" and entry_src not in ("tool_output", "virtual", "system"):
            return False

    # 4. Date Range
    ts_raw = entry.get("timestamp")
    entry_dt = _parse_utc_iso(ts_raw)
    if entry_dt:
        if start_dt and entry_dt < start_dt:
            return False
        if end_dt and entry_dt > end_dt:
            return False

    # 5. Search Query (free text across all fields: decision, tool, reason, summary, text, hash)
    if q_lower:
        haystack = f"{entry.get('decision', '')} {entry.get('tool', '')} {entry.get('reason', '')} {entry.get('plain_summary', '')} {entry.get('text', '')} {entry.get('event', '')} {entry.get('entry_hash', '')} {entry.get('role', '')} {entry.get('username', '')}".lower()
        if q_lower not in haystack:
            return False

    return True


def read_entries_reverse(
    log_file: Path,
    limit: int = 50,
    offset: int = 0,
    decision_filter: str | None = None,
    role_filter: str | None = None,
    source_filter: str | None = None,
    search_query: str | None = None,
    start_dt: datetime | None = None,
    end_dt: datetime | None = None,
    block_size: int = 65536,
) -> tuple[list[dict[str, Any]], int, int]:
    """
    High-performance streaming tail reader.
    Scans the audit log backwards from end-of-file using 64KB blocks.
    Never loads the entire file into memory; supports arbitrarily large 100k+ line files.
    Returns: (matching_page_items, total_matching, total_lines_in_file)
    """
    if not log_file.exists():
        return [], 0, 0

    block_size = max(16, block_size)
    total_lines = 0
    total_matching = 0
    collected_items: list[dict[str, Any]] = []

    q_lower = search_query.strip().lower() if search_query else None
    dec_upper = decision_filter.strip().upper() if decision_filter else None
    role_lower = role_filter.strip().lower() if role_filter else None
    src_lower = source_filter.strip().lower() if source_filter else None

    # Fast reverse scan
    with _file_lock(log_file):
        file_size = log_file.stat().st_size
        if file_size == 0:
            return [], 0, 0

        with open(log_file, "rb") as f:
            cursor = file_size
            remainder = b""

            while cursor > 0:
                step = min(block_size, cursor)
                cursor -= step
                f.seek(cursor)
                chunk = f.read(step) + remainder
                lines = chunk.split(b"\n")
                remainder = lines[0]

                for raw_line in reversed(lines[1:]):
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    total_lines += 1

                    try:
                        entry = json.loads(raw_line.decode("utf-8", errors="replace"))
                    except Exception:
                        continue

                    if not _matches_filters(entry, dec_upper, role_lower, src_lower, q_lower, start_dt, end_dt):
                        continue

                    # Item passed all filters
                    total_matching += 1

                    # Collect page slice
                    if total_matching > offset and len(collected_items) < limit:
                        entry["plain_summary"] = format_plain_summary(entry)
                        entry["category"] = classify_audit_decision(entry)
                        collected_items.append(entry)

            # Process leftover remainder if cursor reached 0
            if remainder.strip():
                total_lines += 1
                try:
                    entry = json.loads(remainder.decode("utf-8", errors="replace"))
                    if _matches_filters(entry, dec_upper, role_lower, src_lower, q_lower, start_dt, end_dt):
                        total_matching += 1
                        if total_matching > offset and len(collected_items) < limit:
                            entry["plain_summary"] = format_plain_summary(entry)
                            entry["category"] = classify_audit_decision(entry)
                            collected_items.append(entry)
                except Exception:
                    pass

    return collected_items, total_matching, total_lines


def escape_csv_cell(value: Any) -> str:
    """
    Prevents CSV Spreadsheet Formula Injection (CWE-1236).
    If a cell value begins with =, +, -, @, \\t, or \\r, prepend with a single quote.
    """
    if value is None:
        return ""
    s = str(value)
    if s.startswith(("=", "+", "-", "@", "\t", "\r")):
        return f"'{s}"
    return s


# =========================================================================
# API ROUTES (ADMIN ONLY)
# =========================================================================

@audit_bp.route("/api/audit/entries", methods=["GET"])
@role_required("admin")
def api_audit_entries():
    """Returns paginated, filtered audit log records read in reverse streaming."""
    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = min(200, max(1, int(request.args.get("limit", 50))))
        offset = (page - 1) * limit

        decision = request.args.get("decision")
        role = request.args.get("role")
        source = request.args.get("source")
        search = request.args.get("search")

        # Parse date filters if provided
        start_date_str = request.args.get("start_date")
        end_date_str = request.args.get("end_date")
        start_dt = _parse_utc_iso(start_date_str) if start_date_str else None
        end_dt = _parse_utc_iso(end_date_str) if end_date_str else None

        log_file = get_log_file()
        items, total_matching, total_lines = read_entries_reverse(
            log_file=log_file,
            limit=limit,
            offset=offset,
            decision_filter=decision,
            role_filter=role,
            source_filter=source,
            search_query=search,
            start_dt=start_dt,
            end_dt=end_dt,
        )

        return jsonify({
            "status": "success",
            "page": page,
            "limit": limit,
            "total_matching": total_matching,
            "total_lines": total_lines,
            "total_pages": (total_matching + limit - 1) // limit if total_matching > 0 else 1,
            "entries": items,
        })
    except Exception as e:
        return jsonify({"status": "error", "message": "Failed to query audit entries", "detail": str(e)}), 500


@audit_bp.route("/api/audit/export/csv", methods=["GET"])
@role_required("admin")
def api_audit_export_csv():
    """
    Streams filtered audit entries as an RFC 4180 CSV file with formula-injection defenses.
    """
    try:
        decision = request.args.get("decision")
        role = request.args.get("role")
        source = request.args.get("source")
        search = request.args.get("search")

        log_file = get_log_file()
        # Read up to 5000 matching items for CSV export
        items, _, _ = read_entries_reverse(
            log_file=log_file,
            limit=5000,
            offset=0,
            decision_filter=decision,
            role_filter=role,
            source_filter=source,
            search_query=search,
        )

        output = io.StringIO()
        # Header row
        output.write("Timestamp (UTC),Timestamp (IST),Actor / Role,Decision,Event / Tool,Plain English Summary,Entry Hash,Prev Hash\n")

        for item in items:
            ts_utc = item.get("timestamp", "")
            ts_dt = _parse_utc_iso(ts_utc)
            if ts_dt:
                # Convert to IST (UTC + 5:30)
                ts_ist = (ts_dt + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%d %H:%M:%S IST")
            else:
                ts_ist = ""

            actor = item.get("role", item.get("decided_by", "system"))
            dec = item.get("decision", item.get("ok", "INFO"))
            ev = item.get("event", item.get("tool", "system"))
            summary = item.get("plain_summary", "")
            eh = item.get("entry_hash", "")
            ph = item.get("prev_hash", "")

            row = [
                escape_csv_cell(ts_utc),
                escape_csv_cell(ts_ist),
                escape_csv_cell(actor),
                escape_csv_cell(dec),
                escape_csv_cell(ev),
                escape_csv_cell(summary.replace('"', '""')),
                escape_csv_cell(eh),
                escape_csv_cell(ph),
            ]
            output.write(f'"{row[0]}","{row[1]}","{row[2]}","{row[3]}","{row[4]}","{row[5]}","{row[6]}","{row[7]}"\n')

        csv_data = output.getvalue()
        output.close()

        timestamp_label = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"aegis_audit_log_{timestamp_label}.csv"

        return Response(
            csv_data,
            mimetype="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "text/csv; charset=utf-8",
                "X-Content-Type-Options": "nosniff",
            },
        )
    except Exception as e:
        return jsonify({"status": "error", "message": "CSV export failed", "detail": str(e)}), 500


@audit_bp.route("/api/audit/anchor/export", methods=["GET"])
@role_required("admin")
def api_audit_anchor_export():
    """Generates and downloads an external anchor record with an off-site custody warning."""
    try:
        log_file = get_log_file()
        anchor = create_anchor(log_file)
        anchor_payload = {
            "version": "1.0",
            "algorithm": "SHA-256",
            "count": anchor["count"],
            "head_hash": anchor["head_hash"],
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "warning": "STORE THIS OFF THIS COMPUTER (print it, phone, GitHub, hardware ledger). An anchor stored on the same disk proves nothing if the host is compromised.",
        }
        timestamp_label = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"aegis_anchor_{timestamp_label}.json"

        return Response(
            json.dumps(anchor_payload, indent=2),
            mimetype="application/json",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "application/json; charset=utf-8",
            },
        )
    except Exception as e:
        return jsonify({"status": "error", "message": "Failed to generate anchor", "detail": str(e)}), 500


@audit_bp.route("/api/audit/anchor/check", methods=["POST"])
@role_required("admin")
@csrf_protect
def api_audit_anchor_check():
    """Validates the active audit log against an uploaded or pasted anchor record."""
    try:
        data = request.get_json(silent=True) or {}
        raw_anchor = data.get("anchor_text", "").strip()
        if not raw_anchor:
            raw_anchor = request.form.get("anchor_text", "").strip()

        if not raw_anchor and "file" in request.files:
            file_obj = request.files["file"]
            raw_anchor = file_obj.read().decode("utf-8", errors="replace").strip()

        if not raw_anchor:
            return jsonify({"status": "error", "message": "No anchor data provided. Paste JSON/anchor string or upload file."}), 400

        log_file = get_log_file()
        ok, msg = check_anchor_line(raw_anchor, log_file)

        return jsonify({
            "status": "success" if ok else "tampered",
            "verified": ok,
            "message": msg,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as e:
        return jsonify({"status": "error", "message": "Anchor verification failed", "detail": str(e)}), 500


def classify_audit_decision(entry: dict[str, Any]) -> str:
    """
    Categorizes audit record into one of 5 distinct badge states:
    ALLOWED, BLOCKED, WAITING, ERROR, or INFO.
    Only genuine failures and execution faults are ERROR; informational lifecycle
    events (login success, role switches, turn summaries) map to INFO.
    """
    raw_dec = str(entry.get("decision", "")).strip().upper()
    event = str(entry.get("event", "")).strip().lower()
    ok = entry.get("ok")

    if raw_dec in ("ALLOW", "ALLOWED", "PERMIT"):
        return "ALLOWED"
    if raw_dec in ("BLOCK", "BLOCKED", "DENY", "DENIED", "REJECT", "REJECTED"):
        return "BLOCKED"
    if raw_dec in ("REVIEW", "WAITING", "PENDING", "HOLD"):
        return "WAITING"
    if raw_dec in ("ERROR", "FAIL", "FAILED") or event in ("error", "execution_error", "hardware_failure", "login_failure"):
        return "ERROR"
    if ok is False and raw_dec not in ("BLOCK", "BLOCKED"):
        return "ERROR"
    if ok is True and not raw_dec:
        return "ALLOWED"
    return "INFO"


def _read_tail_entries(log_file: Path, n: int = 6) -> tuple[list[dict[str, Any]] | None, str | None]:
    """
    Reads the last n non-empty lines from EOF in blocks without loading the whole file.
    Returns (entries, error_message). If corrupted JSON is found, returns (None, err_msg).
    """
    if not log_file.exists():
        return [], None

    block_size = 65536
    raw_lines: list[str] = []

    with _file_lock(log_file):
        file_size = log_file.stat().st_size
        if file_size == 0:
            return [], None

        with open(log_file, "rb") as f:
            cursor = file_size
            remainder = b""
            while cursor > 0 and len(raw_lines) < n:
                step = min(block_size, cursor)
                cursor -= step
                f.seek(cursor)
                chunk = f.read(step) + remainder
                parts = chunk.split(b"\n")
                remainder = parts[0]
                for p in reversed(parts[1:]):
                    s = p.strip()
                    if s:
                        try:
                            line_str = s.decode("utf-8")
                        except Exception:
                            return None, "Corrupted encoding in audit log"
                        raw_lines.append(line_str)
                        if len(raw_lines) >= n:
                            break

            if len(raw_lines) < n and remainder.strip():
                try:
                    raw_lines.append(remainder.strip().decode("utf-8"))
                except Exception:
                    return None, "Corrupted encoding in audit log"

    raw_lines.reverse()

    entries = []
    for line_str in raw_lines:
        try:
            parsed = json.loads(line_str)
            entries.append(parsed)
        except Exception:
            return None, f"Invalid JSON in audit line: {line_str[:40]}..."

    return entries, None


# =========================================================================
# TAMPER DEMONSTRATION LAB (COPY-ONLY SANDBOX)
# Operates strictly on a volatile temp file; NEVER touches real log.
# =========================================================================

@audit_bp.route("/api/audit/tamper_demo", methods=["POST"])
@role_required("admin")
@csrf_protect
def api_audit_tamper_demo():
    """
    Simulates attacks on a temporary copy of the audit log to demonstrate
    how the cryptographic hash chain breaks, and why external anchors are necessary.
    Ensured: real audit_log.jsonl is NEVER written to.
    """
    client_ip = request.remote_addr or "127.0.0.1"
    if not _check_tamper_rate_limit(client_ip):
        return jsonify({"status": "error", "message": "Rate limit exceeded for tamper demo (max 15/min). Please wait."}), 429

    data = request.get_json(silent=True) or {}
    action = data.get("action", "edit_line")

    real_log = get_log_file()
    if not real_log.exists():
        return jsonify({"status": "error", "message": "Real audit log is empty or does not exist."}), 400

    # Memory-safe tail read: retrieve only last 6 lines from EOF without read_text
    tail_entries, json_err = _read_tail_entries(real_log, n=6)
    if json_err:
        return jsonify({"status": "error", "message": f"Audit log contains invalid JSON line: {json_err}"}), 400

    if not tail_entries or len(tail_entries) < 3:
        return jsonify({"status": "error", "message": "Audit log needs at least 3 entries to run the tamper demo."}), 400

    # Build a clean, self-contained demonstration chain starting from genesis 0*64
    demo_chain: list[dict[str, Any]] = []
    prev_h = "0" * 64
    for it in tail_entries:
        clean_content = {k: v for k, v in it.items() if k not in ("prev_hash", "entry_hash", "plain_summary")}
        payload = json.dumps(clean_content, sort_keys=True) + prev_h
        entry_h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        entry_item = dict(clean_content)
        entry_item["prev_hash"] = prev_h
        entry_item["entry_hash"] = entry_h
        demo_chain.append(entry_item)
        prev_h = entry_h

    original_head = demo_chain[-1]["entry_hash"]
    original_count = len(demo_chain)

    tampered_lines = [json.dumps(e) for e in demo_chain]
    explanation = ""
    target_idx = max(1, len(tampered_lines) // 2)

    if action == "edit_line":
        item = json.loads(tampered_lines[target_idx])
        item["decision"] = "ALLOW" if item.get("decision") == "BLOCK" else "BLOCK"
        item["reason"] = "TAMPERED: Unauthorized payload injection"
        tampered_lines[target_idx] = json.dumps(item)
        explanation = f"Line {target_idx + 1} payload was modified. The internal chain check FAILS because the link broke, but the anchor check MATCHES because total count ({original_count}) and the newest hash are unchanged. This demonstrates why an anchor alone cannot catch middle-log tampering."

    elif action == "delete_line":
        deleted_item = json.loads(tampered_lines.pop(target_idx))
        explanation = f"Line {target_idx + 1} was deleted. Line {target_idx + 1}'s prev_hash now points to a missing link."

    elif action == "truncate":
        tampered_lines = tampered_lines[:-1]
        explanation = "The last entry was deleted. Notice: The internal chain passes! But an EXTERNAL ANCHOR catches it immediately."

    elif action == "rewrite":
        item = json.loads(tampered_lines[target_idx])
        item["reason"] = "HISTORY REWRITTEN: Artificial benign record"
        for i in range(target_idx, len(tampered_lines)):
            cur_item = json.loads(tampered_lines[i]) if i != target_idx else item
            prev_h = json.loads(tampered_lines[i - 1])["entry_hash"] if i > 0 else "0" * 64
            clean_item = {k: v for k, v in cur_item.items() if k not in ("prev_hash", "entry_hash")}
            payload = json.dumps(clean_item, sort_keys=True) + prev_h
            clean_item["prev_hash"] = prev_h
            clean_item["entry_hash"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            tampered_lines[i] = json.dumps(clean_item)
        explanation = f"An attacker altered line {target_idx + 1} and recomputed all subsequent hashes. The internal chain passes, but the EXTERNAL ANCHOR head_hash mismatches."

    elif action == "reset":
        explanation = "All 6 blocks link correctly. Press an attack button to see what breaks."

    else:
        return jsonify({"status": "error", "message": f"Unknown tamper action '{action}'"}), 400

    # Verify the tampered lines in a volatile sandbox
    temp_dir = tempfile.mkdtemp(prefix="aegis_tamper_demo_")
    try:
        temp_log = Path(temp_dir) / "demo_audit.jsonl"
        temp_log.write_text("\n".join(tampered_lines) + "\n", encoding="utf-8")

        # Verify chain integrity
        is_intact, verify_msg = check_audit_log_status(temp_log)

        # Build visual node chain for the UI
        chain_blocks = []
        broken_found = False
        broken_index = None

        for idx, line in enumerate(tampered_lines, start=1):
            entry = json.loads(line)
            eh = entry.get("entry_hash", "")
            ph = entry.get("prev_hash", "")

            # Test this specific link
            expected_prev = "0" * 64 if idx == 1 else json.loads(tampered_lines[idx - 2]).get("entry_hash")
            payload = json.dumps({k: v for k, v in entry.items() if k not in ("prev_hash", "entry_hash")}, sort_keys=True) + ph
            calc_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

            link_ok = (ph == expected_prev) and (eh == calc_hash)

            if not link_ok and not broken_found:
                broken_found = True
                broken_index = idx
                status = "broken"
            elif broken_found:
                status = "after_break"
            else:
                status = "valid"

            chain_blocks.append({
                "block_number": idx,
                "status": status,
                "hash_short": f"{eh[:6]}...{eh[-4:]}" if len(eh) >= 10 else eh,
                "prev_short": f"{ph[:6]}...{ph[-4:]}" if len(ph) >= 10 else ph,
                "event": entry.get("event", entry.get("tool", "entry")),
                "decision": entry.get("decision", "INFO"),
            })

        # Compare with external anchor
        new_head = json.loads(tampered_lines[-1])["entry_hash"] if tampered_lines else "0" * 64
        anchor_matches = (len(tampered_lines) == original_count) and (new_head == original_head)
        # An anchor holds only {count, head_hash}. It matches if count and newest hash match.
        anchor_ok = bool(anchor_matches)
        anchor_status = "Anchor Matches" if anchor_matches else "Anchor Mismatch Detected (History Tampered)"

        return jsonify({
            "status": "success",
            "action": action,
            "chain_ok": is_intact,
            "chain_intact": is_intact,
            "broken_index": broken_index,
            "anchor_ok": anchor_ok,
            "anchor_status": anchor_status,
            "verify_message": verify_msg,
            "explanation": explanation,
            "chain_blocks": chain_blocks,
            "anchor_result": {
                "matches": anchor_matches,
                "expected_count": original_count,
                "actual_count": len(tampered_lines),
                "expected_head": f"{original_head[:8]}...{original_head[-6:]}",
                "actual_head": f"{new_head[:8]}...{new_head[-6:]}",
                "status_text": anchor_status,
            },
        })
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
