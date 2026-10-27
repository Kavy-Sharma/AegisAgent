"""
Phase 6 — Human-In-The-Loop Approval Framework
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any
import uuid

import security.logger
import security.policy_loader


def sanitize_for_console(val: Any, max_len: int = 200) -> str:
    """
    Sanitizes values for display in the console by stripping ANSI escape sequences,
    control characters, and truncating to max_len.
    """
    if val is None:
        return "None"
    if isinstance(val, (dict, list)):
        str_val = json.dumps(val, sort_keys=True)
    else:
        str_val = str(val)

    # Strip ANSI escape codes
    str_val = re.sub(r"\x1b\[[0-9;]*[mG-Z]", "", str_val)
    # Strip control characters (C0 and C1 control codes except newlines/tabs)
    str_val = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", str_val)

    if len(str_val) > max_len:
        return str_val[:max_len] + "... [truncated]"
    return str_val


@dataclass
class ApprovalRequest:
    session_id: str
    kind: str  # "tool_call" | "message_review"
    tool: str | None
    args: dict
    risk: str
    reasons: list[str] = field(default_factory=list)
    request_id: str = ""
    request_hash: str = ""
    created_at: str = ""

    def __post_init__(self):
        if not self.request_id:
            self.request_id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.request_hash:
            tool_str = self.tool if self.tool is not None else ""
            canonical_args = json.dumps(self.args or {}, sort_keys=True)
            payload = f"{self.kind}{tool_str}{canonical_args}"
            self.request_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class ApprovalResult:
    approved: bool
    decided_by: str
    reason: str
    timed_out: bool = False


class ApprovalProvider(ABC):
    @abstractmethod
    def request_approval(self, req: ApprovalRequest) -> ApprovalResult:
        pass


class ConsoleApprovalProvider(ApprovalProvider):
    def __init__(self, timeout_seconds: float = 30.0):
        self.timeout_seconds = timeout_seconds

    def _timed_input(self, prompt_text: str, timeout_sec: float) -> str | None:
        print(prompt_text, end="", flush=True)
        start_time = time.time()

        if os.name == "nt":
            import msvcrt
            chars = []
            while True:
                if msvcrt.kbhit():
                    ch = msvcrt.getwche()
                    if ch in ("\r", "\n"):
                        print()
                        return "".join(chars).strip()
                    elif ch == "\003":  # Ctrl+C
                        raise KeyboardInterrupt
                    elif ch == "\b":
                        if chars:
                            chars.pop()
                    else:
                        chars.append(ch)
                if (time.time() - start_time) >= timeout_sec:
                    print("\n[TIMEOUT]")
                    return None
                time.sleep(0.05)
        else:
            import select
            rlist, _, _ = select.select([sys.stdin], [], [], timeout_sec)
            if rlist:
                return sys.stdin.readline().rstrip("\r\n").strip()
            else:
                print("\n[TIMEOUT]")
                return None

    def request_approval(self, req: ApprovalRequest) -> ApprovalResult:
        try:
            print("\n" + "=" * 60)
            print(" SECURITY GATEWAY APPROVAL REQUIRED ".center(60, "="))
            print(f" Request ID  : {sanitize_for_console(req.request_id)}")
            print(f" Session ID  : {sanitize_for_console(req.session_id)}")
            print(f" Kind        : {sanitize_for_console(req.kind)}")
            print(f" Tool        : {sanitize_for_console(req.tool)}")
            print(f" Risk Level  : {sanitize_for_console(req.risk)}")
            print(f" Arguments   : {sanitize_for_console(req.args)}")
            print(f" Reasons     : {sanitize_for_console(req.reasons)}")
            print("=" * 60)

            max_reasks = 2
            attempts = 0

            while attempts <= max_reasks:
                prompt_msg = f"Approve action? (y/n) [timeout {self.timeout_seconds}s]: "
                user_ans = self._timed_input(prompt_msg, self.timeout_seconds)

                if user_ans is None:
                    return ApprovalResult(
                        approved=False,
                        decided_by="timeout",
                        reason="Approval timed out",
                        timed_out=True,
                    )

                norm_ans = user_ans.lower().strip()
                if norm_ans in ("y", "yes"):
                    return ApprovalResult(
                        approved=True,
                        decided_by="human_operator",
                        reason="Approved by human operator via console",
                        timed_out=False,
                    )
                elif norm_ans in ("n", "no"):
                    return ApprovalResult(
                        approved=False,
                        decided_by="human_operator",
                        reason="Denied by human operator via console",
                        timed_out=False,
                    )
                else:
                    attempts += 1
                    if attempts <= max_reasks:
                        print(f"Invalid input '{sanitize_for_console(user_ans)}'. Please enter 'y' or 'n'.")

            return ApprovalResult(
                approved=False,
                decided_by="system",
                reason="Too many invalid responses",
                timed_out=False,
            )

        except (EOFError, KeyboardInterrupt):
            print("\n[APPROVAL CANCELLED BY OPERATOR]")
            return ApprovalResult(
                approved=False,
                decided_by="system",
                reason="Approval cancelled by operator (fail closed)",
                timed_out=False,
            )
        except Exception as e:
            return ApprovalResult(
                approved=False,
                decided_by="system",
                reason=f"Approval prompt error: {e}",
                timed_out=False,
            )


class ScriptedApprovalProvider(ApprovalProvider):
    """Provider for testing with pre-scripted responses."""

    def __init__(self, responses: list[str | ApprovalResult] | None = None):
        self.responses = list(responses) if responses else []
        self.call_count = 0

    def request_approval(self, req: ApprovalRequest) -> ApprovalResult:
        self.call_count += 1
        if not self.responses:
            return ApprovalResult(
                approved=False,
                decided_by="scripted_default",
                reason="No scripted response remaining",
                timed_out=False,
            )

        resp = self.responses.pop(0)

        if isinstance(resp, ApprovalResult):
            return resp
        elif resp == "error":
            raise RuntimeError("Scripted provider simulated error")
        elif resp == "timeout":
            return ApprovalResult(
                approved=False,
                decided_by="timeout",
                reason="Approval timed out",
                timed_out=True,
            )
        elif str(resp).lower() in ("y", "yes"):
            return ApprovalResult(
                approved=True,
                decided_by="human_operator",
                reason="Approved by scripted operator",
                timed_out=False,
            )
        elif str(resp).lower() in ("n", "no"):
            return ApprovalResult(
                approved=False,
                decided_by="human_operator",
                reason="Denied by scripted operator",
                timed_out=False,
            )
        else:
            return ApprovalResult(
                approved=False,
                decided_by="human_operator",
                reason=f"Scripted invalid response '{resp}'",
                timed_out=False,
            )


class DashboardApprovalProvider(ApprovalProvider):
    def __init__(
        self,
        timeout_seconds: float = 30.0,
        poll_interval: float = 0.3,
        base_dir: Path | str | None = None,
    ):
        self.timeout_seconds = timeout_seconds
        self.poll_interval = poll_interval
        if base_dir is None:
            self.base_dir = Path(__file__).resolve().parent.parent / "data" / "approvals"
        else:
            self.base_dir = Path(base_dir)

        self.pending_dir = self.base_dir / "pending"
        self.decisions_dir = self.base_dir / "decisions"
        self.pending_dir.mkdir(parents=True, exist_ok=True)
        self.decisions_dir.mkdir(parents=True, exist_ok=True)

    def request_approval(self, req: ApprovalRequest) -> ApprovalResult:
        created_at_iso = req.created_at or datetime.now(timezone.utc).isoformat()
        now_ts = time.time()
        expires_at_iso = datetime.fromtimestamp(now_ts + self.timeout_seconds, tz=timezone.utc).isoformat()

        pending_data = {
            "request_id": req.request_id,
            "kind": req.kind,
            "tool": req.tool,
            "args": req.args,
            "risk": req.risk,
            "reasons": req.reasons,
            "request_hash": req.request_hash,
            "created_at": created_at_iso,
            "expires_at": expires_at_iso,
        }

        pending_file = self.pending_dir / f"{req.request_id}.json"
        tmp_pending_file = self.pending_dir / f"{req.request_id}.tmp.{uuid.uuid4().hex[:6]}"
        decision_file = self.decisions_dir / f"{req.request_id}.json"

        try:
            # Write atomically (temp file then os.replace)
            with open(tmp_pending_file, "w", encoding="utf-8") as f:
                f.write(json.dumps(pending_data, indent=2))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_pending_file, pending_file)
        except Exception as e:
            if tmp_pending_file.exists():
                try:
                    tmp_pending_file.unlink()
                except Exception:
                    pass
            return ApprovalResult(
                approved=False,
                decided_by="system",
                reason=f"Failed to create pending approval file: {e}",
                timed_out=False,
            )

        start_time = time.time()
        try:
            while (time.time() - start_time) < self.timeout_seconds:
                if decision_file.exists():
                    try:
                        content = decision_file.read_text(encoding="utf-8").strip()
                        if not content:
                            time.sleep(self.poll_interval)
                            continue
                        dec_data = json.loads(content)
                    except Exception as e:
                        return ApprovalResult(
                            approved=False,
                            decided_by="system",
                            reason=f"Malformed decision file: {e}",
                            timed_out=False,
                        )

                    # Verify request_hash
                    decision_hash = dec_data.get("request_hash")
                    if decision_hash != req.request_hash:
                        return ApprovalResult(
                            approved=False,
                            decided_by="dashboard_operator",
                            reason="hash mismatch",
                            timed_out=False,
                        )

                    approved = bool(dec_data.get("approved", False))
                    default_reason = (
                        "Approved by operator via dashboard"
                        if approved
                        else "Denied by operator via dashboard"
                    )
                    reason = dec_data.get("reason") or default_reason

                    return ApprovalResult(
                        approved=approved,
                        decided_by="dashboard_operator",
                        reason=reason,
                        timed_out=False,
                    )

                time.sleep(self.poll_interval)

            return ApprovalResult(
                approved=False,
                decided_by="timeout",
                reason="Approval timed out",
                timed_out=True,
            )

        except Exception as e:
            return ApprovalResult(
                approved=False,
                decided_by="system",
                reason=f"Dashboard approval error: {e}",
                timed_out=False,
            )
        finally:
            for fpath in (pending_file, decision_file, tmp_pending_file):
                try:
                    if fpath.exists():
                        fpath.unlink()
                except Exception:
                    pass


class ApprovalManager:
    def __init__(
        self,
        policy_dict: dict | None = None,
        provider: ApprovalProvider | None = None,
        audit_logger=None,
    ):
        if policy_dict is None:
            policy_dict = security.policy_loader.POLICY
        self.policy_dict = policy_dict

        approval_cfg = policy_dict.get("approval", {})
        self.enabled = approval_cfg.get("enabled", True)
        self.timeout_seconds = float(approval_cfg.get("timeout_seconds", 30.0))
        self.provider_type = str(approval_cfg.get("provider", "console")).lower().strip()

        if provider is None:
            if self.provider_type == "dashboard":
                provider = DashboardApprovalProvider(timeout_seconds=self.timeout_seconds)
            else:
                provider = ConsoleApprovalProvider(timeout_seconds=self.timeout_seconds)
        self.provider = provider

        if audit_logger is None:
            audit_logger = security.logger
        self.audit_logger = audit_logger

    def request(self, req: ApprovalRequest) -> ApprovalResult:
        if not self.enabled:
            self.audit_logger.log_approval_request(req)
            res = ApprovalResult(
                approved=True,
                decided_by="policy_disabled",
                reason="Approval disabled by policy",
                timed_out=False,
            )
            self.audit_logger.log_approval_decision(req, res)
            return res

        # 1. Write audit event BEFORE asking provider
        self.audit_logger.log_approval_request(req)

        try:
            res = self.provider.request_approval(req)
        except Exception as e:
            # Audit provider error and return DENY
            self.audit_logger.log_approval_error(req, str(e))
            res = ApprovalResult(
                approved=False,
                decided_by="system",
                reason=f"Provider exception: {e}",
                timed_out=False,
            )
            return res

        # 2. Write audit decision AFTER provider returns
        self.audit_logger.log_approval_decision(req, res)
        return res
