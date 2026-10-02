"""
AegisAgent Phase 6 — Interactive Approval Demo (No Ollama needed)
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.approval import ApprovalManager, ApprovalRequest, ConsoleApprovalProvider


def main():
    print("=== AegisAgent Phase 6 Approval Demo ===")
    print("This script simulates a HIGH-risk tool execution request requiring human approval.\n")

    provider = ConsoleApprovalProvider(timeout_seconds=15.0)
    manager = ApprovalManager(provider=provider)

    req = ApprovalRequest(
        session_id="demo_session",
        kind="tool_call",
        tool="activate_alarm",
        args={"duration_sec": 30, "zone": "main_hall"},
        risk="HIGH",
        reasons=["HIGH-risk tool 'activate_alarm' requires explicit human operator approval"],
    )

    result = manager.request(req)

    print("\n--- Approval Result ---")
    print(f"Approved   : {result.approved}")
    print(f"Decided By : {result.decided_by}")
    print(f"Reason     : {result.reason}")
    print(f"Timed Out  : {result.timed_out}")


if __name__ == "__main__":
    main()
