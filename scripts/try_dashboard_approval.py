"""
AegisAgent Phase 8 -- Manual Web Approvals CLI Test Tool (No Ollama needed)

Dispatches a HIGH-risk approval request to DashboardApprovalProvider so you can
test approving or denying it in the Web Control Room (/approvals).
"""

from pathlib import Path
import sys

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.approval import ApprovalManager, ApprovalRequest, DashboardApprovalProvider
import security.policy_loader


def main():
    print("=" * 60)
    print(" AegisAgent Phase 8 — Web Approval Test ".center(60, "="))
    print("=" * 60)

    timeout = float(security.policy_loader.POLICY.get("approval", {}).get("timeout_seconds", 30.0))
    provider = DashboardApprovalProvider(timeout_seconds=timeout)
    manager = ApprovalManager(provider=provider)

    req = ApprovalRequest(
        session_id="manual_dashboard_test",
        kind="tool_call",
        tool="unlock_door",
        args={"door_id": "front_door", "unlock_duration_sec": 15},
        risk="HIGH",
        reasons=[
            "Physical entry actuation requested (HIGH-risk)",
            "Manual operator verification required via Control Room",
        ],
    )

    print(f"\nGenerated Test Request:")
    print(f"  Request ID   : {req.request_id}")
    print(f"  Tool         : {req.tool}")
    print(f"  Risk Level   : {req.risk}")
    print(f"  Arguments    : {req.args}")
    print(f"  Reasons      : {req.reasons}")
    print(f"  Pending File : data/approvals/pending/{req.request_id}.json")
    print(f"\n--> Open the Web Control Room at http://127.0.0.1:8501/approvals")
    print(f"    (Ensure the server is running via: python start.py)")
    print(f"\nWaiting up to {timeout:.0f}s for your decision in the web interface...")

    result = manager.request(req)

    print("\n" + "-" * 30 + " Decision Result " + "-" * 30)
    print(f"Approved   : {result.approved}")
    print(f"Decided By : {result.decided_by}")
    print(f"Reason     : {result.reason}")
    print(f"Timed Out  : {result.timed_out}")
    print("-" * 77)


if __name__ == "__main__":
    main()
