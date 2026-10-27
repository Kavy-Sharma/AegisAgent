"""
AegisAgent Phase 8 — Manual Dashboard Approval CLI Tool (No Ollama needed)

Dispatches a HIGH-risk approval request to DashboardApprovalProvider so you can
test approving or denying it in the Streamlit dashboard interface.
"""

from pathlib import Path
import sys

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.approval import ApprovalManager, ApprovalRequest, DashboardApprovalProvider
import security.policy_loader


def main():
    print("=" * 60)
    print(" AegisAgent Phase 8 — Dashboard Approval Test ".center(60, "="))
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
            "Manual operator verification required via Dashboard",
        ],
    )

    print(f"\nGenerated Test Request:")
    print(f"  Request ID   : {req.request_id}")
    print(f"  Tool         : {req.tool}")
    print(f"  Risk Level   : {req.risk}")
    print(f"  Arguments    : {req.args}")
    print(f"  Reasons      : {req.reasons}")
    print(f"  Pending File : data/approvals/pending/{req.request_id}.json")
    print(f"\n--> Open the Streamlit Dashboard at http://127.0.0.1:8501")
    print(f"    (Run: streamlit run dashboard/app.py --server.address 127.0.0.1)")
    print(f"\nWaiting up to {timeout:.0f}s for your decision in the dashboard...")

    result = manager.request(req)

    print("\n" + "-" * 30 + " Decision Result " + "-" * 30)
    print(f"Approved   : {result.approved}")
    print(f"Decided By : {result.decided_by}")
    print(f"Reason     : {result.reason}")
    print(f"Timed Out  : {result.timed_out}")
    print("-" * 77)


if __name__ == "__main__":
    main()
