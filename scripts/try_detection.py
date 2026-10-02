"""
AegisAgent Phase 5 — Interactive Test Harness (No Ollama needed)
"""

import argparse
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import security.gateway


def main():
    parser = argparse.ArgumentParser(description="AegisAgent Prompt Injection Detection Harness")
    parser.add_argument("--session", default="demo", help="Session ID (default: demo)")
    parser.add_argument("--source", choices=["user", "tool_output"], default="user", help="Message source (default: user)")
    args = parser.parse_args()

    session_id = args.session
    source = args.source

    print(f"=== AegisAgent Detection Harness (session: '{session_id}', source: '{source}') ===")
    print("Commands: '/reset' to clear session history | '/source user' or '/source tool_output' | 'quit' to exit\n")

    while True:
        try:
            line = input(f"[{session_id}:{source}] > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not line:
            continue
        if line.lower() in ("quit", "exit"):
            break
        if line.lower() == "/reset":
            engine = security.gateway.get_detection_engine()
            engine.reset_session(session_id)
            print(f"Session '{session_id}' history reset.\n")
            continue
        if line.lower().startswith("/source "):
            new_source = line.split(maxsplit=1)[1].strip()
            if new_source in ("user", "tool_output"):
                source = new_source
                print(f"Source set to '{source}'.\n")
            else:
                print("Invalid source. Use 'user' or 'tool_output'.\n")
            continue

        if source == "user":
            verdict = security.gateway.inspect_user_message(session_id, line)
        else:
            verdict = security.gateway.inspect_tool_output(session_id, line)

        print(f"Decision: {verdict.decision} | Score: {verdict.score:.2f}")
        for res in verdict.results:
            rule_str = f"rules={res.rule_ids}" if res.rule_ids else "rules=[]"
            reasons_str = f"reasons={res.reasons}" if res.reasons else "reasons=[]"
            print(f"  [{res.detector}] score={res.score:.2f}, {rule_str}, {reasons_str}")
        print()


if __name__ == "__main__":
    main()
