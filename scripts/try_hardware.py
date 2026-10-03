"""
AegisAgent Phase 7 — Hardware CLI Dispatch Tool (No Ollama needed)
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.hardware import COMMAND_ALLOWLIST, get_bridge


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/try_hardware.py <command>")
        print(f"Allowlisted commands: {', '.join(sorted(COMMAND_ALLOWLIST))}")
        sys.exit(1)

    command = sys.argv[1].strip()

    if command not in COMMAND_ALLOWLIST:
        print(f"Error: '{command}' is not in the hardware command allowlist.")
        print(f"Allowlisted commands: {', '.join(sorted(COMMAND_ALLOWLIST))}")
        sys.exit(1)

    print(f"=== Dispatching Hardware Command: '{command}' ===")
    bridge = get_bridge()
    result = bridge.publish(command)

    print("\n--- Result ---")
    print(f"Success : {result.ok}")
    print(f"Error   : {result.error}")
    print(f"Device Online : {bridge.is_device_online()}")


if __name__ == "__main__":
    main()
