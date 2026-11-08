"""
CLI script to reset an AegisAgent user's password and clear any active lockout.
Usage:
  python scripts/reset_password.py --username admin [--password newpassword]
"""

import argparse
import getpass
from pathlib import Path
import sys

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.auth import reset_password


def main():
    parser = argparse.ArgumentParser(description="Reset an AegisAgent user password")
    parser.add_argument("--username", "-u", required=True, help="Username")
    parser.add_argument("--password", "-p", default=None, help="New password (prompted if omitted)")
    args = parser.parse_args()

    password = args.password
    if not password:
        password = getpass.getpass("Enter new password: ")
        confirm = getpass.getpass("Confirm new password: ")
        if password != confirm:
            print("Error: Passwords do not match.")
            sys.exit(1)

    try:
        reset_password(args.username, password)
        print(f"Successfully reset password for user '{args.username}' and cleared all lockouts.")
    except Exception as e:
        print(f"Error resetting password: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
