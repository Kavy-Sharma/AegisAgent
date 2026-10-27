"""
CLI script to create a new AegisAgent user in data/users.json.
Usage:
  python scripts/create_user.py --username admin --role admin [--password secret]
"""

import argparse
import getpass
from pathlib import Path
import sys

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.auth import create_user
import security.policy_loader


def main():
    parser = argparse.ArgumentParser(description="Create a new AegisAgent user")
    parser.add_argument("--username", "-u", required=True, help="Username")
    parser.add_argument("--role", "-r", required=True, help="Role (must exist in policy.yaml)")
    parser.add_argument("--password", "-p", default=None, help="Password (prompted if omitted)")
    args = parser.parse_args()

    password = args.password
    if not password:
        password = getpass.getpass("Enter password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Error: Passwords do not match.")
            sys.exit(1)

    try:
        user = create_user(args.username, password, args.role)
        print(f"Successfully created user '{user['username']}' with role '{user['role']}'.")
    except Exception as e:
        print(f"Error creating user: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
