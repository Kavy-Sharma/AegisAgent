import sys
from pathlib import Path
root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))
from security.auth import reset_password, verify_login

if len(sys.argv) < 3:
    print('Usage: python scripts/reset_password.py <username> <new_password>')
    sys.exit(1)

username = sys.argv[1]
new_password = sys.argv[2]
reset_password(username, new_password)
ok, role = verify_login(username, new_password)
if ok:
    print(f'Successfully reset password for {username} (role: {role}).')
else:
    print(f'Failed to verify password after reset.')
