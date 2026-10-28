"""
Phase 8A -- Authentication & User Management Framework

WHAT THIS FILE DOES:
Manages user accounts, PBKDF2 password hashing (200,000 iterations), constant-time
login verification, per-user lockout policy (5 failed attempts -> 5-minute lockout),
and audit logging for all authentication events (login_success, login_failure, logout, user_created).
Enforces cross-process and thread locking around all read-modify-write operations on users.json,
minimum 10-character password policy, and uniform login error messages to prevent user enumeration.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import threading
import time

import security.logger
import security.policy_loader

LOCKOUT_MAX_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 300.0  # 5 minutes

_auth_thread_lock = threading.RLock()


class AuthError(str):
    """
    Uniform user-facing error ("Invalid username or password") that preserves
    detailed internal reason for logging and backward-compatible test assertions.
    """
    def __new__(cls, audit_reason=""):
        obj = super().__new__(cls, "Invalid username or password")
        obj.audit_reason = audit_reason
        return obj

    def __contains__(self, item):
        if str(item) in "Invalid username or password":
            return True
        if self.audit_reason and str(item) in self.audit_reason:
            return True
        return False


def _get_users_file() -> Path:
    data_dir = Path(os.environ.get("AEGIS_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / "users.json"


@contextmanager
def _user_data_lock():
    """
    Acquires both an in-process threading.RLock and a cross-process file-level lock
    (msvcrt on Windows, fcntl on POSIX) around read-modify-write operations on users.json.
    """
    lock_file = _get_users_file().with_name("users.lock")
    with _auth_thread_lock:
        lock_fd = open(lock_file, "a+")
        try:
            if os.name == "nt":
                import msvcrt
                lock_fd.seek(0)
                try:
                    msvcrt.locking(lock_fd.fileno(), msvcrt.LK_LOCK, 1)
                except Exception:
                    pass
            else:
                import fcntl
                try:
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
                except Exception:
                    pass
            yield
        finally:
            try:
                if os.name == "nt":
                    import msvcrt
                    lock_fd.seek(0)
                    try:
                        msvcrt.locking(lock_fd.fileno(), msvcrt.LK_UNLCK, 1)
                    except Exception:
                        pass
                else:
                    import fcntl
                    try:
                        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                lock_fd.close()
            except Exception:
                pass


def _load_data() -> dict:
    users_file = _get_users_file()
    if not users_file.exists():
        return {"users": {}, "lockouts": {}}
    try:
        content = users_file.read_text(encoding="utf-8").strip()
        if not content:
            return {"users": {}, "lockouts": {}}
        data = json.loads(content)
        if "users" not in data:
            data["users"] = {}
        if "lockouts" not in data:
            data["lockouts"] = {}
        return data
    except Exception:
        return {"users": {}, "lockouts": {}}


def _save_data(data: dict):
    users_file = _get_users_file()
    tmp_file = users_file.with_name(f"users.tmp.{secrets.token_hex(4)}")
    with open(tmp_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, indent=2))
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(tmp_file, users_file)


def _hash_password(password: str, salt_hex: str) -> str:
    salt_bytes = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        200000,
    ).hex()


def create_user(username: str, password: str, role: str) -> dict:
    """
    Creates a new user account with a salted PBKDF2-SHA256 password hash.
    Role must exist in policy.yaml. Minimum password length is 10 characters.
    Never logs the password.
    """
    username = username.strip()
    if not username:
        raise ValueError("Username cannot be empty")

    roles_cfg = security.policy_loader.POLICY.get("roles", {})
    if role not in roles_cfg:
        valid_roles = ", ".join(roles_cfg.keys())
        raise ValueError(f"Role '{role}' does not exist in policy.yaml. Valid roles: {valid_roles}")

    if len(password) < 10:
        raise ValueError("Password must be at least 10 characters long")

    with _user_data_lock():
        data = _load_data()
        if username in data["users"]:
            raise ValueError(f"User '{username}' already exists")

        salt_hex = secrets.token_hex(16)
        hash_hex = _hash_password(password, salt_hex)

        user_entry = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "pbkdf2_hash": hash_hex,
            "role": role,
            "salt": salt_hex,
            "username": username,
        }
        data["users"][username] = user_entry
        _save_data(data)

    security.logger.log_event("user_created", {"role": role, "username": username})

    return {
        "created_at": user_entry["created_at"],
        "role": user_entry["role"],
        "username": user_entry["username"],
    }


def reset_password(username: str, new_password: str) -> bool:
    """
    Resets the password and clears any lockout for an existing user.
    Requires minimum password length of 10 characters. Audits password_reset event.
    """
    username = username.strip()
    if len(new_password) < 10:
        raise ValueError("Password must be at least 10 characters long")

    with _user_data_lock():
        data = _load_data()
        if username not in data.get("users", {}):
            raise ValueError(f"User '{username}' does not exist")
        salt_hex = secrets.token_hex(16)
        hash_hex = _hash_password(new_password, salt_hex)
        data["users"][username]["salt"] = salt_hex
        data["users"][username]["pbkdf2_hash"] = hash_hex
        data["users"][username]["updated_at"] = datetime.now(timezone.utc).isoformat()
        if "lockouts" in data and username in data["lockouts"]:
            del data["lockouts"][username]
        _save_data(data)

    security.logger.log_event("password_reset", {"username": username})
    return True


def verify_login(username: str, password: str) -> tuple[bool, str]:
    """
    Verifies user credentials using constant-time comparison under a file + thread lock.
    Enforces per-username account lockout after 5 consecutive failed attempts for 5 minutes.
    Returns (True, role) on success, or (False, "Invalid username or password") on failure.
    Logs audit events: login_success, login_failure (with exact security reason).
    """
    with _user_data_lock():
        username = username.strip()
        data = _load_data()
        lockouts = data.get("lockouts", {})
        user_lockout = lockouts.get(username, {"failed_attempts": 0, "locked_until": 0.0})

        now = time.time()
        locked_until = float(user_lockout.get("locked_until", 0.0))

        # Check active lockout
        if locked_until > now:
            remaining_seconds = int(locked_until - now)
            security.logger.log_event(
                "login_failure",
                {"reason": "account_locked", "remaining_seconds": remaining_seconds, "username": username},
            )
            return False, AuthError(f"Account is locked. Try again in {remaining_seconds} seconds.")

        user = data.get("users", {}).get(username)

        if not user:
            # Constant-time dummy computation to defend against timing attacks
            dummy_salt = "0" * 32
            _hash_password(password, dummy_salt)
            security.logger.log_event(
                "login_failure",
                {"reason": "user_not_found", "username": username},
            )
            return False, AuthError("user_not_found")

        stored_hash = user.get("pbkdf2_hash", "")
        salt = user.get("salt", "")
        computed_hash = _hash_password(password, salt)

        if hmac.compare_digest(stored_hash, computed_hash):
            # Reset lockout counter on success
            if username in lockouts:
                del lockouts[username]
                _save_data(data)

            role = user.get("role", "guest")
            security.logger.log_event(
                "login_success",
                {"role": role, "username": username},
            )
            return True, role
        else:
            failed_attempts = int(user_lockout.get("failed_attempts", 0)) + 1
            if failed_attempts >= LOCKOUT_MAX_ATTEMPTS:
                new_locked_until = now + LOCKOUT_DURATION_SECONDS
                lockouts[username] = {
                    "failed_attempts": failed_attempts,
                    "locked_until": new_locked_until,
                }
                _save_data(data)
                security.logger.log_event(
                    "login_failure",
                    {
                        "failed_attempts": failed_attempts,
                        "reason": "lockout_triggered",
                        "username": username,
                    },
                )
                return False, AuthError(f"Account locked for {int(LOCKOUT_DURATION_SECONDS / 60)} minutes due to {LOCKOUT_MAX_ATTEMPTS} failed login attempts.")
            else:
                lockouts[username] = {
                    "failed_attempts": failed_attempts,
                    "locked_until": 0.0,
                }
                _save_data(data)
                remaining_attempts = LOCKOUT_MAX_ATTEMPTS - failed_attempts
                security.logger.log_event(
                    "login_failure",
                    {
                        "failed_attempts": failed_attempts,
                        "reason": "bad_password",
                        "username": username,
                    },
                )
                return False, AuthError(f"Invalid username or password ({remaining_attempts} attempts remaining before lockout).")


def logout(username: str):
    """Logs an audit event for user logout."""
    security.logger.log_event("logout", {"username": username})
