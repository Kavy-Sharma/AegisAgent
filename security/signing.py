"""
Phase 8A -- Cryptographic Request & Decision Signing Framework

WHAT THIS FILE DOES:
Provides HMAC-SHA256 signing and verification for IPC payloads between the dashboard,
worker, and approval providers using AEGIS_DASH_SECRET.
If AEGIS_DASH_SECRET is missing from .env / environment, generates a secure 32-byte hex
secret, saves it to .env, and loads it into memory. Never logs the secret.
"""

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets

from security.logger import _file_lock

_SECRET_ENV_KEY = "AEGIS_DASH_SECRET"
_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


def get_secret() -> str:
    """
    Retrieves AEGIS_DASH_SECRET from environment or .env.
    Generates and persists a new 32-byte hex secret if missing.
    Atomic and cross-process safe using logger's file lock.
    Never logs or exposes the secret.
    """
    # 1. Fast check current environment
    val = os.environ.get(_SECRET_ENV_KEY)
    if val and val.strip():
        return val.strip()

    # 2. Acquire cross-process file lock around .env read and write
    with _file_lock(_ENV_FILE):
        # Re-check environment after acquiring lock
        val = os.environ.get(_SECRET_ENV_KEY)
        if val and val.strip():
            return val.strip()

        # Re-read .env file under lock
        if _ENV_FILE.exists():
            try:
                with open(_ENV_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            if k.strip() == _SECRET_ENV_KEY:
                                secret = v.strip().strip("'\"")
                                if secret:
                                    os.environ[_SECRET_ENV_KEY] = secret
                                    return secret
            except Exception:
                pass

        # 3. Generate new 32-byte hex secret and persist to .env under lock
        new_secret = secrets.token_hex(32)
        os.environ[_SECRET_ENV_KEY] = new_secret

        try:
            if _ENV_FILE.exists():
                existing = _ENV_FILE.read_text(encoding="utf-8")
                if not existing.endswith("\n"):
                    existing += "\n"
                existing += f"{_SECRET_ENV_KEY}={new_secret}\n"
                _ENV_FILE.write_text(existing, encoding="utf-8")
            else:
                _ENV_FILE.write_text(f"{_SECRET_ENV_KEY}={new_secret}\n", encoding="utf-8")
        except Exception:
            # If unable to write to .env (e.g. read-only filesystem), we still have os.environ
            pass

        return new_secret


def sign(payload_dict: dict) -> str:
    """
    Computes an HMAC-SHA256 signature over the canonical JSON representation
    of payload_dict using AEGIS_DASH_SECRET.
    """
    canonical_json = json.dumps(payload_dict, sort_keys=True, separators=(",", ":"))
    secret = get_secret()
    return hmac.new(
        secret.encode("utf-8"),
        canonical_json.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify(payload_dict: dict, sig: str) -> bool:
    """
    Verifies that sig matches HMAC-SHA256 of payload_dict using constant-time comparison.
    """
    if not sig or not isinstance(sig, str):
        return False

    try:
        expected = sign(payload_dict)
        return hmac.compare_digest(expected, sig)
    except Exception:
        return False
