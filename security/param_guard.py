"""
security/param_guard.py - Parameter Safety Guard

WHAT THIS FILE DOES:
Inspects tool arguments against declarative parameter safety rules defined in the active policy:
1. Strict argument validation: rejects missing guarded arguments and unexpected arguments
   not declared in the tool schema.
2. path_safe: prevents directory traversal ('..'), absolute paths, drive letters, backslashes,
   null bytes, length overflows, percent characters ('%'), non-ASCII characters, and control characters.
3. url_allowlist: restricts URLs to https scheme, standard port 443, non-IP hosts, no embedded
   credentials, no backslashes, no whitespace, no non-ASCII/control characters, stripping trailing
   dots on hosts before matching domain/subdomain allowlists.
4. sql_readonly: keyword guard, not a SQL parser. Enforces single SELECT statements, blocks SQL
   comments, and rejects destructive/data-manipulation keywords (drop, delete, update, insert,
   into, union, load_extension, exec, call, merge, etc.).

Generic implementation: Contains zero tool names or hardcoded tool bindings.
Unknown rule types fail closed on startup / policy load.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
import urllib.parse

# Known rule types supported by parameter guard
KNOWN_RULE_TYPES = {"path_safe", "url_allowlist", "sql_readonly"}

# Forbidden whole words for sql_readonly guard
FORBIDDEN_SQL_WORDS = re.compile(
    r"\b(drop|delete|update|insert|alter|create|truncate|attach|pragma|replace|grant|into|union|load_extension|exec|call|merge)\b",
    re.IGNORECASE,
)


def validate_rule_type(rule_type: str) -> None:
    """Validates that a rule type is known. Raises ValueError if unknown."""
    if rule_type not in KNOWN_RULE_TYPES:
        raise ValueError(
            f"Unknown param guard rule type: '{rule_type}'. "
            f"Must be one of: {sorted(list(KNOWN_RULE_TYPES))}"
        )


def check_path_safe(val: Any, rule_opts: dict[str, Any] | None = None) -> tuple[bool, str]:
    """
    Validates a filesystem path parameter:
    - Must be a string
    - Max length 120 chars
    - No null bytes
    - No non-ASCII characters
    - No control characters
    - No percent character ('%')
    - No '..' traversal sequence
    - No backslashes
    - No leading '/' or '\\'
    - No drive letters (e.g. 'C:')
    """
    if not isinstance(val, str):
        return False, "path parameter must be a string"

    if len(val) > 120:
        return False, f"path length ({len(val)}) exceeds maximum limit of 120 characters"

    if "\x00" in val:
        return False, "null byte detected in path"

    if not val.isascii():
        return False, "non-ASCII character detected in path"

    if any(ord(c) < 32 or ord(c) == 127 for c in val):
        return False, "control character detected in path"

    if "%" in val:
        return False, "percent character ('%') not allowed in path"

    if ".." in val:
        return False, "directory traversal sequence ('..') detected in path"

    if "\\" in val:
        return False, "backslash ('\\') not allowed in path"

    if val.startswith("/") or val.startswith("\\"):
        return False, "absolute path leading slash not allowed"

    if re.match(r"^[a-zA-Z]:", val):
        return False, f"drive letter detected in path: '{val[:2]}'"

    return True, ""


def check_url_allowlist(val: Any, rule_opts: dict[str, Any] | None = None) -> tuple[bool, str]:
    """
    Validates a URL against an allowlist:
    - Must be a string
    - https scheme only
    - Reject backslash, whitespace, control character, non-ASCII
    - Reject IP-literal hosts (IPv4, IPv6)
    - Reject localhost
    - Reject user credentials ('user:pass@')
    - Reject ports other than 443
    - Strip one trailing dot from host before matching
    - Host must match allowed_hosts (exact match or subdomain)
    """
    if not isinstance(val, str):
        return False, "url parameter must be a string"

    if "\\" in val:
        return False, "backslash not allowed in URL"

    if not val.isascii():
        return False, "non-ASCII character detected in URL"

    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in val):
        return False, "whitespace or control character detected in URL"

    rule_opts = rule_opts or {}
    allowed_hosts = [h.strip().lower() for h in rule_opts.get("allowed_hosts", []) if h.strip()]

    # Parse URL
    try:
        parsed = urllib.parse.urlsplit(val)
    except Exception as e:
        return False, f"malformed URL: {e}"

    if parsed.scheme.lower() != "https":
        return False, f"scheme '{parsed.scheme}' not allowed (only https is permitted)"

    # Check for embedded credentials
    if "@" in parsed.netloc or parsed.username or parsed.password:
        return False, "credentials ('user:pass@') in URL are not allowed"

    # Check port
    try:
        port = parsed.port
    except ValueError:
        return False, "invalid port in URL"

    if port is not None and port != 443:
        return False, f"non-standard port {port} not allowed (only port 443 permitted)"

    host = (parsed.hostname or "").lower()
    if not host:
        return False, "missing hostname in URL"

    # Strip one trailing dot from host if present before checks
    if host.endswith("."):
        host = host[:-1]

    if not host:
        return False, "missing hostname in URL"

    if host == "localhost" or host.endswith(".localhost"):
        return False, "localhost host is not allowed"

    # Check for IP-literal hosts
    host_clean = host.strip("[]")
    try:
        ipaddress.ip_address(host_clean)
        return False, f"IP-literal host '{host}' is not allowed"
    except ValueError:
        pass

    if re.match(r"^\d+(\.\d+)*$", host):
        return False, f"IP-literal host '{host}' is not allowed"

    # Check against allowed_hosts list (exact or subdomain)
    if not allowed_hosts:
        return False, "no allowed hosts configured in policy"

    is_allowed = any(host == ah or host.endswith("." + ah) for ah in allowed_hosts)
    if not is_allowed:
        return False, f"host '{host}' not in policy allowed_hosts: {allowed_hosts}"

    return True, ""


def check_sql_readonly(val: Any, rule_opts: dict[str, Any] | None = None) -> tuple[bool, str]:
    """
    Validates a SQL query parameter:
    - keyword guard, not a SQL parser.
    - Exactly one statement.
    - Must start with SELECT (case-insensitive after strip).
    - Reject comments ('--', '/*').
    - Reject a ';' followed by more non-space text.
    - Reject forbidden keywords as whole words anywhere.
    - Length <= 500 chars.
    """
    if not isinstance(val, str):
        return False, "query parameter must be a string"

    if len(val) > 500:
        return False, f"query length ({len(val)}) exceeds maximum limit of 500 characters"

    # Reject comments
    if "--" in val or "/*" in val:
        return False, "SQL comments ('--', '/*') are not allowed"

    stripped = val.strip()
    if not re.match(r"^SELECT\b", stripped, re.IGNORECASE):
        return False, "only SELECT statements are allowed"

    # Semicolon checks: reject multiple statements
    if ";" in stripped:
        parts = stripped.split(";")
        # Check if anything after the first semicolon contains non-whitespace
        if any(part.strip() for part in parts[1:]):
            return False, "multiple SQL statements are not allowed"
        if len(parts) > 2:
            return False, "multiple semicolons not allowed"

    # Reject destructive or modifying SQL keywords anywhere as whole words
    m = FORBIDDEN_SQL_WORDS.search(val)
    if m:
        return False, f"forbidden SQL keyword detected: '{m.group(0).lower()}'"

    return True, ""


RULE_HANDLERS = {
    "path_safe": check_path_safe,
    "url_allowlist": check_url_allowlist,
    "sql_readonly": check_sql_readonly,
}


def check_params(
    tool: str,
    args: dict[str, Any],
    param_rules: dict[str, Any],
    allowed_keys: set[str] | list[str] | None = None,
) -> tuple[bool, str]:
    """
    Evaluates parameter safety rules for a tool call.
    Args:
        tool: Name of the tool being called.
        args: Dictionary of arguments supplied to the tool.
        param_rules: Declarative parameter rules for this tool from registry/policy.
                     Format: { param_name: { "type": rule_type, ... } }
                     or:     { param_name: rule_type_str }
        allowed_keys: Declared property keys from tool schema (if available).
    Returns:
        (ok, reason): True and empty string if valid, False and descriptive error message if blocked.
    """
    if not param_rules:
        return True, ""

    # Strict schema check: any argument key not in the tool's declared schema properties -> reject
    if allowed_keys is not None:
        allowed_set = set(allowed_keys)
        for k in args:
            if k not in allowed_set:
                return False, f"unexpected argument '{k}' for tool '{tool}'"

    # Strict presence check: any guarded parameter that is missing from args -> reject
    for param_name, rule_spec in param_rules.items():
        if param_name not in args:
            return False, f"required argument '{param_name}' missing for tool '{tool}'"

        if isinstance(rule_spec, str):
            rule_type = rule_spec
            rule_opts = {}
        elif isinstance(rule_spec, dict):
            rule_type = rule_spec.get("type", "")
            rule_opts = rule_spec
        else:
            raise ValueError(f"Invalid rule specification for parameter '{param_name}': {rule_spec}")

        validate_rule_type(rule_type)

        param_val = args[param_name]
        handler = RULE_HANDLERS[rule_type]
        ok, reason = handler(param_val, rule_opts)
        if not ok:
            return False, f"Parameter guard rejected argument '{param_name}' for tool '{tool}': {reason}"

    return True, ""
