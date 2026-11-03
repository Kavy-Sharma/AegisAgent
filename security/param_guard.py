"""
security/param_guard.py - Parameter Safety Guard

WHAT THIS FILE DOES:
Inspects tool arguments against declarative parameter safety rules defined in the active policy:
1. path_safe: prevents directory traversal ('..'), absolute paths, drive letters, backslashes,
   null bytes, and length overflows.
2. url_allowlist: restricts URLs to https scheme, standard port 443, non-IP hosts, no embedded
   credentials, and domain/subdomain allowlists.
3. sql_readonly: keyword guard, not a SQL parser. Enforces single SELECT statements, blocks SQL
   comments, and rejects destructive keywords (drop, delete, update, etc.).

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
    r"\b(drop|delete|update|insert|alter|create|truncate|attach|pragma|replace|grant)\b",
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
    - Reject IP-literal hosts (IPv4, IPv6)
    - Reject localhost
    - Reject user credentials ('user:pass@')
    - Reject ports other than 443
    - Host must match allowed_hosts (exact match or subdomain)
    """
    if not isinstance(val, str):
        return False, "url parameter must be a string"

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


def check_params(tool: str, args: dict[str, Any], param_rules: dict[str, Any]) -> tuple[bool, str]:
    """
    Evaluates parameter safety rules for a tool call.
    Args:
        tool: Name of the tool being called.
        args: Dictionary of arguments supplied to the tool.
        param_rules: Declarative parameter rules for this tool from registry/policy.
                     Format: { param_name: { "type": rule_type, ... } }
                     or:     { param_name: rule_type_str }
    Returns:
        (ok, reason): True and empty string if valid, False and descriptive error message if blocked.
    """
    if not param_rules:
        return True, ""

    for param_name, rule_spec in param_rules.items():
        if isinstance(rule_spec, str):
            rule_type = rule_spec
            rule_opts = {}
        elif isinstance(rule_spec, dict):
            rule_type = rule_spec.get("type", "")
            rule_opts = rule_spec
        else:
            raise ValueError(f"Invalid rule specification for parameter '{param_name}': {rule_spec}")

        validate_rule_type(rule_type)

        # Check if argument is present
        if param_name in args:
            param_val = args[param_name]
            handler = RULE_HANDLERS[rule_type]
            ok, reason = handler(param_val, rule_opts)
            if not ok:
                return False, f"Parameter guard rejected argument '{param_name}' for tool '{tool}': {reason}"

    return True, ""

