"""
Phase 5 — Text Normalizer and Multi-View Extraction
"""

import base64
import re
import unicodedata


def normalize_text(text: str) -> str:
    """
    Applies unicode NFKC normalization, replaces curly quotes with straight quotes,
    removes zero-width characters, lowercases, and collapses whitespace.
    """
    # NFKC normalization
    normalized = unicodedata.normalize("NFKC", text)

    # Replace curly quotes with straight quotes
    normalized = (
        normalized.replace("’", "'")
        .replace("‘", "'")
        .replace("“", '"')
        .replace("”", '"')
    )

    # Remove zero-width chars (U+200B-U+200F, U+2060, U+FEFF)
    normalized = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", normalized)

    # Lowercase
    normalized = normalized.lower()

    # Collapse whitespace
    normalized = re.sub(r"\s+", " ", normalized).strip()

    return normalized


def get_text_views(text: str) -> list[tuple[str, str]]:
    """
    Returns a list of (view_name, text) pairs:
      - ("raw", original)
      - ("normalized", normalized_text)
      - ("base64_decoded", normalized_decoded_text) for up to 5 valid base64 tokens
    """
    views = [("raw", text)]

    normalized = normalize_text(text)
    views.append(("normalized", normalized))

    # Base64 decoded view for up to 5 tokens matching [A-Za-z0-9+/]{16,}={0,2}
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
    matches = b64_pattern.findall(text)[:5]

    for token in matches:
        try:
            missing_padding = len(token) % 4
            padded_token = token + "=" * (4 - missing_padding) if missing_padding else token
            decoded_bytes = base64.b64decode(padded_token, validate=True)
            decoded_str = decoded_bytes.decode("utf-8")

            # Keep only if valid printable UTF-8 string
            if decoded_str and all(c.isprintable() or c in "\n\r\t" for c in decoded_str):
                norm_decoded = normalize_text(decoded_str)
                if norm_decoded:
                    views.append(("base64_decoded", norm_decoded))
        except Exception:
            continue

    return views
