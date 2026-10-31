from pathlib import Path
import pytest
from agent.tools import read_note


@pytest.fixture
def notes_dir():
    d = Path(__file__).resolve().parent.parent / "demo" / "notes"
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_read_note_caps_at_64kb(notes_dir):
    """VULN-10: read_note must cap content at 64KB (65,536 bytes)."""
    test_file = notes_dir / "test_large_64kb.txt"
    try:
        # Write 100KB of content
        with open(test_file, "wb") as f:
            f.write(b"A" * 100_000)

        content = read_note("test_large_64kb")
        assert len(content.encode("utf-8")) == 64 * 1024, f"Expected 65536 bytes, got {len(content.encode('utf-8'))}"
    finally:
        if test_file.exists():
            test_file.unlink()


def test_read_note_binary_safe_invalid_utf8(notes_dir):
    """VULN-10: read_note must use errors='replace' to safely handle invalid/binary bytes without crashing."""
    test_file = notes_dir / "test_binary_bytes.txt"
    try:
        # Write bytes with invalid UTF-8 sequences (0xFF, 0xFE, 0x80)
        with open(test_file, "wb") as f:
            f.write(b"Valid prefix \xff\xfe non-utf8 \x80\x81 data")

        content = read_note("test_binary_bytes")
        assert "Valid prefix" in content
        assert "\ufffd" in content  # Replaced characters
    finally:
        if test_file.exists():
            test_file.unlink()

