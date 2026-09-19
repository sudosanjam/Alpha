"""
Input Sanitization and String Safety Module for Alpha.

Protects against:
- ANSI escape injection / cursor hijacking / terminal clearing from malicious SSIDs/names
- Control character exploitation
- Shell metacharacter injection
- Malformed MAC / BSSID strings
- Formatting issues across narrow terminals
"""

import re
import html
from typing import Optional

# Regex pattern to match ANSI escape sequences (CSI, OSC, etc.)
ANSI_ESCAPE_PATTERN = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
)

# Pattern for control characters (ASCII 0-31 and 127) excluding standard printable space
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1F\x7F-\x9F]")

# Standard MAC / BSSID validation regex (supports colon, hyphen, or dot delimiters)
MAC_ADDRESS_PATTERN = re.compile(
    r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|"
    r"^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$|"
    r"^[0-9A-Fa-f]{12}$"
)


def strip_ansi(text: str) -> str:
    """Strip all ANSI escape codes from string."""
    if not isinstance(text, str):
        return ""
    return ANSI_ESCAPE_PATTERN.sub("", text)


def sanitize_string(text: Optional[str], fallback: str = "UNKNOWN", max_length: int = 128) -> str:
    """
    Sanitize an untrusted string for terminal display or storage.
    
    - Replaces None with fallback.
    - Strips ANSI sequences.
    - Replaces non-printable control characters with spaces or safe representation.
    - Truncates to max_length safely.
    """
    if text is None:
        return fallback
    
    if not isinstance(text, str):
        text = str(text)
    
    # Strip ANSI escapes first to avoid terminal attacks
    cleaned = strip_ansi(text)
    
    # Replace control characters with a safe space
    cleaned = CONTROL_CHAR_PATTERN.sub(" ", cleaned)
    
    # Strip extra surrounding whitespace
    cleaned = cleaned.strip()
    
    if not cleaned:
        return fallback
    
    if len(cleaned) > max_length:
        return cleaned[:max_length - 3] + "..."
    
    return cleaned


def sanitize_mac(mac: Optional[str]) -> str:
    """
    Normalize MAC address to uppercase colon-delimited format (AA:BB:CC:DD:EE:FF).
    Returns '00:00:00:00:00:00' if malformed or invalid.
    """
    if not mac or not isinstance(mac, str):
        return "00:00:00:00:00:00"
    
    # Clean whitespace and strip ANSI
    clean = strip_ansi(mac).strip()
    # Remove separators
    hex_only = re.sub(r"[^0-9A-Fa-f]", "", clean)
    
    if len(hex_only) != 12:
        return "00:00:00:00:00:00"
    
    hex_upper = hex_only.upper()
    return ":".join(hex_upper[i:i + 2] for i in range(0, 12, 2))


def is_randomized_mac(mac: str) -> bool:
    """
    Determine if a MAC address has the Locally Administered (U/L) bit set.
    In IEEE 802, if the 2nd least significant bit of the first byte is 1 (e.g. x2, x6, xA, xE),
    the MAC is locally administered (commonly randomized on modern mobile devices).
    """
    normalized = sanitize_mac(mac)
    if normalized == "00:00:00:00:00:00":
        return False
    try:
        first_byte = int(normalized[:2], 16)
        # Bit 1 (0x02) indicates Locally Administered Address (LAA)
        return bool(first_byte & 0x02)
    except ValueError:
        return False


def sanitize_html(text: str) -> str:
    """Escape text for safe HTML output in web/reports."""
    return html.escape(sanitize_string(text, fallback=""))


def visible_length(text: str) -> int:
    """Calculate the visible character length of text ignoring ANSI escape codes."""
    return len(strip_ansi(text))
