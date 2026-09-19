"""
Unit tests for input sanitization and anti-injection defenses.
"""

import pytest
from alpha.sanitizer import (
    strip_ansi,
    sanitize_string,
    sanitize_mac,
    is_randomized_mac,
    sanitize_html,
    visible_length,
)


def test_strip_ansi():
    raw = "\033[31;1mRed Alert\033[0m \033[2J\033[HCleared"
    cleaned = strip_ansi(raw)
    assert cleaned == "Red Alert Cleared"
    assert "\033" not in cleaned


def test_sanitize_string_control_characters():
    malicious = "Network\x00Name\x07\x08\x0cWith\tControl"
    cleaned = sanitize_string(malicious)
    assert "\x00" not in cleaned
    assert "\x07" not in cleaned
    assert "Network" in cleaned
    assert "With" in cleaned


def test_sanitize_string_truncation():
    long_ssid = "A" * 200
    cleaned = sanitize_string(long_ssid, max_length=32)
    assert len(cleaned) <= 32
    assert cleaned.endswith("...")


def test_sanitize_mac():
    assert sanitize_mac("001122334455") == "00:11:22:33:44:55"
    assert sanitize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
    assert sanitize_mac("11-22-33-44-55-66") == "11:22:33:44:55:66"
    assert sanitize_mac("1122.3344.5566") == "11:22:33:44:55:66"
    assert sanitize_mac("invalid_mac") == "00:00:00:00:00:00"


def test_is_randomized_mac():
    # Bit 1 set (locally administered)
    assert is_randomized_mac("02:00:00:00:00:00") is True
    assert is_randomized_mac("DA:A1:19:88:77:66") is True
    assert is_randomized_mac("7E:11:22:33:44:55") is True

    # Bit 1 clear (globally unique / assigned OUI)
    assert is_randomized_mac("00:17:F2:11:22:33") is False
    assert is_randomized_mac("B8:27:EB:55:66:77") is False


def test_visible_length():
    colored = "\033[1;36mHello World\033[0m"
    assert visible_length(colored) == 11
