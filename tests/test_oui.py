"""
Unit tests for OUI lookup and vendor identification.
"""

import pytest
from alpha.oui.database import lookup_vendor, get_oui_database


def test_oui_known_vendors():
    # Apple
    mfg_apple, prefix_apple = lookup_vendor("00:17:F2:12:34:56")
    assert "Apple" in mfg_apple
    assert prefix_apple == "00:17:F2"

    # Espressif
    mfg_esp, prefix_esp = lookup_vendor("18:FE:34:AA:BB:CC")
    assert "Espressif" in mfg_esp

    # Cisco
    mfg_cisco, prefix_cisco = lookup_vendor("00:00:0C:55:66:77")
    assert "Cisco" in mfg_cisco

    # Raspberry Pi
    mfg_rpi, prefix_rpi = lookup_vendor("B8:27:EB:11:22:33")
    assert "Raspberry Pi" in mfg_rpi


def test_oui_randomized_mac():
    mfg_rand, prefix_rand = lookup_vendor("52:54:00:12:34:56")
    # Bit 1 of 52 is 1 (0x52 & 0x02 != 0) -> randomized
    assert "Randomized" in mfg_rand
    assert prefix_rand == "RANDOMIZED"


def test_oui_unknown_vendor():
    mfg_unknown, prefix = lookup_vendor("00:00:01:22:33:44")
    # If not in database and not randomized
    assert mfg_unknown == "UNKNOWN"
    assert prefix == "00:00:01"
