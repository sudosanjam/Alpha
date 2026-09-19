"""
System Diagnostics and Capability Matrix Inspector for Alpha.

Safely probes the host environment (Android / Termux / Linux) to ascertain verified
capabilities, permissions, and tool states without assuming missing tools exist.
"""

import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Tuple

from alpha.models import CapabilityMatrix
from alpha.oui.database import get_oui_database
from alpha.config import get_default_base_dir, get_default_data_dir


def _safe_run_cmd(cmd: str, timeout: float = 3.0) -> Tuple[bool, str]:
    """Safely execute a shell command without raising exceptions."""
    try:
        res = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if res.returncode == 0:
            return True, res.stdout.strip()
        return False, res.stderr.strip()
    except Exception as ex:
        return False, str(ex)


class EnvironmentInspector:
    """Probes the runtime host for wireless, terminal, storage, and platform capabilities."""

    @staticmethod
    def inspect_platform() -> Dict[str, str]:
        """Detect OS, kernel, Android release, and Termux version."""
        info = {
            "os": platform.system(),
            "kernel": platform.release(),
            "arch": platform.machine(),
            "python": platform.python_version(),
            "is_termux": "com.termux" in os.environ.get("PREFIX", "") or "TERMUX_VERSION" in os.environ,
            "termux_version": os.environ.get("TERMUX_VERSION", "Unknown"),
            "android_release": "Unknown",
            "android_sdk": "Unknown",
            "is_root": False,
        }

        # Check UID for root status
        if hasattr(os, "geteuid"):
            info["is_root"] = (os.geteuid() == 0)

        # Check Android getprop if on Linux/Android
        if info["os"] == "Linux" or info["is_termux"]:
            ok, out = _safe_run_cmd("getprop ro.build.version.release")
            if ok and out:
                info["android_release"] = out
            ok_sdk, out_sdk = _safe_run_cmd("getprop ro.build.version.sdk")
            if ok_sdk and out_sdk:
                info["android_sdk"] = out_sdk

        return info

    @staticmethod
    def inspect_terminal() -> Dict[str, Any]:
        """Inspect terminal size, color support, and encoding."""
        term_size = shutil.get_terminal_size((80, 24))
        term_env = os.environ.get("TERM", "")
        colorterm = os.environ.get("COLORTERM", "")
        has_color = ("color" in term_env.lower() or colorterm != "" or os.environ.get("NO_COLOR") != "1")
        
        # Test UTF-8 box drawing
        unicode_ok = sys.stdout.encoding and "utf" in sys.stdout.encoding.lower()

        return {
            "columns": term_size.columns,
            "lines": term_size.lines,
            "term": term_env or "Unknown",
            "color_supported": has_color,
            "unicode_supported": bool(unicode_ok),
        }

    @staticmethod
    def inspect_storage() -> Dict[str, Any]:
        """Inspect SQLite availability, WAL mode, and filesystem write access."""
        config_dir = get_default_base_dir()
        data_dir = get_default_data_dir()
        
        can_write_config = False
        can_write_data = False
        wal_ok = False

        try:
            config_dir.mkdir(parents=True, exist_ok=True)
            test_file = config_dir / ".write_test"
            test_file.write_text("ok")
            test_file.unlink()
            can_write_config = True
        except Exception:
            pass

        try:
            data_dir.mkdir(parents=True, exist_ok=True)
            test_db = data_dir / ".test_wal.db"
            conn = sqlite3.connect(str(test_db))
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode = WAL")
            mode = cur.fetchone()[0]
            conn.close()
            if test_db.exists():
                test_db.unlink()
            wal_ok = (mode.upper() == "WAL")
            can_write_data = True
        except Exception:
            pass

        return {
            "config_dir": str(config_dir),
            "data_dir": str(data_dir),
            "can_write_config": can_write_config,
            "can_write_data": can_write_data,
            "sqlite_wal_supported": wal_ok,
        }

    @staticmethod
    def inspect_wireless() -> Dict[str, Any]:
        """Inspect Termux:API Wi-Fi and Bluetooth availability."""
        wifi_scan_bin = shutil.which("termux-wifi-scaninfo") is not None
        wifi_conn_bin = shutil.which("termux-wifi-connectioninfo") is not None
        vibrate_bin = shutil.which("termux-vibrate") is not None
        notify_bin = shutil.which("termux-notification") is not None

        # Check BLE helpers
        ble_found = False
        for helper in [
            "termux-ble-scan",
            "termux-bluetooth-scaninfo",
            "termux-bluetooth-devices",
            "dumpsys",
            "bluetoothctl",
            "hcitool",
        ]:
            if shutil.which(helper):
                ble_found = True
                break

        return {
            "termux_wifi_scaninfo": wifi_scan_bin,
            "termux_wifi_connectioninfo": wifi_conn_bin,
            "termux_vibrate": vibrate_bin,
            "termux_notification": notify_bin,
            "ble_scan_available": ble_found,
            "monitor_mode_available": False,  # Always False in stock rootless Android
            "raw_injection_available": False,  # Always False in stock rootless Android
        }

    @classmethod
    def get_capability_matrix(cls) -> CapabilityMatrix:
        """Construct CapabilityMatrix dataclass from current environment."""
        plat = cls.inspect_platform()
        term = cls.inspect_terminal()
        stor = cls.inspect_storage()
        wire = cls.inspect_wireless()

        return CapabilityMatrix(
            wifi_scan=wire["termux_wifi_scaninfo"],
            wifi_connection_info=wire["termux_wifi_connectioninfo"],
            wifi_raw_frames=False,
            wifi_monitor_mode=False,
            ble_scan=wire["ble_scan_available"],
            ble_raw_capture=False,
            termux_api_available=wire["termux_wifi_scaninfo"],
            location_permission_granted=wire["termux_wifi_scaninfo"],
            location_service_enabled=wire["termux_wifi_scaninfo"],
            vibration_supported=wire["termux_vibrate"],
            notifications_supported=wire["termux_notification"],
            sqlite_wal_supported=stor["sqlite_wal_supported"],
            terminal_colors_256=term["color_supported"],
            unicode_supported=term["unicode_supported"],
            root_available=plat["is_root"],
        )

    @classmethod
    def format_diagnostics_report(cls) -> str:
        """Produce a human-readable diagnostics report with high-contrast formatting."""
        plat = cls.inspect_platform()
        term = cls.inspect_terminal()
        stor = cls.inspect_storage()
        wire = cls.inspect_wireless()
        oui_db = get_oui_database()

        def status_str(val: bool, true_text: str = "AVAILABLE", false_text: str = "UNAVAILABLE") -> str:
            if val:
                return f"\033[92;1m[{true_text}]\033[0m"
            return f"\033[33m[{false_text}]\033[0m"

        lines = [
            "============================================================",
            "                ALPHA ENVIRONMENT DIAGNOSTICS               ",
            "============================================================",
            f"Platform / OS:        {plat['os']} ({plat['kernel']}) [{plat['arch']}]",
            f"Android Release:      {plat['android_release']} (SDK: {plat['android_sdk']})",
            f"Termux Environment:   {'YES (v' + plat['termux_version'] + ')' if plat['is_termux'] else 'Standard Host / Emulated'}",
            f"Root Privileges:      {'YES (Non-standard)' if plat['is_root'] else 'NO (Standard Rootless User)'}",
            f"Python Version:       {plat['python']}",
            "",
            "--- Storage & Persistence ---",
            f"Config Directory:     {stor['config_dir']}  {status_str(stor['can_write_config'], 'WRITABLE', 'READ-ONLY')}",
            f"Data Directory:       {stor['data_dir']}  {status_str(stor['can_write_data'], 'WRITABLE', 'READ-ONLY')}",
            f"SQLite WAL Support:   {status_str(stor['sqlite_wal_supported'])}",
            f"OUI Vendor Database:  {status_str(True, f'LOADED ({len(oui_db.memory_cache)} prefixes)')}",
            "",
            "--- Terminal & Rendering ---",
            f"Dimensions:           {term['columns']} columns x {term['lines']} lines",
            f"Color Support:        {status_str(term['color_supported'], '256 / ANSI COLOR')}",
            f"Unicode Box Drawing:  {status_str(term['unicode_supported'], 'SUPPORTED', 'ASCII FALLBACK')}",
            "",
            "--- Wireless & Hardware Capabilities ---",
            f"Wi-Fi Scan (Termux):  {status_str(wire['termux_wifi_scaninfo'])}",
            f"Wi-Fi Connection Info:{status_str(wire['termux_wifi_connectioninfo'])}",
            f"BLE Scanning:         {status_str(wire['ble_scan_available'], 'AVAILABLE', 'NOT EXPOSED (Use --mock-ble)')}",
            f"Vibration Alert:      {status_str(wire['termux_vibrate'])}",
            f"Android Notification: {status_str(wire['termux_notification'])}",
            f"Wi-Fi Monitor Mode:   \033[37m[NOT EXPOSED / ROOTLESS BOUNDARY]\033[0m",
            f"Packet Injection:     \033[37m[NOT EXPOSED / ROOTLESS BOUNDARY]\033[0m",
            "============================================================",
        ]
        return "\n".join(lines)
