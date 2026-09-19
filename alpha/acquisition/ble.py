"""
Termux BLE & Bluetooth Acquisition Subsystem.

Provides multi-backend Bluetooth/BLE acquisition supporting:
1. 'termux-bluetooth-scaninfo' / 'termux-bluetooth-devices' / 'termux-ble-scan' (Termux:API)
2. 'dumpsys bluetooth_manager' (Android system service dump for bonded/connected devices)
3. 'bluetoothctl' / 'hcitool' (Linux BlueZ subsystem)
4. 'bleak' Python library (if available)
5. Hybrid BLE fallback simulation mode (for rootless Android environments where the
   kernel blocks raw BlueZ sockets from userland).
"""

import json
import math
import random
import re
import shutil
import subprocess
import time
from typing import List, Optional, Dict, Any, Tuple

from alpha.acquisition.base import AcquisitionBackend, BackendStatus, ScanBatch
from alpha.models import ScanMetadata, FreshnessState, Observation, SignalType, DataProvenance
from alpha.sanitizer import sanitize_mac, sanitize_string
from alpha.logger import get_logger

logger = get_logger("acquisition.ble")


class TermuxBleBackend(AcquisitionBackend):
    """Bluetooth & BLE Acquisition Backend supporting Termux:API, system dumpsys, tools, and hybrid fallback."""

    def __init__(self, command_timeout: float = 6.0, enable_hybrid_fallback: bool = False):
        self.command_timeout = command_timeout
        self.enable_hybrid_fallback = enable_hybrid_fallback
        self.detected_helper: Optional[str] = None
        self._find_usable_helper()

    def _find_usable_helper(self) -> Optional[str]:
        """Find the best available Bluetooth / BLE scanning utility."""
        candidates = [
            "termux-ble-scan",
            "termux-bluetooth-scaninfo",
            "termux-bluetooth-devices",
            "bluetoothctl",
            "hcitool",
            "dumpsys",
        ]
        for cmd in candidates:
            if shutil.which(cmd):
                self.detected_helper = cmd
                return cmd
        self.detected_helper = None
        return None

    def get_name(self) -> str:
        if self.detected_helper:
            return f"Bluetooth/BLE ({self.detected_helper})"
        if self.enable_hybrid_fallback:
            return "Bluetooth/BLE (Hybrid Fallback)"
        return "Termux Bluetooth/BLE Probe"

    def check_availability(self) -> BackendStatus:
        """Inspect if any legitimate BLE scanning mechanism is accessible."""
        helper = self._find_usable_helper()
        if helper:
            return BackendStatus(
                available=True,
                name=self.get_name(),
                status_text="AVAILABLE",
                error_details=None,
                requires_action=False
            )
        
        if self.enable_hybrid_fallback:
            return BackendStatus(
                available=True,
                name=self.get_name(),
                status_text="HYBRID FALLBACK",
                error_details=None,
                requires_action=False
            )

        return BackendStatus(
            available=False,
            name=self.get_name(),
            status_text="REQUIRES ACTION",
            error_details="No standard Bluetooth scanner CLI utility found (termux-bluetooth-devices / dumpsys).",
            requires_action=True,
            action_hint="Ensure Bluetooth is enabled in Android settings. On rootless Android, run with '--mock-ble' for hybrid device testing."
        )

    def _scan_termux_api(self, cmd_path: str, session_id: str) -> List[Observation]:
        """Execute Termux:API Bluetooth commands and parse results."""
        proc = subprocess.run(
            [cmd_path],
            capture_output=True,
            text=True,
            timeout=self.command_timeout
        )
        if proc.returncode != 0:
            return []
        
        raw_text = proc.stdout.strip()
        if not raw_text:
            return []
        
        data = json.loads(raw_text)
        if isinstance(data, dict):
            # Some builds return {"devices": [...]}
            data = data.get("devices", [data])
        if not isinstance(data, list):
            return []

        observations = []
        now = time.time()
        for item in data:
            if not isinstance(item, dict):
                continue
            addr_raw = item.get("address") or item.get("mac") or item.get("bssid") or ""
            mac = sanitize_mac(addr_raw)
            if mac == "00:00:00:00:00:00":
                continue
            name_raw = item.get("name") or item.get("device_name") or ""
            name = sanitize_string(name_raw, fallback="") or None
            rssi = int(item.get("rssi", -75))

            obs = Observation(
                session_id=session_id,
                timestamp=now,
                source=self.get_name(),
                signal_type=SignalType.BLE,
                interface="hci0",
                identifier=mac,
                mac_address=mac,
                device_name=name,
                rssi=rssi,
                raw_metadata=item,
                provenance=DataProvenance.OBSERVED
            )
            observations.append(obs)

        return observations

    def _scan_dumpsys(self, session_id: str) -> List[Observation]:
        """Query Android dumpsys bluetooth_manager for bonded and connected devices."""
        cmd_path = shutil.which("dumpsys")
        if not cmd_path:
            return []
        try:
            proc = subprocess.run(
                [cmd_path, "bluetooth_manager"],
                capture_output=True,
                text=True,
                timeout=self.command_timeout
            )
            if proc.returncode != 0 or not proc.stdout:
                return []
            
            return self._parse_dumpsys_output(proc.stdout, session_id)
        except Exception:
            return []

    def _parse_dumpsys_output(self, raw_output: str, session_id: str) -> List[Observation]:
        """Parse raw dumpsys bluetooth_manager text output."""
        observations = []
        now = time.time()
        seen_macs = set()

        # Regular expressions for bonded/connected device lines in dumpsys
        mac_pattern = re.compile(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})')

        for line in raw_output.splitlines():
            line_str = line.strip()
            if not line_str:
                continue

            match = mac_pattern.search(line_str)
            if match:
                mac = sanitize_mac(match.group(1))
                if mac == "00:00:00:00:00:00" or mac in seen_macs:
                    continue
                
                seen_macs.add(mac)
                
                # Extract device name if present
                name = None
                name_match = re.search(r'\(([^)]+)\)', line_str)
                if name_match:
                    name = sanitize_string(name_match.group(1), fallback="")
                elif "name:" in line_str.lower():
                    parts = line_str.split("name:", 1)
                    if len(parts) > 1:
                        name = sanitize_string(parts[1].split(",")[0].strip(), fallback="")

                obs = Observation(
                    session_id=session_id,
                    timestamp=now,
                    source="dumpsys bluetooth_manager",
                    signal_type=SignalType.BLE,
                    interface="hci0",
                    identifier=mac,
                    mac_address=mac,
                    device_name=name or None,
                    rssi=-68,
                    provenance=DataProvenance.OBSERVED
                )
                observations.append(obs)

        return observations

    def _scan_bluetoothctl(self, session_id: str) -> List[Observation]:
        """Query paired/discovered devices via bluetoothctl."""
        cmd_path = shutil.which("bluetoothctl")
        if not cmd_path:
            return []
        try:
            proc = subprocess.run(
                [cmd_path, "devices"],
                capture_output=True,
                text=True,
                timeout=self.command_timeout
            )
            if proc.returncode != 0:
                return []
            
            observations = []
            now = time.time()
            for line in proc.stdout.splitlines():
                parts = line.strip().split(maxsplit=2)
                if len(parts) >= 2 and parts[0].lower() == "device":
                    mac = sanitize_mac(parts[1])
                    name = parts[2] if len(parts) > 2 else None
                    obs = Observation(
                        session_id=session_id,
                        timestamp=now,
                        source="bluetoothctl",
                        signal_type=SignalType.BLE,
                        interface="hci0",
                        identifier=mac,
                        mac_address=mac,
                        device_name=name,
                        rssi=-70,
                        provenance=DataProvenance.OBSERVED
                    )
                    observations.append(obs)
            return observations
        except Exception:
            return []

    def _generate_hybrid_ble(self, session_id: str) -> List[Observation]:
        """Generate realistic dynamic BLE device observations for rootless testing."""
        now = time.time()
        jitter1 = int(math.sin(now / 5.0) * 4)
        jitter2 = int(math.cos(now / 7.0) * 5)
        jitter3 = int(math.sin(now / 3.0) * 3)

        devices = [
            ("5A:B4:01:FE:39:2A", "Apple Watch Ultra (BLE)", -65 + jitter1, True),
            ("F4:34:F0:88:99:AA", "AirPods Pro (Audio)", -58 + jitter2, True),
            ("E0:4F:43:11:22:33", "Tile Mate Tracker", -82 + jitter3, False),
            ("40:4E:36:55:66:77", "Samsung Galaxy Watch", -72 + jitter1, False),
            ("DC:A6:32:44:55:66", "Nordic BLE Sensor", -78 + jitter2, False),
        ]

        observations = []
        for mac_raw, name, rssi, is_random in devices:
            mac = sanitize_mac(mac_raw)
            obs = Observation(
                session_id=session_id,
                timestamp=now,
                source="BLE (Hybrid Fallback)",
                signal_type=SignalType.BLE,
                interface="hci0",
                identifier=mac,
                mac_address=mac,
                device_name=name,
                rssi=rssi,
                raw_metadata={"hybrid_fallback": True, "is_randomized": is_random},
                provenance=DataProvenance.DERIVED
            )
            observations.append(obs)

        return observations

    def scan(self, session_id: str = "default") -> ScanBatch:
        """Execute multi-backend Bluetooth discovery scan."""
        req_time = time.time()
        helper = self._find_usable_helper()
        
        observations: List[Observation] = []
        error_msg = None
        success = True

        # 1. Try Termux:API Bluetooth commands
        if helper in ("termux-bluetooth-scaninfo", "termux-bluetooth-devices", "termux-ble-scan"):
            try:
                observations = self._scan_termux_api(shutil.which(helper), session_id)
            except Exception as ex:
                logger.debug(f"Termux API scan failed: {ex}")

        # 2. Try dumpsys bluetooth_manager
        if not observations:
            try:
                obs_dump = self._scan_dumpsys(session_id)
                if obs_dump:
                    observations = obs_dump
            except Exception as ex:
                logger.debug(f"dumpsys scan failed: {ex}")

        # 3. Try bluetoothctl
        if not observations and helper == "bluetoothctl":
            try:
                observations = self._scan_bluetoothctl(session_id)
            except Exception as ex:
                logger.debug(f"bluetoothctl scan failed: {ex}")

        # 4. Try Python bleak if available
        if not observations:
            try:
                from bleak import BleakScanner
                import asyncio
                
                async def _run_bleak():
                    devices = await BleakScanner.discover(timeout=1.5)
                    return devices
                    
                devices = asyncio.run(_run_bleak())
                now = time.time()
                for d in devices:
                    mac = sanitize_mac(d.address)
                    obs = Observation(
                        session_id=session_id,
                        timestamp=now,
                        source="bleak",
                        signal_type=SignalType.BLE,
                        interface="hci0",
                        identifier=mac,
                        mac_address=mac,
                        device_name=d.name or None,
                        rssi=d.rssi or -75,
                        provenance=DataProvenance.OBSERVED
                    )
                    observations.append(obs)
            except Exception:
                pass

        # 5. Hybrid Fallback (if enabled and 0 hardware observations found)
        if not observations and self.enable_hybrid_fallback:
            observations = self._generate_hybrid_ble(session_id)

        if not observations and not self.enable_hybrid_fallback:
            error_msg = "No BLE devices discovered (Android userland socket restriction)."
            success = False

        completed_time = time.time()
        meta = ScanMetadata(
            requested_at=req_time,
            completed_at=completed_time,
            duration_ms=(completed_time - req_time) * 1000,
            source=self.get_name(),
            item_count=len(observations),
            success=success or bool(observations),
            freshness=FreshnessState.LIVE if observations else FreshnessState.UNAVAILABLE,
            error_message=error_msg
        )

        return ScanBatch(observations=observations, metadata=meta)
