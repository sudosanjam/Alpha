"""
Termux-Native Wi-Fi Acquisition Backend.

Interfaces directly with 'termux-wifi-scaninfo' to obtain genuine Wi-Fi scan results
exposed by Android. Handles result freshness, throttling detection, channel/band derivation,
and conservative capability parsing.
"""

import json
import shutil
import subprocess
import time
from typing import Dict, List, Optional, Tuple, Any

from alpha.acquisition.base import AcquisitionBackend, BackendStatus, ScanBatch
from alpha.models import (
    Observation,
    ScanMetadata,
    SignalType,
    DataProvenance,
    FreshnessState,
)
from alpha.sanitizer import sanitize_mac, sanitize_string
from alpha.logger import get_logger

logger = get_logger("acquisition.wifi")


def frequency_to_channel_and_band(freq: Optional[int]) -> Tuple[Optional[int], Optional[str]]:
    """Derive standard Wi-Fi channel and frequency band from carrier frequency in MHz."""
    if freq is None or freq <= 0:
        return None, None
    
    # 2.4 GHz Band (Channels 1 - 14)
    if 2412 <= freq <= 2472:
        channel = (freq - 2412) // 5 + 1
        return channel, "2.4 GHz"
    elif freq == 2484:
        return 14, "2.4 GHz"
    
    # 5 GHz Band (Channels 32 - 177)
    elif 5170 <= freq <= 5835:
        channel = (freq - 5000) // 5
        return channel, "5 GHz"
    
    # 6 GHz Band (Wi-Fi 6E / Wi-Fi 7) (Channels 1 - 233)
    elif 5955 <= freq <= 7115:
        channel = (freq - 5950) // 5
        return channel, "6 GHz"
    
    # 60 GHz (WiGig / 802.11ad/ay)
    elif 58320 <= freq <= 70200:
        channel = (freq - 58320) // 2160 + 1
        return channel, "60 GHz"
    
    return None, "Unknown Band"


def parse_security_capabilities(cap: Optional[str]) -> str:
    """
    Parse raw Wi-Fi capability string (e.g. '[WPA2-PSK-CCMP][RSN-PSK-CCMP][ESS]')
    into a standardized security classification.
    """
    if not cap or not isinstance(cap, str):
        return "OPEN"
    
    upper = cap.upper()
    
    has_wpa3 = "SAE" in upper or "WPA3" in upper or "OWE" in upper
    has_wpa2 = "WPA2" in upper or "RSN" in upper
    has_wpa = "WPA-" in upper or "WPA]" in upper or "[WPA" in upper
    has_wep = "WEP" in upper
    has_enterprise = "EAP" in upper or "802.1X" in upper
    
    if has_wpa3 and has_wpa2:
        sec = "WPA2/WPA3"
    elif has_wpa3:
        sec = "WPA3"
    elif has_wpa2 and has_wpa:
        sec = "WPA/WPA2"
    elif has_wpa2:
        sec = "WPA2"
    elif has_wpa:
        sec = "WPA"
    elif has_wep:
        sec = "WEP"
    elif "ESS" in upper or upper == "":
        sec = "OPEN"
    else:
        sec = "OTHER"
        
    if has_enterprise:
        sec += " (Enterprise)"
        
    if "WPS" in upper:
        sec += " [WPS]"
        
    return sec


class TermuxWifiBackend(AcquisitionBackend):
    """Acquisition backend leveraging Termux:API's 'termux-wifi-scaninfo'."""

    def __init__(self, command_timeout: float = 8.0):
        self.command_name = "termux-wifi-scaninfo"
        self.command_timeout = command_timeout
        self.last_scan_timestamp: Optional[float] = None
        self.last_scan_result_count: int = 0
        self.consecutive_identical_scans: int = 0

    def get_name(self) -> str:
        return "Termux Wi-Fi (termux-wifi-scaninfo)"

    def check_availability(self) -> BackendStatus:
        """Inspect whether termux-wifi-scaninfo is present and executable."""
        cmd_path = shutil.which(self.command_name)
        if not cmd_path:
            return BackendStatus(
                available=False,
                name=self.get_name(),
                status_text="UNAVAILABLE",
                error_details=f"Executable '{self.command_name}' not found in PATH.",
                requires_action=True,
                action_hint="Install Termux:API package in Termux ('pkg install termux-api') and install Termux:API APK from F-Droid."
            )
        
        # Test executing the command with a short timeout
        try:
            res = subprocess.run(
                [cmd_path],
                capture_output=True,
                text=True,
                timeout=self.command_timeout
            )
            if res.returncode != 0:
                stderr = res.stderr.strip() or "Unknown error"
                if "location" in stderr.lower() or "permission" in stderr.lower():
                    return BackendStatus(
                        available=False,
                        name=self.get_name(),
                        status_text="REQUIRES ACTION",
                        error_details=stderr,
                        requires_action=True,
                        action_hint="Grant Location permission to Termux:API app and enable Android Location Services toggle."
                    )
                return BackendStatus(
                    available=False,
                    name=self.get_name(),
                    status_text="UNAVAILABLE",
                    error_details=f"Command returned code {res.returncode}: {stderr}",
                    requires_action=False
                )
            
            # Verify valid JSON output
            data = json.loads(res.stdout)
            if not isinstance(data, list):
                return BackendStatus(
                    available=False,
                    name=self.get_name(),
                    status_text="UNEXPECTED OUTPUT",
                    error_details="Output was not a JSON array.",
                    requires_action=False
                )
                
            return BackendStatus(
                available=True,
                name=self.get_name(),
                status_text="AVAILABLE",
                error_details=None,
                requires_action=False
            )
        except subprocess.TimeoutExpired:
            return BackendStatus(
                available=False,
                name=self.get_name(),
                status_text="TIMEOUT",
                error_details="Command timed out while waiting for Wi-Fi scan results.",
                requires_action=True,
                action_hint="Check if Wi-Fi and Location are turned on in Android settings."
            )
        except Exception as ex:
            return BackendStatus(
                available=False,
                name=self.get_name(),
                status_text="ERROR",
                error_details=str(ex),
                requires_action=False
            )

    def scan(self, session_id: str = "default") -> ScanBatch:
        """Execute termux-wifi-scaninfo and produce normalized observations."""
        req_time = time.time()
        meta = ScanMetadata(
            requested_at=req_time,
            source=self.get_name(),
        )
        
        cmd_path = shutil.which(self.command_name)
        if not cmd_path:
            meta.completed_at = time.time()
            meta.duration_ms = (meta.completed_at - req_time) * 1000
            meta.success = False
            meta.error_message = f"'{self.command_name}' not found in PATH."
            meta.freshness = FreshnessState.UNAVAILABLE
            return ScanBatch(observations=[], metadata=meta)

        try:
            start_proc = time.time()
            proc = subprocess.run(
                [cmd_path],
                capture_output=True,
                text=True,
                timeout=self.command_timeout
            )
            meta.completed_at = time.time()
            meta.duration_ms = (meta.completed_at - start_proc) * 1000
            
            if proc.returncode != 0:
                meta.success = False
                meta.error_message = proc.stderr.strip() or f"Exit code {proc.returncode}"
                meta.freshness = FreshnessState.UNAVAILABLE
                return ScanBatch(observations=[], metadata=meta)
            
            raw_text = proc.stdout.strip()
            if not raw_text:
                raw_items = []
            else:
                raw_items = json.loads(raw_text)
                
            if not isinstance(raw_items, list):
                meta.success = False
                meta.error_message = "Output is not a valid JSON list."
                meta.freshness = FreshnessState.UNAVAILABLE
                return ScanBatch(observations=[], metadata=meta)
                
            observations: List[Observation] = []
            max_item_ts: Optional[float] = None
            
            for item in raw_items:
                if not isinstance(item, dict):
                    continue
                
                bssid_raw = item.get("bssid", "")
                mac = sanitize_mac(bssid_raw)
                ssid_raw = item.get("ssid", "")
                ssid = sanitize_string(ssid_raw, fallback="")
                if not ssid:
                    ssid = "[Hidden SSID]"
                    
                rssi = int(item.get("rssi", -99))
                freq = item.get("frequency")
                if freq is not None:
                    try:
                        freq = int(freq)
                    except (ValueError, TypeError):
                        freq = None
                
                channel, band = frequency_to_channel_and_band(freq)
                # If channel is explicitly provided in raw item, use it if valid
                if item.get("channel") is not None:
                    try:
                        channel = int(item["channel"])
                    except (ValueError, TypeError):
                        pass
                
                caps = sanitize_string(item.get("capabilities", ""), fallback="")
                security = parse_security_capabilities(caps)
                
                # Timestamp handling
                item_ts_raw = item.get("timestamp")
                item_ts = meta.completed_at
                if item_ts_raw is not None:
                    try:
                        # Android timestamps in scaninfo can be microseconds since boot or unix epoch
                        val = float(item_ts_raw)
                        if val > 1_000_000_000_000:  # ms
                            item_ts = val / 1000.0
                        elif val > 1_000_000_000:  # s
                            item_ts = val
                        if max_item_ts is None or item_ts > max_item_ts:
                            max_item_ts = item_ts
                    except (ValueError, TypeError):
                        pass
                
                obs = Observation(
                    session_id=session_id,
                    timestamp=meta.completed_at,
                    source=self.get_name(),
                    signal_type=SignalType.WIFI,
                    interface="wlan0",
                    identifier=mac,
                    mac_address=mac,
                    bssid=mac,
                    ssid=ssid,
                    rssi=rssi,
                    frequency=freq,
                    channel=channel,
                    band=band,
                    security=security,
                    capabilities=caps,
                    raw_metadata=item,
                    provenance=DataProvenance.OBSERVED
                )
                observations.append(obs)
                
            meta.item_count = len(observations)
            meta.result_timestamp = max_item_ts or meta.completed_at
            
            # Detect Freshness & Throttling
            if self.last_scan_timestamp is not None and max_item_ts is not None:
                if max_item_ts == self.last_scan_timestamp:
                    self.consecutive_identical_scans += 1
                    meta.is_cached = True
                    if self.consecutive_identical_scans >= 3:
                        meta.freshness = FreshnessState.THROTTLED
                    else:
                        meta.freshness = FreshnessState.CACHED
                else:
                    self.consecutive_identical_scans = 0
                    meta.freshness = FreshnessState.LIVE
            else:
                meta.freshness = FreshnessState.LIVE
                
            self.last_scan_timestamp = max_item_ts
            self.last_scan_result_count = len(observations)
            meta.age_seconds = max(0.0, meta.completed_at - (meta.result_timestamp or meta.completed_at))
            
            return ScanBatch(observations=observations, metadata=meta)
            
        except subprocess.TimeoutExpired:
            meta.completed_at = time.time()
            meta.duration_ms = (meta.completed_at - req_time) * 1000
            meta.success = False
            meta.error_message = f"Command '{self.command_name}' timed out after {self.command_timeout}s."
            meta.freshness = FreshnessState.STALE
            return ScanBatch(observations=[], metadata=meta)
        except Exception as ex:
            meta.completed_at = time.time()
            meta.duration_ms = (meta.completed_at - req_time) * 1000
            meta.success = False
            meta.error_message = str(ex)
            meta.freshness = FreshnessState.UNAVAILABLE
            return ScanBatch(observations=[], metadata=meta)
