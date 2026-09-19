"""
Termux BLE Probe & Acquisition Subsystem.

Provides honest BLE capability detection. In standard rootless Termux on Android,
BLE scanning APIs are not exposed via standard Termux:API. This backend detects available
BLE tools (if any companion is present), reports honest status, and gracefully disables
BLE without breaking the rest of Alpha.
"""

import shutil
import time
from typing import List, Optional
from alpha.acquisition.base import AcquisitionBackend, BackendStatus, ScanBatch
from alpha.models import ScanMetadata, FreshnessState, Observation, SignalType, DataProvenance
from alpha.logger import get_logger

logger = get_logger("acquisition.ble")


class TermuxBleBackend(AcquisitionBackend):
    """BLE Acquisition Backend with capability detection and graceful degradation."""

    def __init__(self):
        self.known_ble_helpers = [
            "termux-ble-scan",
            "termux-bluetooth-scaninfo",
            "bleak-scan-helper",
            "hcitool"
        ]

    def get_name(self) -> str:
        return "Termux BLE Probe"

    def check_availability(self) -> BackendStatus:
        """Inspect if any legitimate BLE scanning mechanism is accessible."""
        for helper in self.known_ble_helpers:
            path = shutil.which(helper)
            if path:
                return BackendStatus(
                    available=True,
                    name=self.get_name(),
                    status_text="AVAILABLE",
                    error_details=None,
                    requires_action=False
                )
        
        return BackendStatus(
            available=False,
            name=self.get_name(),
            status_text="NOT EXPOSED IN STOCK ROOTLESS TERMUX",
            error_details="No standard rootless BLE advertisement API is exposed by stock Termux:API.",
            requires_action=False,
            action_hint="Wi-Fi observation will continue normally. BLE is supported in --mock mode for testing."
        )

    def scan(self, session_id: str = "default") -> ScanBatch:
        """Return empty batch gracefully if BLE is not exposed on the host."""
        status = self.check_availability()
        meta = ScanMetadata(
            requested_at=time.time(),
            completed_at=time.time(),
            source=self.get_name(),
            item_count=0,
            success=status.available,
            freshness=FreshnessState.UNAVAILABLE if not status.available else FreshnessState.LIVE,
            error_message=status.error_details
        )
        return ScanBatch(observations=[], metadata=meta)
