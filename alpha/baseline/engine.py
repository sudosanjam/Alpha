"""
Environmental Baseline and Change Detection Engine for Alpha.

Allows establishing local RF environmental profiles and comparing live observations
against baselines to detect population, channel, and vendor anomalies.
"""

import json
import time
from collections import Counter
from typing import Dict, List, Optional, Any, Tuple
from alpha.models import BaselineSnapshot, Contact, SignalType, Event, EventSeverity
from alpha.logger import get_logger

logger = get_logger("baseline")


class BaselineEngine:
    """Creates baseline profiles of normal RF environments and computes comparative deviations."""

    def __init__(self, current_baseline: Optional[BaselineSnapshot] = None):
        self.active_baseline = current_baseline

    def capture_snapshot(self, contacts: List[Contact], name: str = "default_baseline") -> BaselineSnapshot:
        """Generate a baseline snapshot from a collection of contacts."""
        now = time.time()
        wifi_contacts = [c for c in contacts if c.signal_type == SignalType.WIFI]
        ble_contacts = [c for c in contacts if c.signal_type == SignalType.BLE]

        # Channel distribution
        channels = [str(c.channel) for c in wifi_contacts if c.channel is not None]
        channel_dist = dict(Counter(channels))

        # Manufacturer distribution
        manufacturers = [c.manufacturer for c in contacts if c.manufacturer and c.manufacturer != "UNKNOWN"]
        mfg_dist = dict(Counter(manufacturers))

        # Security distribution
        securities = [c.security for c in wifi_contacts if c.security]
        sec_dist = dict(Counter(securities))

        # Mean RSSI
        all_rssi = [c.last_rssi for c in contacts if c.last_rssi > -120]
        mean_rssi = sum(all_rssi) / len(all_rssi) if all_rssi else 0.0

        snapshot = BaselineSnapshot(
            name=name,
            created_at=now,
            observation_count=sum(c.observation_count for c in contacts),
            contact_count=len(contacts),
            wifi_count=len(wifi_contacts),
            ble_count=len(ble_contacts),
            channel_distribution=channel_dist,
            manufacturer_distribution=mfg_dist,
            security_distribution=sec_dist,
            mean_rssi=round(mean_rssi, 1),
        )
        self.active_baseline = snapshot
        return snapshot

    def compare_with_current(self, contacts: List[Contact]) -> Dict[str, Any]:
        """
        Compare active contacts against active baseline.
        Returns a dictionary of deviation metrics and anomalies.
        """
        if not self.active_baseline:
            return {"status": "NO_ACTIVE_BASELINE", "deviations": []}

        base = self.active_baseline
        current = self.capture_snapshot(contacts, name="temp_comparison")

        contact_delta = current.contact_count - base.contact_count
        wifi_delta = current.wifi_count - base.wifi_count
        ble_delta = current.ble_count - base.ble_count
        rssi_delta = current.mean_rssi - base.mean_rssi

        # Check for new manufacturers not in baseline
        new_mfgs = []
        for mfg, count in current.manufacturer_distribution.items():
            if mfg not in base.manufacturer_distribution:
                new_mfgs.append({"manufacturer": mfg, "count": count})

        # Check for channel shifts
        channel_changes = {}
        for ch, count in current.channel_distribution.items():
            base_count = base.channel_distribution.get(ch, 0)
            if abs(count - base_count) >= 2:
                channel_changes[ch] = {"baseline": base_count, "current": count, "delta": count - base_count}

        deviations = []
        if abs(contact_delta) >= 3:
            deviations.append(f"Total contacts changed by {contact_delta:+d} (baseline: {base.contact_count}, current: {current.contact_count})")
        if new_mfgs:
            deviations.append(f"Discovered {len(new_mfgs)} previously unobserved manufacturer(s)")
        if channel_changes:
            deviations.append(f"Channel distribution changed across {len(channel_changes)} channel(s)")
        if abs(rssi_delta) >= 6.0:
            deviations.append(f"Mean environmental RSSI shifted by {rssi_delta:+.1f} dBm")

        return {
            "status": "COMPARED",
            "baseline_name": base.name,
            "baseline_timestamp": base.created_at,
            "contact_delta": contact_delta,
            "wifi_delta": wifi_delta,
            "ble_delta": ble_delta,
            "rssi_delta": round(rssi_delta, 1),
            "new_manufacturers": new_mfgs,
            "channel_changes": channel_changes,
            "deviations": deviations,
        }
