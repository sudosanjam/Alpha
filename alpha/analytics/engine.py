"""
Analytics & Timeline Engine for Alpha.

Provides statistical aggregation of wireless observations, including spectrum density,
channel distributions, frequency band breakdowns, manufacturer shares, security postures,
and historical observation timelines.
"""

from collections import Counter, defaultdict
import time
from typing import Dict, List, Optional, Any, Tuple

from alpha.models import Contact, Observation, SignalType, DeviceCategory, ContactState


class AnalyticsEngine:
    """Computes comprehensive RF metrics from contacts and observations."""

    @staticmethod
    def compute_summary(contacts: List[Contact]) -> Dict[str, Any]:
        """Compute full statistical summary of current wireless environment."""
        total_contacts = len(contacts)
        wifi_contacts = [c for c in contacts if c.signal_type == SignalType.WIFI]
        ble_contacts = [c for c in contacts if c.signal_type == SignalType.BLE]

        # State counts
        state_counts = {
            "NEW": sum(1 for c in contacts if c.state == ContactState.NEW),
            "ACTIVE": sum(1 for c in contacts if c.state == ContactState.ACTIVE),
            "RECENT": sum(1 for c in contacts if c.state == ContactState.RECENT),
            "STALE": sum(1 for c in contacts if c.state == ContactState.STALE),
        }

        # Wi-Fi Channel Distribution
        channels = [str(c.channel) for c in wifi_contacts if c.channel is not None]
        channel_dist = dict(Counter(channels).most_common(15))

        # Frequency Band Distribution
        bands = [c.band for c in wifi_contacts if c.band]
        band_dist = dict(Counter(bands))

        # Manufacturers Breakdown
        mfgs = [c.manufacturer for c in contacts if c.manufacturer and c.manufacturer != "UNKNOWN"]
        mfg_dist = dict(Counter(mfgs).most_common(10))
        unknown_mfg = sum(1 for c in contacts if not c.manufacturer or c.manufacturer == "UNKNOWN")
        if unknown_mfg > 0:
            mfg_dist["UNKNOWN"] = unknown_mfg

        # Device Categories Breakdown
        categories = [c.category.value for c in contacts]
        cat_dist = dict(Counter(categories))

        # Security Breakdown
        security = [c.security for c in wifi_contacts if c.security]
        sec_dist = dict(Counter(security))

        # RSSI Distribution Buckets
        rssi_buckets = {
            "Strong (>-60 dBm)": 0,
            "Medium (-60 to -75 dBm)": 0,
            "Weak (-75 to -85 dBm)": 0,
            "Very Weak (<-85 dBm)": 0,
        }
        for c in contacts:
            r = c.last_rssi
            if r > -60:
                rssi_buckets["Strong (>-60 dBm)"] += 1
            elif r >= -75:
                rssi_buckets["Medium (-60 to -75 dBm)"] += 1
            elif r >= -85:
                rssi_buckets["Weak (-75 to -85 dBm)"] += 1
            elif r > -120:
                rssi_buckets["Very Weak (<-85 dBm)"] += 1

        # Mean RSSI
        valid_rssi = [c.last_rssi for c in contacts if c.last_rssi > -120]
        mean_rssi = sum(valid_rssi) / len(valid_rssi) if valid_rssi else 0.0

        # Randomized MAC count
        randomized_mac_count = sum(1 for c in contacts if c.is_randomized_mac)

        return {
            "total_contacts": total_contacts,
            "wifi_count": len(wifi_contacts),
            "ble_count": len(ble_contacts),
            "states": state_counts,
            "channel_distribution": channel_dist,
            "band_distribution": band_dist,
            "manufacturer_distribution": mfg_dist,
            "category_distribution": cat_dist,
            "security_distribution": sec_dist,
            "rssi_distribution": rssi_buckets,
            "mean_rssi": round(mean_rssi, 1),
            "randomized_mac_count": randomized_mac_count,
        }

    @staticmethod
    def generate_timeline(
        observations: List[Observation], bucket_seconds: int = 60
    ) -> List[Dict[str, Any]]:
        """
        Group observations into discrete time buckets to visualize temporal observation rates.
        """
        if not observations:
            return []

        sorted_obs = sorted(observations, key=lambda x: x.timestamp)
        start_ts = sorted_obs[0].timestamp
        
        buckets: Dict[int, Dict[str, Any]] = defaultdict(
            lambda: {"timestamp": 0.0, "total": 0, "wifi": 0, "ble": 0, "unique_identifiers": set()}
        )

        for obs in sorted_obs:
            bucket_idx = int((obs.timestamp - start_ts) // bucket_seconds)
            bucket_time = start_ts + (bucket_idx * bucket_seconds)
            b = buckets[bucket_idx]
            b["timestamp"] = bucket_time
            b["total"] += 1
            if obs.signal_type == SignalType.WIFI:
                b["wifi"] += 1
            elif obs.signal_type == SignalType.BLE:
                b["ble"] += 1
            b["unique_identifiers"].add(obs.identifier)

        timeline = []
        for idx in sorted(buckets.keys()):
            entry = buckets[idx]
            timeline.append({
                "time_str": time.strftime("%H:%M:%S", time.localtime(entry["timestamp"])),
                "timestamp": entry["timestamp"],
                "total_observations": entry["total"],
                "wifi_count": entry["wifi"],
                "ble_count": entry["ble"],
                "unique_devices": len(entry["unique_identifiers"]),
            })

        return timeline
