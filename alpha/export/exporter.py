"""
Export Subsystem for Alpha.

Provides structured data exports in CSV, JSON, Markdown, and an LLM-friendly Debrief Report.
Explicitly distinguishes OBSERVED data, DERIVED analytics, and HEURISTIC classifications.
"""

import csv
import io
import json
import time
from typing import Dict, List, Optional, Any

from alpha.models import Session, Contact, Event, Observation, ContactState, SignalType
from alpha.analytics.engine import AnalyticsEngine
from alpha.sanitizer import sanitize_string


class AlphaExporter:
    """Exports Alpha monitoring sessions and observations in various formats."""

    @staticmethod
    def to_csv(contacts: List[Contact]) -> str:
        """Export list of contacts to CSV format."""
        output = io.StringIO()
        fieldnames = [
            "contact_id",
            "signal_type",
            "mac_address",
            "ssid",
            "device_name",
            "manufacturer",
            "oui",
            "is_randomized_mac",
            "category",
            "confidence",
            "state",
            "first_seen",
            "last_seen",
            "observation_count",
            "last_rssi",
            "min_rssi",
            "max_rssi",
            "mean_rssi",
            "rssi_trend",
            "channel",
            "band",
            "security",
            "is_watchlist_match",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for c in contacts:
            writer.writerow({
                "contact_id": c.contact_id,
                "signal_type": c.signal_type.value,
                "mac_address": c.mac_address,
                "ssid": c.ssid or "",
                "device_name": c.device_name or "",
                "manufacturer": c.manufacturer,
                "oui": c.oui,
                "is_randomized_mac": c.is_randomized_mac,
                "category": c.category.value,
                "confidence": c.confidence,
                "state": c.state.value,
                "first_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(c.first_seen)),
                "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(c.last_seen)),
                "observation_count": c.observation_count,
                "last_rssi": c.last_rssi,
                "min_rssi": c.min_rssi,
                "max_rssi": c.max_rssi,
                "mean_rssi": round(c.mean_rssi, 1),
                "rssi_trend": c.rssi_trend,
                "channel": c.channel or "",
                "band": c.band or "",
                "security": c.security,
                "is_watchlist_match": c.is_watchlist_match,
            })
            
        return output.getvalue()

    @staticmethod
    def to_json(
        session: Session,
        contacts: List[Contact],
        events: List[Event],
        observations: Optional[List[Observation]] = None,
        indent: int = 2
    ) -> str:
        """Export session, contacts, and events to structured JSON."""
        summary = AnalyticsEngine.compute_summary(contacts)
        payload = {
            "alpha_version": session.alpha_version,
            "session": session.to_dict(),
            "summary": summary,
            "contacts": [c.to_dict() for c in contacts],
            "events": [e.to_dict() for e in events],
        }
        if observations:
            payload["observations"] = [o.to_dict() for o in observations]
            
        return json.dumps(payload, indent=indent)

    @staticmethod
    def to_markdown(session: Session, contacts: List[Contact], events: List[Event]) -> str:
        """Export clean Markdown summary tables."""
        summary = AnalyticsEngine.compute_summary(contacts)
        lines = [
            f"# ALPHA Session Report: `{session.session_id}`",
            f"*Started:* {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session.started_at))}  ",
            f"*Device:* {session.device_model} (Android: {session.android_version}, Termux: {session.termux_version})  ",
            f"*Total Unique Contacts:* {summary['total_contacts']} (Wi-Fi: {summary['wifi_count']}, BLE: {summary['ble_count']})  ",
            f"*Mean RSSI:* {summary['mean_rssi']} dBm  ",
            "",
            "## Contacts",
            "| State | Signal | SSID / Device Name | MAC / BSSID | Manufacturer | Category | Conf | RSSI | Ch | Security |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for c in contacts:
            name = sanitize_string(c.ssid or c.device_name or "[None]", max_length=20)
            lines.append(
                f"| {c.state.value} | {c.signal_type.value} | {name} | `{c.mac_address}` | {c.manufacturer} | {c.category.value} | {c.confidence:.2f} | {c.last_rssi} dBm | {c.channel or 'N/A'} | {c.security} |"
            )
        
        lines.append("")
        lines.append("## Events")
        lines.append("| Timestamp | Type | Severity | Target | Message |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for e in events[:50]:
            ts_str = time.strftime("%H:%M:%S", time.localtime(e.timestamp))
            lines.append(
                f"| {ts_str} | {e.event_type} | {e.severity.value} | `{e.related_identifier}` | {e.message} |"
            )
            
        return "\n".join(lines)

    @staticmethod
    def to_debrief_report(
        session: Session,
        contacts: List[Contact],
        events: List[Event],
        observations: Optional[List[Observation]] = None
    ) -> str:
        """
        Generate a comprehensive, LLM-ready structured Markdown debrief report.
        """
        summary = AnalyticsEngine.compute_summary(contacts)
        dur = (session.ended_at or time.time()) - session.started_at
        dur_min = round(dur / 60.0, 1)

        doc = [
            "# ALPHA WIRELESS ENVIRONMENTAL DEBRIEF REPORT",
            "---",
            "## 1. Session Metadata & Context",
            f"- **Session ID:** `{session.session_id}`",
            f"- **Timestamp:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session.started_at))} (Duration: {dur_min} min)",
            f"- **Operating Environment:** Android {session.android_version} / Termux {session.termux_version} / Alpha v{session.alpha_version}",
            f"- **Execution Mode:** {'MOCK SIMULATION (Scenario: ' + session.scenario + ')' if session.is_mock else 'GENUINE ROOTLESS ACQUISITION'}",
            f"- **Total Observations:** {session.observation_count}",
            f"- **Unique Wireless Contacts:** {summary['total_contacts']} (Wi-Fi: {summary['wifi_count']}, BLE: {summary['ble_count']})",
            "",
            "---",
            "## 2. RF Spectrum & Channel Density",
            "### 2.1 Frequency Band Distribution",
        ]
        for band, cnt in summary["band_distribution"].items():
            pct = (cnt / max(1, summary["wifi_count"])) * 100
            doc.append(f"- **{band}:** {cnt} access points ({pct:.1f}%)")

        doc.append("")
        doc.append("### 2.2 Wi-Fi Channel Occupancy")
        for ch, cnt in summary["channel_distribution"].items():
            doc.append(f"- **Channel {ch}:** {cnt} BSSID(s)")

        doc.append("")
        doc.append("### 2.3 Signal Strength Distribution (RSSI)")
        for bucket, cnt in summary["rssi_distribution"].items():
            doc.append(f"- **{bucket}:** {cnt} device(s)")

        doc.append("")
        doc.append("---",)
        doc.append("## 3. Manufacturer & Classification Analysis")
        doc.append("### 3.1 Top Manufacturers")
        for mfg, cnt in summary["manufacturer_distribution"].items():
            doc.append(f"- **{mfg}:** {cnt} contact(s)")

        doc.append("")
        doc.append("### 3.2 Heuristic Device Categories")
        for cat, cnt in summary["category_distribution"].items():
            doc.append(f"- **{cat}:** {cnt} device(s)")

        doc.append("")
        doc.append("---")
        doc.append("## 4. Notable Contacts & Heuristic Evidence")
        doc.append("| State | Type | Identifier / BSSID | SSID / Name | Manufacturer | Category | Conf | RSSI | Evidence Summary |")
        doc.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for c in sorted(contacts, key=lambda x: x.last_rssi, reverse=True):
            ev_str = "; ".join(c.evidence[:2]) if c.evidence else "Standard broadcast"
            name_str = sanitize_string(c.ssid or c.device_name or "[Hidden/None]", max_length=18)
            doc.append(
                f"| {c.state.value} | {c.signal_type.value} | `{c.mac_address}` | {name_str} | {c.manufacturer} | {c.category.value} | {c.confidence:.2f} | {c.last_rssi} dBm | {ev_str} |"
            )

        doc.append("")
        doc.append("---")
        doc.append("## 5. Security Posture & Watchlist Events")
        doc.append(f"- **Randomized / Private MACs:** {summary['randomized_mac_count']} contact(s)")
        doc.append(f"- **Total Operational Events Recorded:** {len(events)}")
        
        watchlist_events = [e for e in events if e.event_type == "WATCHLIST_MATCH"]
        doc.append(f"- **Watchlist Matches:** {len(watchlist_events)}")
        for we in watchlist_events:
            doc.append(f"  - `{we.related_identifier}`: {we.message}")

        doc.append("")
        doc.append("---")
        doc.append("## 6. Data Provenance & Methodological Limitations")
        doc.append("### 6.1 Data Provenance")
        doc.append("- **OBSERVED:** BSSID, SSID, raw RSSI, carrier frequency, capabilities, raw BLE advertisements.")
        doc.append("- **DERIVED:** Channel numbers, frequency bands, RSSI rolling averages/trends, contact states (NEW/ACTIVE/RECENT/STALE), session timelines.")
        doc.append("- **HEURISTIC:** Heuristic device categories, confidence scores, and signature matches.")
        doc.append("")
        doc.append("### 6.2 Operational Limitations")
        doc.append("- **Stock Rootless Android:** Alpha operates completely without root privileges. No monitor mode, packet injection, or raw 802.11 frames are captured.")
        doc.append("- **Wi-Fi Scan Throttling:** Android limits foreground scan requests. Cached results are detected and reported.")
        doc.append("- **Non-Geographic RSSI:** RSSI measures relative RF signal attenuation, not physical distance or GPS coordinates.")

        return "\n".join(doc)
