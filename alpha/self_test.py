"""
Automated Self-Test Engine for Alpha.

Executes an end-to-end programmatic verification of all internal subsystems:
Models, Sanitization, OUI Database, SQLite Storage, Acquisition Backends,
Correlation Tracker, Classification Engine, Signatures, Baseline Engine,
Watchlist, Analytics, Radar, and Exporters.
"""

import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Tuple

from alpha.models import (
    Observation,
    Contact,
    Event,
    Session,
    SignalType,
    ContactState,
    DeviceCategory,
    EventSeverity,
)
from alpha.sanitizer import (
    strip_ansi,
    sanitize_string,
    sanitize_mac,
    is_randomized_mac,
)
from alpha.oui.database import lookup_vendor, get_oui_database
from alpha.storage.database import AlphaDatabase
from alpha.acquisition.wifi import frequency_to_channel_and_band, parse_security_capabilities
from alpha.acquisition.mock import MockAcquisitionBackend
from alpha.correlation.tracker import ContactTracker
from alpha.signatures.rules import SignatureEngine, SignatureRule
from alpha.classification.engine import HeuristicClassifier
from alpha.baseline.engine import BaselineEngine
from alpha.watchlist.engine import WatchlistEngine, WatchlistRule
from alpha.analytics.engine import AnalyticsEngine
from alpha.radar.radar import TerminalRadar
from alpha.export.exporter import AlphaExporter


from alpha.acquisition.ble import TermuxBleBackend


class SelfTestRunner:
    """Executes automated verification tests across all Alpha subsystems."""

    def __init__(self):
        self.results: List[Tuple[str, bool, str]] = []

    def _record(self, name: str, passed: bool, msg: str = "") -> None:
        self.results.append((name, passed, msg))

    def run_all(self) -> bool:
        """Run all test suites and return overall pass/fail status."""
        self.test_sanitizer()
        self.test_oui_database()
        self.test_models()
        self.test_wifi_parsers()
        self.test_storage()
        self.test_mock_acquisition()
        self.test_ble_acquisition()
        self.test_correlation_tracker()
        self.test_classification_and_signatures()
        self.test_baseline_engine()
        self.test_watchlist_engine()
        self.test_analytics_and_timeline()
        self.test_radar_rendering()
        self.test_exporters()

        all_passed = all(passed for _, passed, _ in self.results)
        return all_passed

    def test_ble_acquisition(self) -> None:
        try:
            # Test hybrid fallback mode
            backend = TermuxBleBackend(enable_hybrid_fallback=True)
            batch = backend.scan("test_ble_sess")
            assert batch.metadata.success is True
            assert len(batch.observations) > 0
            assert any(o.signal_type == SignalType.BLE for o in batch.observations)
            assert any(o.device_name and "Apple Watch" in o.device_name for o in batch.observations)

            # Test dumpsys parsing directly
            sample_dump = """
            Bonded devices:
              AA:BB:CC:DD:EE:FF (Pixel Buds Pro) [LE]
              11:22:33:44:55:66 (Sony WH-1000XM4) [BR/EDR]
            Connected devices:
              AA:BB:CC:DD:EE:FF (Pixel Buds Pro)
            """
            parsed = backend._parse_dumpsys_output(sample_dump, "sess1")
            assert len(parsed) == 2
            assert any(p.identifier == "AA:BB:CC:DD:EE:FF" for p in parsed)
            assert any(p.device_name == "Pixel Buds Pro" for p in parsed)

            self._record("BLE & Bluetooth Acquisition Subsystem", True)
        except Exception as ex:
            self._record("BLE & Bluetooth Acquisition Subsystem", False, str(ex))

    def test_sanitizer(self) -> None:
        try:
            # ANSI stripping
            dirty = "\033[31mEvilNet\033[0m\x00\x07"
            cleaned = sanitize_string(dirty)
            assert "\033" not in cleaned, "ANSI escape not stripped"
            assert "\x00" not in cleaned, "Null byte not stripped"
            assert "EvilNet" in cleaned, "Expected content lost"

            # MAC normalization
            assert sanitize_mac("001122334455") == "00:11:22:33:44:55"
            assert sanitize_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"

            # Randomized MAC bit check
            assert is_randomized_mac("02:11:22:33:44:55") is True
            assert is_randomized_mac("00:11:22:33:44:55") is False
            self._record("Input Sanitizer & Security", True)
        except Exception as ex:
            self._record("Input Sanitizer & Security", False, str(ex))

    def test_oui_database(self) -> None:
        try:
            db = get_oui_database()
            mfg_apple, _ = lookup_vendor("00:17:F2:11:22:33")
            assert "Apple" in mfg_apple, f"Expected Apple, got {mfg_apple}"

            mfg_cisco, _ = lookup_vendor("00:00:0C:AA:BB:CC")
            assert "Cisco" in mfg_cisco, f"Expected Cisco, got {mfg_cisco}"

            mfg_rand, prefix_rand = lookup_vendor("DA:A1:19:88:77:66")
            assert "Randomized" in mfg_rand, f"Expected Randomized, got {mfg_rand}"

            self._record("OUI / Manufacturer Database", True)
        except Exception as ex:
            self._record("OUI / Manufacturer Database", False, str(ex))

    def test_models(self) -> None:
        try:
            obs = Observation(
                identifier="00:11:22:33:44:55",
                mac_address="00:11:22:33:44:55",
                rssi=-65,
                ssid="TestNet"
            )
            obs_dict = obs.to_dict()
            restored = Observation.from_dict(obs_dict)
            assert restored.identifier == obs.identifier
            assert restored.rssi == -65

            contact = Contact(
                identifier="00:11:22:33:44:55",
                mac_address="00:11:22:33:44:55",
                last_rssi=-65
            )
            c_dict = contact.to_dict()
            restored_c = Contact.from_dict(c_dict)
            assert restored_c.identifier == contact.identifier
            self._record("Data Models & Serialization", True)
        except Exception as ex:
            self._record("Data Models & Serialization", False, str(ex))

    def test_wifi_parsers(self) -> None:
        try:
            ch, band = frequency_to_channel_and_band(2412)
            assert ch == 1 and band == "2.4 GHz"
            ch5, band5 = frequency_to_channel_and_band(5180)
            assert ch5 == 36 and band5 == "5 GHz"
            ch6, band6 = frequency_to_channel_and_band(5975)
            assert band6 == "6 GHz"

            sec1 = parse_security_capabilities("[WPA2-PSK-CCMP][RSN-PSK-CCMP][ESS]")
            assert "WPA2" in sec1
            sec2 = parse_security_capabilities("[WPA3-SAE-CCMP][ESS]")
            assert "WPA3" in sec2
            self._record("Wi-Fi Frequency & Security Parsers", True)
        except Exception as ex:
            self._record("Wi-Fi Frequency & Security Parsers", False, str(ex))

    def test_storage(self) -> None:
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                db_file = Path(tmpdir) / "test.db"
                db = AlphaDatabase(str(db_file))

                # Test Session
                session = Session(session_id="test_sess", started_at=time.time())
                db.create_session(session)
                fetched_sess = db.get_session("test_sess")
                assert fetched_sess is not None and fetched_sess.session_id == "test_sess"

                # Test Observations
                obs = Observation(session_id="test_sess", identifier="00:11:22:33:44:55", mac_address="00:11:22:33:44:55", rssi=-60)
                db.insert_observations([obs])
                fetched_obs = db.get_observations_for_session("test_sess")
                assert len(fetched_obs) == 1

                # Test Contacts
                contact = Contact(session_id="test_sess", identifier="00:11:22:33:44:55", mac_address="00:11:22:33:44:55", last_rssi=-60)
                db.save_contacts([contact])
                fetched_c = db.get_contacts_for_session("test_sess")
                assert len(fetched_c) == 1

                # Test Events
                event = Event(session_id="test_sess", event_type="NEW_CONTACT", message="Test")
                db.insert_events([event])
                fetched_e = db.get_events_for_session("test_sess")
                assert len(fetched_e) == 1

                self._record("SQLite Database & Persistence", True)
        except Exception as ex:
            self._record("SQLite Database & Persistence", False, str(ex))

    def test_mock_acquisition(self) -> None:
        try:
            backend = MockAcquisitionBackend(scenario="busy")
            batch = backend.scan("mock_session")
            assert batch.metadata.success is True
            assert len(batch.observations) > 10
            assert any(o.signal_type == SignalType.BLE for o in batch.observations)
            assert any(o.signal_type == SignalType.WIFI for o in batch.observations)
            self._record("Mock Acquisition Subsystem", True)
        except Exception as ex:
            self._record("Mock Acquisition Subsystem", False, str(ex))

    def test_correlation_tracker(self) -> None:
        try:
            tracker = ContactTracker(new_window=10.0, active_window=20.0, stale_window=30.0, jump_threshold=15)
            obs1 = Observation(
                session_id="s1",
                timestamp=100.0,
                identifier="00:11:22:33:44:55",
                mac_address="00:11:22:33:44:55",
                ssid="TestNet",
                rssi=-60,
                channel=6
            )
            c1, ev1 = tracker.process_observation(obs1, "s1")
            assert c1.state == ContactState.NEW
            assert len(ev1) == 1 and ev1[0].event_type == "NEW_CONTACT"

            # Process 2nd observation with channel change and signal jump
            obs2 = Observation(
                session_id="s1",
                timestamp=105.0,
                identifier="00:11:22:33:44:55",
                mac_address="00:11:22:33:44:55",
                ssid="TestNet",
                rssi=-40,
                channel=11
            )
            c2, ev2 = tracker.process_observation(obs2, "s1")
            assert c2.observation_count == 2
            assert c2.mean_rssi == -50.0
            assert any(e.event_type == "CHANNEL_CHANGE" for e in ev2)
            assert any(e.event_type == "SIGNAL_CHANGE" for e in ev2)

            self._record("Temporal Correlation & Tracker", True)
        except Exception as ex:
            self._record("Temporal Correlation & Tracker", False, str(ex))

    def test_classification_and_signatures(self) -> None:
        try:
            sig_engine = SignatureEngine()
            classifier = HeuristicClassifier(sig_engine)

            # Test IoT Smart Bulb / Espressif
            contact_iot = Contact(
                identifier="18:FE:34:11:22:33",
                mac_address="18:FE:34:11:22:33",
                manufacturer="Espressif Systems",
                ssid="SmartLight_LivingRoom"
            )
            classifier.classify(contact_iot)
            assert contact_iot.category == DeviceCategory.IOT
            assert contact_iot.confidence >= 0.85

            # Test Enterprise Access Point
            contact_cisco = Contact(
                identifier="00:00:0C:11:22:33",
                mac_address="00:00:0C:11:22:33",
                manufacturer="Cisco Systems",
                ssid="Corporate_Staff"
            )
            classifier.classify(contact_cisco)
            assert contact_cisco.category == DeviceCategory.NETWORK_INFRASTRUCTURE

            self._record("Heuristic Classifier & Signatures", True)
        except Exception as ex:
            self._record("Heuristic Classifier & Signatures", False, str(ex))

    def test_baseline_engine(self) -> None:
        try:
            engine = BaselineEngine()
            contacts = [
                Contact(identifier="00:11:22:33:44:55", mac_address="00:11:22:33:44:55", manufacturer="Apple, Inc.", channel=1, last_rssi=-50),
                Contact(identifier="00:22:33:44:55:66", mac_address="00:22:33:44:55:66", manufacturer="TP-Link Technologies", channel=6, last_rssi=-70),
            ]
            snapshot = engine.capture_snapshot(contacts, name="test_baseline")
            assert snapshot.contact_count == 2
            assert snapshot.wifi_count == 2

            # Compare against modified environment
            new_contacts = list(contacts) + [
                Contact(identifier="00:33:44:55:66:77", mac_address="00:33:44:55:66:77", manufacturer="Unknown Vendor", channel=11, last_rssi=-80)
            ]
            comp = engine.compare_with_current(new_contacts)
            assert comp["status"] == "COMPARED"
            assert comp["contact_delta"] == 1
            self._record("Baseline & Anomaly Detection Engine", True)
        except Exception as ex:
            self._record("Baseline & Anomaly Detection Engine", False, str(ex))

    def test_watchlist_engine(self) -> None:
        try:
            engine = WatchlistEngine()
            rule = WatchlistRule(
                rule_id="w1",
                target_type="SSID",
                pattern="SecretNet",
                label="Target Test Network",
                severity=EventSeverity.ALERT
            )
            engine.add_rule(rule)

            c_match = Contact(
                identifier="00:11:22:33:44:55",
                mac_address="00:11:22:33:44:55",
                ssid="SecretNet_5G"
            )
            events = engine.evaluate(c_match, "s1")
            assert c_match.is_watchlist_match is True
            assert len(events) == 1 and events[0].event_type == "WATCHLIST_MATCH"
            self._record("Watchlist & Alert Trigger Engine", True)
        except Exception as ex:
            self._record("Watchlist & Alert Trigger Engine", False, str(ex))

    def test_analytics_and_timeline(self) -> None:
        try:
            contacts = [
                Contact(identifier="00:11:22:33:44:55", mac_address="00:11:22:33:44:55", signal_type=SignalType.WIFI, channel=6, last_rssi=-55),
                Contact(identifier="00:22:33:44:55:66", mac_address="00:22:33:44:55:66", signal_type=SignalType.BLE, last_rssi=-75),
            ]
            summary = AnalyticsEngine.compute_summary(contacts)
            assert summary["total_contacts"] == 2
            assert summary["wifi_count"] == 1
            assert summary["ble_count"] == 1

            obs = [
                Observation(timestamp=100.0, identifier="00:11:22:33:44:55", mac_address="00:11:22:33:44:55"),
                Observation(timestamp=120.0, identifier="00:11:22:33:44:55", mac_address="00:11:22:33:44:55"),
            ]
            timeline = AnalyticsEngine.generate_timeline(obs, bucket_seconds=60)
            assert len(timeline) >= 1
            self._record("Analytics & Spectrum Aggregator", True)
        except Exception as ex:
            self._record("Analytics & Spectrum Aggregator", False, str(ex))

    def test_radar_rendering(self) -> None:
        try:
            radar = TerminalRadar(ascii_only=True)
            contacts = [
                Contact(identifier="00:11:22:33:44:55", mac_address="00:11:22:33:44:55", last_rssi=-50, ssid="NetA"),
                Contact(identifier="00:22:33:44:55:66", mac_address="00:22:33:44:55:66", last_rssi=-80, ssid="NetB"),
            ]
            rendered = radar.render(contacts, width=60, height=16, use_color=False)
            assert "RELATIVE RF SIGNAL RADAR" in rendered
            assert len(rendered.splitlines()) >= 16
            self._record("Terminal Polar Radar Visualization", True)
        except Exception as ex:
            self._record("Terminal Polar Radar Visualization", False, str(ex))

    def test_exporters(self) -> None:
        try:
            session = Session(session_id="test_export_sess", started_at=time.time())
            contacts = [
                Contact(identifier="00:11:22:33:44:55", mac_address="00:11:22:33:44:55", ssid="NetA", last_rssi=-55)
            ]
            events = [
                Event(session_id="test_export_sess", event_type="NEW_CONTACT", message="New device")
            ]

            csv_out = AlphaExporter.to_csv(contacts)
            assert "00:11:22:33:44:55" in csv_out

            json_out = AlphaExporter.to_json(session, contacts, events)
            assert "test_export_sess" in json_out

            md_out = AlphaExporter.to_markdown(session, contacts, events)
            assert "# ALPHA Session Report" in md_out

            debrief_out = AlphaExporter.to_debrief_report(session, contacts, events)
            assert "# ALPHA WIRELESS ENVIRONMENTAL DEBRIEF REPORT" in debrief_out
            assert "OBSERVED" in debrief_out
            assert "HEURISTIC" in debrief_out

            self._record("Multi-Format & Debrief Exporters", True)
        except Exception as ex:
            self._record("Multi-Format & Debrief Exporters", False, str(ex))

    def format_report(self) -> str:
        """Produce formatted report of all self-test results."""
        lines = [
            "============================================================",
            "                   ALPHA AUTOMATED SELF-TEST                ",
            "============================================================",
        ]
        passed_count = sum(1 for _, ok, _ in self.results if ok)
        total_count = len(self.results)

        for name, ok, msg in self.results:
            if ok:
                lines.append(f"  \033[92;1m[PASS]\033[0m {name:<42}")
            else:
                lines.append(f"  \033[91;1m[FAIL]\033[0m {name:<42} -> {msg}")

        lines.append("------------------------------------------------------------")
        if passed_count == total_count:
            lines.append(f"  \033[92;1mALL SUBSYSTEMS OPERATIONAL ({passed_count}/{total_count} PASSED)\033[0m")
        else:
            lines.append(f"  \033[91;1mVERIFICATION FAILED ({passed_count}/{total_count} PASSED)\033[0m")
        lines.append("============================================================")
        return "\n".join(lines)


def run_self_test() -> bool:
    """Run self-test suite and print report to console."""
    runner = SelfTestRunner()
    ok = runner.run_all()
    print(runner.format_report())
    return ok
