"""
Unit tests for data models, serialization, and immutability.
"""

import pytest
from alpha.models import (
    Observation,
    Contact,
    Event,
    Session,
    BaselineSnapshot,
    SignalType,
    ContactState,
    DeviceCategory,
    EventSeverity,
    DataProvenance,
)


def test_observation_lifecycle():
    obs = Observation(
        session_id="test_sess",
        source="unit_test",
        signal_type=SignalType.WIFI,
        identifier="00:11:22:33:44:55",
        mac_address="00:11:22:33:44:55",
        ssid="MyHomeWiFi",
        rssi=-55,
        frequency=2412,
        channel=1,
        band="2.4 GHz",
        security="WPA2",
    )
    d = obs.to_dict()
    assert d["signal_type"] == "WIFI"
    assert d["provenance"] == "OBSERVED"
    assert d["rssi"] == -55

    restored = Observation.from_dict(d)
    assert restored.identifier == "00:11:22:33:44:55"
    assert restored.signal_type == SignalType.WIFI
    assert restored.ssid == "MyHomeWiFi"


def test_contact_lifecycle():
    contact = Contact(
        session_id="test_sess",
        signal_type=SignalType.WIFI,
        identifier="AA:BB:CC:DD:EE:FF",
        mac_address="AA:BB:CC:DD:EE:FF",
        manufacturer="Apple, Inc.",
        category=DeviceCategory.MOBILE_DEVICE,
        confidence=0.85,
        state=ContactState.NEW,
        last_rssi=-50,
        mean_rssi=-50.0,
    )
    d = contact.to_dict()
    assert d["category"] == "MOBILE_DEVICE"
    assert d["state"] == "NEW"

    restored = Contact.from_dict(d)
    assert restored.identifier == "AA:BB:CC:DD:EE:FF"
    assert restored.category == DeviceCategory.MOBILE_DEVICE
    assert restored.state == ContactState.NEW


def test_event_lifecycle():
    ev = Event(
        session_id="test_sess",
        event_type="NEW_CONTACT",
        severity=EventSeverity.NOTICE,
        related_identifier="00:11:22:33:44:55",
        message="New device found",
        evidence=["RSSI -60 dBm"],
    )
    d = ev.to_dict()
    assert d["severity"] == "NOTICE"
    assert d["event_type"] == "NEW_CONTACT"
