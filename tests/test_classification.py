"""
Unit tests for heuristic classifier and signature rules.
"""

import pytest
from alpha.models import Contact, DeviceCategory, SignalType
from alpha.signatures.rules import SignatureEngine, SignatureRule
from alpha.classification.engine import HeuristicClassifier


def test_classify_router():
    classifier = HeuristicClassifier()
    contact = Contact(
        identifier="00:19:E0:11:22:33",
        mac_address="00:19:E0:11:22:33",
        manufacturer="TP-Link Technologies",
        ssid="TP-Link_Deco_Home",
        signal_type=SignalType.WIFI,
    )
    classifier.classify(contact)
    assert contact.category in (DeviceCategory.ROUTER, DeviceCategory.NETWORK_INFRASTRUCTURE)
    assert contact.confidence >= 0.75
    assert len(contact.evidence) > 0


def test_classify_wearable():
    classifier = HeuristicClassifier()
    contact = Contact(
        identifier="DC:A6:32:00:11:22",
        mac_address="DC:A6:32:00:11:22",
        signal_type=SignalType.BLE,
        device_name="Apple Watch Series 9",
        manufacturer="Apple, Inc.",
    )
    classifier.classify(contact)
    assert contact.category == DeviceCategory.WEARABLE
    assert contact.confidence >= 0.85


def test_classify_iot():
    classifier = HeuristicClassifier()
    contact = Contact(
        identifier="18:FE:34:55:66:77",
        mac_address="18:FE:34:55:66:77",
        manufacturer="Espressif Systems",
        ssid="SmartBulb_RGB",
        signal_type=SignalType.WIFI,
    )
    classifier.classify(contact)
    assert contact.category == DeviceCategory.IOT
    assert contact.confidence >= 0.85
