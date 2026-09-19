"""
Unit tests for temporal correlation, state machine transitions, and RSSI statistics.
"""

import pytest
from alpha.models import Observation, ContactState, SignalCategory
from alpha.correlation.tracker import ContactTracker


def test_contact_state_lifecycle():
    tracker = ContactTracker(new_window=10.0, active_window=20.0, stale_window=30.0)
    
    # 1. First observation -> NEW
    obs1 = Observation(
        timestamp=100.0,
        identifier="00:11:22:33:44:55",
        mac_address="00:11:22:33:44:55",
        rssi=-50,
        ssid="TestAP"
    )
    c1, ev1 = tracker.process_observation(obs1, "sess_1")
    assert c1.state == ContactState.NEW
    assert c1.observation_count == 1
    assert len(ev1) == 1 and ev1[0].event_type == "NEW_CONTACT"

    # 2. Second observation at +5s -> Still NEW
    obs2 = Observation(
        timestamp=105.0,
        identifier="00:11:22:33:44:55",
        mac_address="00:11:22:33:44:55",
        rssi=-52,
        ssid="TestAP"
    )
    c2, _ = tracker.process_observation(obs2, "sess_1")
    assert c2.state == ContactState.NEW
    assert c2.observation_count == 2
    assert c2.mean_rssi == -51.0

    # 3. Third observation at +15s -> Transitions to ACTIVE
    obs3 = Observation(
        timestamp=115.0,
        identifier="00:11:22:33:44:55",
        mac_address="00:11:22:33:44:55",
        rssi=-48,
        ssid="TestAP"
    )
    c3, _ = tracker.process_observation(obs3, "sess_1")
    assert c3.state == ContactState.ACTIVE
    assert c3.observation_count == 3


def test_signal_categories():
    tracker = ContactTracker(rssi_strong=-60, rssi_medium=-75, rssi_weak=-85)
    assert tracker.get_signal_category(-45) == SignalCategory.STRONG
    assert tracker.get_signal_category(-68) == SignalCategory.MEDIUM
    assert tracker.get_signal_category(-80) == SignalCategory.WEAK
    assert tracker.get_signal_category(-92) == SignalCategory.VERY_WEAK


def test_channel_change_detection():
    tracker = ContactTracker()
    obs1 = Observation(timestamp=100.0, identifier="00:11:22:33:44:55", mac_address="00:11:22:33:44:55", channel=1, rssi=-60)
    tracker.process_observation(obs1, "sess_1")

    obs2 = Observation(timestamp=110.0, identifier="00:11:22:33:44:55", mac_address="00:11:22:33:44:55", channel=6, rssi=-60)
    c, events = tracker.process_observation(obs2, "sess_1")
    assert c.channel == 6
    assert any(e.event_type == "CHANNEL_CHANGE" for e in events)
