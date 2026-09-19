"""
Temporal Correlation and Contact Tracking Engine for Alpha.

Maintains stateful entities (Contacts) from incoming raw Observations, calculating
RSSI statistics, signal categorization, state transitions (NEW, ACTIVE, RECENT, STALE),
and detecting operational wireless events.
"""

import math
import time
from typing import Dict, List, Optional, Tuple

from alpha.models import (
    Observation,
    Contact,
    Event,
    ContactState,
    SignalCategory,
    EventSeverity,
    SignalType,
)
from alpha.sanitizer import is_randomized_mac, sanitize_string
from alpha.oui.database import lookup_vendor
from alpha.logger import get_logger

logger = get_logger("correlation")


class ContactTracker:
    """Tracks wireless observations over time and aggregates them into Contacts."""

    def __init__(
        self,
        new_window: float = 20.0,
        active_window: float = 45.0,
        stale_window: float = 120.0,
        jump_threshold: int = 15,
        rssi_strong: int = -60,
        rssi_medium: int = -75,
        rssi_weak: int = -85,
    ):
        self.new_window = new_window
        self.active_window = active_window
        self.stale_window = stale_window
        self.jump_threshold = jump_threshold
        self.rssi_strong = rssi_strong
        self.rssi_medium = rssi_medium
        self.rssi_weak = rssi_weak
        self.contacts: Dict[str, Contact] = {}

    def get_signal_category(self, rssi: int) -> SignalCategory:
        """Classify RSSI into signal strength category."""
        if rssi > self.rssi_strong:
            return SignalCategory.STRONG
        elif rssi >= self.rssi_medium:
            return SignalCategory.MEDIUM
        elif rssi >= self.rssi_weak:
            return SignalCategory.WEAK
        elif rssi < self.rssi_weak and rssi > -120:
            return SignalCategory.VERY_WEAK
        return SignalCategory.UNKNOWN

    def _calculate_trend(self, history: List[int]) -> str:
        """Calculate signal trend (RISING, FALLING, STEADY) from recent RSSI samples."""
        if len(history) < 4:
            return "STEADY"
        recent = sum(history[-2:]) / 2.0
        earlier = sum(history[-4:-2]) / 2.0
        delta = recent - earlier
        if delta >= 4.0:
            return "RISING"
        elif delta <= -4.0:
            return "FALLING"
        return "STEADY"

    def process_observation(
        self, obs: Observation, session_id: str
    ) -> Tuple[Contact, List[Event]]:
        """
        Process a single observation, update or create contact, and return generated events.
        """
        now = obs.timestamp
        identifier = obs.identifier
        events: List[Event] = []

        if identifier not in self.contacts:
            # First time observing this identifier
            manufacturer, oui = lookup_vendor(obs.mac_address)
            is_rand = is_randomized_mac(obs.mac_address)
            
            contact = Contact(
                session_id=session_id,
                signal_type=obs.signal_type,
                identifier=identifier,
                mac_address=obs.mac_address,
                bssid=obs.bssid,
                ssid=obs.ssid,
                device_name=obs.device_name,
                manufacturer=manufacturer,
                oui=oui,
                is_randomized_mac=is_rand,
                state=ContactState.NEW,
                first_seen=now,
                last_seen=now,
                observation_count=1,
                last_rssi=obs.rssi,
                min_rssi=obs.rssi,
                max_rssi=obs.rssi,
                mean_rssi=float(obs.rssi),
                rssi_variance=0.0,
                rssi_trend="STEADY",
                signal_category=self.get_signal_category(obs.rssi),
                channel=obs.channel,
                frequency=obs.frequency,
                band=obs.band,
                security=obs.security,
                capabilities=obs.capabilities,
                recent_rssi_history=[obs.rssi],
            )
            self.contacts[identifier] = contact

            # Emit NEW_CONTACT event
            events.append(
                Event(
                    session_id=session_id,
                    timestamp=now,
                    event_type="NEW_CONTACT",
                    severity=EventSeverity.INFO,
                    related_identifier=identifier,
                    related_contact_id=contact.contact_id,
                    message=f"New contact observed: {obs.ssid or obs.device_name or identifier} ({manufacturer})",
                    evidence=[
                        f"Signal: {obs.signal_type.value}",
                        f"RSSI: {obs.rssi} dBm",
                        f"Manufacturer: {manufacturer}",
                        f"Channel: {obs.channel or 'N/A'}",
                    ],
                    data={"rssi": obs.rssi, "mac": obs.mac_address},
                )
            )
            return contact, events

        # Existing contact
        contact = self.contacts[identifier]
        prev_state = contact.state
        prev_rssi = contact.last_rssi
        prev_channel = contact.channel
        prev_security = contact.security

        # Update timing and counts
        contact.last_seen = now
        contact.observation_count += 1
        
        # Check return from STALE
        if prev_state == ContactState.STALE:
            contact.state = ContactState.ACTIVE
            events.append(
                Event(
                    session_id=session_id,
                    timestamp=now,
                    event_type="CONTACT_RETURNED",
                    severity=EventSeverity.NOTICE,
                    related_identifier=identifier,
                    related_contact_id=contact.contact_id,
                    message=f"Contact returned after being stale: {contact.ssid or contact.device_name or identifier}",
                    evidence=[f"Current RSSI: {obs.rssi} dBm"],
                    data={"last_seen": now},
                )
            )
        elif (now - contact.first_seen) <= self.new_window:
            contact.state = ContactState.NEW
        else:
            contact.state = ContactState.ACTIVE

        # Update metadata if newly available
        if obs.ssid and obs.ssid != "[Hidden SSID]" and not contact.ssid:
            contact.ssid = obs.ssid
        if obs.device_name and not contact.device_name:
            contact.device_name = obs.device_name
        if obs.frequency:
            contact.frequency = obs.frequency
        if obs.band:
            contact.band = obs.band
        if obs.capabilities:
            contact.capabilities = obs.capabilities

        # Check for Channel Change
        if obs.channel is not None and prev_channel is not None and obs.channel != prev_channel:
            contact.channel = obs.channel
            events.append(
                Event(
                    session_id=session_id,
                    timestamp=now,
                    event_type="CHANNEL_CHANGE",
                    severity=EventSeverity.NOTICE,
                    related_identifier=identifier,
                    related_contact_id=contact.contact_id,
                    message=f"Contact changed channel from {prev_channel} to {obs.channel}",
                    evidence=[f"Previous: Ch {prev_channel}", f"New: Ch {obs.channel}"],
                    data={"old_channel": prev_channel, "new_channel": obs.channel},
                )
            )
        elif obs.channel is not None:
            contact.channel = obs.channel

        # Check for Security Change
        if obs.security and obs.security != "UNKNOWN" and prev_security != "UNKNOWN" and obs.security != prev_security:
            contact.security = obs.security
            events.append(
                Event(
                    session_id=session_id,
                    timestamp=now,
                    event_type="SECURITY_CHANGE",
                    severity=EventSeverity.WARNING,
                    related_identifier=identifier,
                    related_contact_id=contact.contact_id,
                    message=f"Contact security changed from {prev_security} to {obs.security}",
                    evidence=[f"Old: {prev_security}", f"New: {obs.security}"],
                    data={"old_sec": prev_security, "new_sec": obs.security},
                )
            )
        elif obs.security and obs.security != "UNKNOWN":
            contact.security = obs.security

        # Update RSSI statistics
        contact.last_rssi = obs.rssi
        contact.min_rssi = min(contact.min_rssi, obs.rssi)
        contact.max_rssi = max(contact.max_rssi, obs.rssi)
        
        # Incremental Mean Update
        n = contact.observation_count
        old_mean = contact.mean_rssi
        contact.mean_rssi = old_mean + (obs.rssi - old_mean) / n
        
        # Rolling RSSI History (keep last 20)
        contact.recent_rssi_history.append(obs.rssi)
        if len(contact.recent_rssi_history) > 20:
            contact.recent_rssi_history.pop(0)

        # Variance calculation
        if len(contact.recent_rssi_history) > 1:
            m = sum(contact.recent_rssi_history) / len(contact.recent_rssi_history)
            contact.rssi_variance = sum((x - m) ** 2 for x in contact.recent_rssi_history) / len(contact.recent_rssi_history)

        contact.rssi_trend = self._calculate_trend(contact.recent_rssi_history)
        contact.signal_category = self.get_signal_category(obs.rssi)

        # Check for sudden Signal Jump / Drop
        rssi_delta = abs(obs.rssi - prev_rssi)
        if rssi_delta >= self.jump_threshold:
            events.append(
                Event(
                    session_id=session_id,
                    timestamp=now,
                    event_type="SIGNAL_CHANGE",
                    severity=EventSeverity.INFO,
                    related_identifier=identifier,
                    related_contact_id=contact.contact_id,
                    message=f"Significant signal change ({obs.rssi - prev_rssi:+d} dBm) for {contact.ssid or identifier}",
                    evidence=[f"Previous: {prev_rssi} dBm", f"Current: {obs.rssi} dBm"],
                    data={"prev_rssi": prev_rssi, "current_rssi": obs.rssi, "delta": obs.rssi - prev_rssi},
                )
            )

        return contact, events

    def update_temporal_states(self, session_id: str) -> List[Event]:
        """
        Periodically evaluate contact states based on elapsed time without new observations.
        Transitions contacts to RECENT or STALE.
        """
        now = time.time()
        events: List[Event] = []

        for identifier, contact in self.contacts.items():
            age = now - contact.last_seen
            prev_state = contact.state

            if age > self.stale_window:
                if prev_state != ContactState.STALE:
                    contact.state = ContactState.STALE
                    events.append(
                        Event(
                            session_id=session_id,
                            timestamp=now,
                            event_type="CONTACT_STALE",
                            severity=EventSeverity.INFO,
                            related_identifier=identifier,
                            related_contact_id=contact.contact_id,
                            message=f"Contact became stale: {contact.ssid or contact.device_name or identifier}",
                            evidence=[f"Unseen for {int(age)}s"],
                            data={"age_seconds": round(age, 1)},
                        )
                    )
            elif age > self.active_window:
                if prev_state not in (ContactState.RECENT, ContactState.STALE):
                    contact.state = ContactState.RECENT
            elif (now - contact.first_seen) <= self.new_window:
                contact.state = ContactState.NEW
            else:
                contact.state = ContactState.ACTIVE

        return events

    def get_all_contacts(self) -> List[Contact]:
        """Return list of all current contacts."""
        return list(self.contacts.values())
