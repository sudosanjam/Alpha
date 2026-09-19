"""
Watchlist Subsystem for Alpha.

Allows tracking specific wireless targets (by MAC, OUI, Vendor, SSID, Device Name, or Category)
and generates informational non-malicious notification events.
"""

import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from alpha.models import Contact, Event, EventSeverity
from alpha.sanitizer import sanitize_mac
from alpha.logger import get_logger

logger = get_logger("watchlist")


@dataclass
class WatchlistRule:
    rule_id: str
    target_type: str  # MAC, OUI, MANUFACTURER, SSID, DEVICE_NAME, CATEGORY
    pattern: str
    label: str
    severity: EventSeverity = EventSeverity.NOTICE
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


class WatchlistEngine:
    """Evaluates contacts against configured watchlist rules."""

    def __init__(self, config_file: Optional[Path] = None):
        self.config_file = config_file
        self.rules: List[WatchlistRule] = []
        self._compiled_regexes: Dict[str, re.Pattern] = {}
        if self.config_file and self.config_file.exists():
            self.load()

    def add_rule(self, rule: WatchlistRule) -> None:
        """Add a watchlist rule and recompile pattern."""
        self.rules.append(rule)
        self._compile_rule(rule)
        self.save()

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a watchlist rule by ID."""
        initial_len = len(self.rules)
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        if rule_id in self._compiled_regexes:
            del self._compiled_regexes[rule_id]
        self.save()
        return len(self.rules) < initial_len

    def _compile_rule(self, rule: WatchlistRule) -> None:
        """Compile regex pattern for a rule."""
        try:
            self._compiled_regexes[rule.rule_id] = re.compile(rule.pattern, re.IGNORECASE)
        except Exception as ex:
            logger.warning(f"Failed to compile pattern '{rule.pattern}': {ex}")

    def load(self) -> None:
        """Load watchlist rules from JSON file."""
        if not self.config_file or not self.config_file.exists():
            return
        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.rules = []
            for item in data:
                rule = WatchlistRule(
                    rule_id=item["rule_id"],
                    target_type=item["target_type"].upper(),
                    pattern=item["pattern"],
                    label=item["label"],
                    severity=EventSeverity(item.get("severity", "NOTICE")),
                    enabled=item.get("enabled", True),
                )
                self.rules.append(rule)
                self._compile_rule(rule)
        except Exception as ex:
            logger.error(f"Error loading watchlist from {self.config_file}: {ex}")

    def save(self) -> None:
        """Persist watchlist rules to JSON file."""
        if not self.config_file:
            return
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump([r.to_dict() for r in self.rules], f, indent=2)
        except Exception as ex:
            logger.error(f"Error saving watchlist: {ex}")

    def evaluate(self, contact: Contact, session_id: str) -> List[Event]:
        """
        Evaluate a contact against watchlist rules.
        If matched, marks contact and returns WATCHLIST_MATCH events.
        """
        events: List[Event] = []
        is_match = False
        matched_labels = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            pattern_re = self._compiled_regexes.get(rule.rule_id)
            target_type = rule.target_type

            matched = False
            evidence_desc = ""

            if target_type == "MAC":
                norm_target = sanitize_mac(rule.pattern)
                if contact.mac_address.upper() == norm_target.upper():
                    matched = True
                    evidence_desc = f"MAC address exact match: {contact.mac_address}"
            elif target_type == "OUI":
                if contact.oui.upper().startswith(rule.pattern.upper()):
                    matched = True
                    evidence_desc = f"OUI prefix match: {contact.oui}"
            elif target_type == "MANUFACTURER" and pattern_re:
                if contact.manufacturer and pattern_re.search(contact.manufacturer):
                    matched = True
                    evidence_desc = f"Manufacturer pattern matched: {contact.manufacturer}"
            elif target_type == "SSID" and pattern_re:
                if contact.ssid and pattern_re.search(contact.ssid):
                    matched = True
                    evidence_desc = f"SSID pattern matched: {contact.ssid}"
            elif target_type == "DEVICE_NAME" and pattern_re:
                if contact.device_name and pattern_re.search(contact.device_name):
                    matched = True
                    evidence_desc = f"Device name pattern matched: {contact.device_name}"
            elif target_type == "CATEGORY":
                if contact.category.value.upper() == rule.pattern.upper():
                    matched = True
                    evidence_desc = f"Category match: {contact.category.value}"

            if matched:
                is_match = True
                matched_labels.append(rule.label)
                events.append(
                    Event(
                        session_id=session_id,
                        event_type="WATCHLIST_MATCH",
                        severity=rule.severity,
                        related_identifier=contact.identifier,
                        related_contact_id=contact.contact_id,
                        message=f"Watchlist matched '{rule.label}': {contact.ssid or contact.device_name or contact.identifier}",
                        evidence=[evidence_desc, f"Signal RSSI: {contact.last_rssi} dBm"],
                        data={"rule_id": rule.rule_id, "label": rule.label},
                    )
                )

        if is_match:
            contact.is_watchlist_match = True
            for lbl in matched_labels:
                if lbl not in contact.watchlist_tags:
                    contact.watchlist_tags.append(lbl)

        return events
