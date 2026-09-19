"""
Heuristic Classification Engine for Alpha.

Applies transparent rule-based heuristic classification to wireless contacts,
assigning device categories, confidence scores, and structured evidence.
"""

from typing import List, Tuple, Optional
from alpha.models import Contact, DeviceCategory, SignalType
from alpha.signatures.rules import SignatureEngine, SignatureRule
from alpha.logger import get_logger

logger = get_logger("classification")


class HeuristicClassifier:
    """Classifies Contacts into functional device categories based on multi-indicator evidence."""

    def __init__(self, signature_engine: Optional[SignatureEngine] = None):
        self.signatures = signature_engine or SignatureEngine()

    def classify(self, contact: Contact) -> None:
        """
        Evaluate contact indicators and update contact.category, confidence,
        classification_reason, and evidence in-place.
        """
        evidence: List[str] = []
        category = DeviceCategory.UNKNOWN
        confidence = 0.0
        reason = "No matching heuristic patterns"

        # 1. Evaluate User / Built-in Signatures first (high specificity)
        sig_matches = self.signatures.evaluate(
            signal_type=contact.signal_type,
            oui=contact.oui,
            manufacturer=contact.manufacturer,
            ssid=contact.ssid,
            device_name=contact.device_name,
            capabilities=contact.capabilities
        )

        if sig_matches:
            best_rule, rule_evidence = max(sig_matches, key=lambda x: x[0].confidence)
            category = best_rule.category
            confidence = best_rule.confidence
            reason = f"Matched signature: {best_rule.name}"
            evidence.extend(rule_evidence)
            if best_rule.description:
                evidence.append(best_rule.description)

        # 2. General Wi-Fi Access Point / Infrastructure Heuristics
        elif contact.signal_type == SignalType.WIFI:
            vendor = contact.manufacturer.lower() if contact.manufacturer else ""
            
            # Router / AP Vendors
            if any(v in vendor for v in ["cisco", "ubiquiti", "aruba", "meraki"]):
                category = DeviceCategory.NETWORK_INFRASTRUCTURE
                confidence = 0.85
                reason = "Enterprise networking vendor"
                evidence.append(f"Enterprise manufacturer: {contact.manufacturer}")
            elif any(v in vendor for v in ["tp-link", "netgear", "d-link", "tenda", "asus", "linksys", "zyxel"]):
                category = DeviceCategory.ROUTER
                confidence = 0.80
                reason = "Consumer networking vendor"
                evidence.append(f"Consumer router manufacturer: {contact.manufacturer}")
            elif "espressif" in vendor or "tuya" in vendor:
                category = DeviceCategory.IOT
                confidence = 0.90
                reason = "IoT embedded Wi-Fi module"
                evidence.append(f"IoT vendor: {contact.manufacturer}")
            elif "raspberry" in vendor:
                category = DeviceCategory.COMPUTER
                confidence = 0.88
                reason = "Single-board computer Wi-Fi interface"
                evidence.append(f"Manufacturer: {contact.manufacturer}")
            elif contact.is_randomized_mac:
                category = DeviceCategory.MOBILE_DEVICE
                confidence = 0.65
                reason = "Locally Administered / Randomized MAC address"
                evidence.append("Randomized MAC indicates mobile client privacy feature")
            elif contact.ssid and contact.ssid != "[Hidden SSID]":
                category = DeviceCategory.ACCESS_POINT
                confidence = 0.50
                reason = "Broadcasting 802.11 SSID"
                evidence.append(f"SSID: '{contact.ssid}'")
            else:
                category = DeviceCategory.UNKNOWN
                confidence = 0.20
                reason = "Generic Wi-Fi broadcast with unknown vendor"
                evidence.append("No distinguishing manufacturer or SSID features")

        # 3. BLE Heuristics
        elif contact.signal_type == SignalType.BLE:
            vendor = contact.manufacturer.lower() if contact.manufacturer else ""
            name = (contact.device_name or "").lower()

            if any(k in name for k in ["watch", "fitbit", "garmin", "band", "ring"]):
                category = DeviceCategory.WEARABLE
                confidence = 0.85
                reason = "Wearable fitness or smartwatch device name"
                evidence.append(f"BLE name: {contact.device_name}")
            elif any(k in name for k in ["buds", "airpods", "headphone", "audio"]):
                category = DeviceCategory.WEARABLE
                confidence = 0.85
                reason = "Audio wearable device name"
                evidence.append(f"BLE name: {contact.device_name}")
            elif any(k in name for k in ["tile", "tag", "beacon", "tracker"]):
                category = DeviceCategory.PERIPHERAL
                confidence = 0.80
                reason = "Location beacon or tracker"
                evidence.append(f"BLE name: {contact.device_name}")
            elif "apple" in vendor or "samsung" in vendor or "google" in vendor:
                category = DeviceCategory.MOBILE_DEVICE
                confidence = 0.70
                reason = "Mobile manufacturer BLE advertisement"
                evidence.append(f"Vendor: {contact.manufacturer}")
            else:
                category = DeviceCategory.UNKNOWN
                confidence = 0.30
                reason = "Generic BLE advertisement without distinguishing signatures"
                evidence.append("Standard BLE advertisement payload")

        # Update contact
        contact.category = category
        contact.confidence = round(confidence, 2)
        contact.classification_reason = reason
        contact.evidence = evidence
