"""
Signature Rules Subsystem for Alpha.

Provides user-customizable, file-based heuristic signature matching for identifying
wireless device categories, manufacturers, and hardware types without code changes.
"""

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from alpha.models import DeviceCategory, SignalType
from alpha.logger import get_logger

logger = get_logger("signatures")


@dataclass
class SignatureRule:
    rule_id: str
    name: str
    category: DeviceCategory
    confidence: float = 0.8
    oui_prefix: Optional[str] = None
    manufacturer_regex: Optional[str] = None
    ssid_regex: Optional[str] = None
    device_name_regex: Optional[str] = None
    capabilities_regex: Optional[str] = None
    signal_type: Optional[SignalType] = None
    description: str = ""
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["signal_type"] = self.signal_type.value if self.signal_type else None
        return d


DEFAULT_SIGNATURES: List[SignatureRule] = [
    # Mobile Wearables & Peripherals
    SignatureRule(
        rule_id="sig_wearable_buds",
        name="Wireless Earbuds / Audio",
        category=DeviceCategory.WEARABLE,
        confidence=0.88,
        device_name_regex=r"(?i)(airpods|buds|earphone|headphone|wh-1000|wf-1000|bose|soundcore)",
        description="Personal audio wearables matched by device name"
    ),
    SignatureRule(
        rule_id="sig_wearable_watch",
        name="Smart Watch / Fitness Tracker",
        category=DeviceCategory.WEARABLE,
        confidence=0.90,
        device_name_regex=r"(?i)(watch|garmin|fitbit|smartband|band\s*[0-9]|ring|polar)",
        description="Wearable fitness and watch devices"
    ),
    SignatureRule(
        rule_id="sig_ble_tracker",
        name="BLE Asset Tracker / Beacon",
        category=DeviceCategory.PERIPHERAL,
        confidence=0.85,
        device_name_regex=r"(?i)(tile|airtag|smarttag|beacon|itag)",
        description="Personal location beacon or tracker"
    ),

    # Smart Home / IoT
    SignatureRule(
        rule_id="sig_iot_espressif",
        name="Espressif IoT Node (ESP32/ESP8266)",
        category=DeviceCategory.IOT,
        confidence=0.92,
        manufacturer_regex=r"(?i)Espressif",
        description="Common Wi-Fi microcontroller used in smart bulbs, plugs, and sensors"
    ),
    SignatureRule(
        rule_id="sig_iot_tuya",
        name="Tuya Smart Home Device",
        category=DeviceCategory.IOT,
        confidence=0.90,
        manufacturer_regex=r"(?i)Tuya",
        description="Smart switch, plug, or home automation module"
    ),
    SignatureRule(
        rule_id="sig_iot_hue",
        name="Philips Hue Bridge / Smart Lighting",
        category=DeviceCategory.IOT,
        confidence=0.92,
        manufacturer_regex=r"(?i)Philips.*Lighting",
        description="Connected lighting bridge or luminaire"
    ),
    SignatureRule(
        rule_id="sig_iot_camera",
        name="Security Camera / Video Node",
        category=DeviceCategory.IOT,
        confidence=0.80,
        ssid_regex=r"(?i)(cam|camera|cctv|ipc|doorbell|ring|reolink|wyze)",
        description="Wireless IP camera or smart doorbell"
    ),
    SignatureRule(
        rule_id="sig_iot_printer",
        name="Wireless Printer / MFD",
        category=DeviceCategory.PERIPHERAL,
        confidence=0.85,
        ssid_regex=r"(?i)(direct-.*(hp|epson|canon|brother|xerox)|hp-print|epson_)",
        description="Direct Wi-Fi printer broadcast"
    ),

    # Network Infrastructure & Access Points
    SignatureRule(
        rule_id="sig_ap_enterprise_mesh",
        name="Enterprise Access Point (802.1X / Mesh)",
        category=DeviceCategory.NETWORK_INFRASTRUCTURE,
        confidence=0.90,
        capabilities_regex=r"(?i)(EAP|802\.1X)",
        description="Enterprise Wi-Fi network infrastructure with 802.1X RADIUS"
    ),
    SignatureRule(
        rule_id="sig_ap_ubiquiti",
        name="Ubiquiti UniFi Infrastructure",
        category=DeviceCategory.NETWORK_INFRASTRUCTURE,
        confidence=0.90,
        manufacturer_regex=r"(?i)Ubiquiti",
        description="Enterprise / prosumer networking hardware"
    ),
    SignatureRule(
        rule_id="sig_ap_cisco",
        name="Cisco / Meraki Network Node",
        category=DeviceCategory.NETWORK_INFRASTRUCTURE,
        confidence=0.88,
        manufacturer_regex=r"(?i)Cisco",
        description="Commercial routing and wireless access point hardware"
    ),
    SignatureRule(
        rule_id="sig_ap_aruba",
        name="Aruba Enterprise AP",
        category=DeviceCategory.NETWORK_INFRASTRUCTURE,
        confidence=0.90,
        manufacturer_regex=r"(?i)Aruba",
        description="Enterprise wireless controller and access points"
    ),
    SignatureRule(
        rule_id="sig_ap_consumer_router",
        name="Consumer Wi-Fi Router",
        category=DeviceCategory.ROUTER,
        confidence=0.80,
        manufacturer_regex=r"(?i)(TP-Link|Netgear|D-Link|Tenda|Asus|Linksys|Zyxel)",
        signal_type=SignalType.WIFI,
        description="Standard consumer wireless gateway/router"
    ),

    # Single Board Computers & Mobile
    SignatureRule(
        rule_id="sig_sbc_rpi",
        name="Raspberry Pi SBC",
        category=DeviceCategory.COMPUTER,
        confidence=0.90,
        manufacturer_regex=r"(?i)Raspberry Pi",
        description="Single board computer gateway or embedded project"
    ),
    SignatureRule(
        rule_id="sig_mobile_hotspot",
        name="Mobile Device Wi-Fi Hotspot",
        category=DeviceCategory.MOBILE_DEVICE,
        confidence=0.75,
        ssid_regex=r"(?i)(iphone|galaxy|pixel|redmi|oneplus|androidap|portable\s*hotspot|huawei)",
        description="Personal mobile phone tethering hotspot"
    ),
]


class SignatureEngine:
    """Loads, manages, and executes signature rules against contacts."""

    def __init__(self, config_file: Optional[Path] = None):
        self.config_file = config_file
        self.rules: List[SignatureRule] = list(DEFAULT_SIGNATURES)
        self._compiled_regexes: Dict[str, Dict[str, re.Pattern]] = {}
        self._compile_rules()
        if self.config_file and self.config_file.exists():
            self._load_custom_rules()

    def _compile_rules(self) -> None:
        """Pre-compile regex patterns for performance."""
        for rule in self.rules:
            comp: Dict[str, re.Pattern] = {}
            if rule.manufacturer_regex:
                comp["manufacturer"] = re.compile(rule.manufacturer_regex)
            if rule.ssid_regex:
                comp["ssid"] = re.compile(rule.ssid_regex)
            if rule.device_name_regex:
                comp["device_name"] = re.compile(rule.device_name_regex)
            if rule.capabilities_regex:
                comp["capabilities"] = re.compile(rule.capabilities_regex)
            self._compiled_regexes[rule.rule_id] = comp

    def _load_custom_rules(self) -> None:
        """Load user signature overrides from JSON."""
        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                custom_data = json.load(f)
            for item in custom_data:
                rule = SignatureRule(
                    rule_id=item["rule_id"],
                    name=item["name"],
                    category=DeviceCategory(item["category"]),
                    confidence=float(item.get("confidence", 0.8)),
                    oui_prefix=item.get("oui_prefix"),
                    manufacturer_regex=item.get("manufacturer_regex"),
                    ssid_regex=item.get("ssid_regex"),
                    device_name_regex=item.get("device_name_regex"),
                    capabilities_regex=item.get("capabilities_regex"),
                    signal_type=SignalType(item["signal_type"]) if item.get("signal_type") else None,
                    description=item.get("description", ""),
                    enabled=item.get("enabled", True),
                )
                self.rules.append(rule)
            self._compile_rules()
        except Exception as ex:
            logger.warning(f"Failed loading custom signatures: {ex}")

    def evaluate(
        self,
        signal_type: SignalType,
        oui: str,
        manufacturer: str,
        ssid: Optional[str],
        device_name: Optional[str],
        capabilities: str
    ) -> List[Tuple[SignatureRule, List[str]]]:
        """
        Evaluate rules against metadata.
        Returns a list of matching (SignatureRule, evidence_list).
        """
        matches = []
        for rule in self.rules:
            if not rule.enabled:
                continue

            # Signal type check
            if rule.signal_type and rule.signal_type != signal_type:
                continue

            # OUI check
            evidence: List[str] = []
            if rule.oui_prefix:
                if oui.upper().startswith(rule.oui_prefix.upper()):
                    evidence.append(f"OUI matched prefix '{rule.oui_prefix}'")
                else:
                    continue

            compiled = self._compiled_regexes.get(rule.rule_id, {})

            # Manufacturer regex check
            if "manufacturer" in compiled:
                if manufacturer and compiled["manufacturer"].search(manufacturer):
                    evidence.append(f"Manufacturer matched pattern: '{rule.manufacturer_regex}'")
                else:
                    continue

            # SSID regex check
            if "ssid" in compiled:
                if ssid and compiled["ssid"].search(ssid):
                    evidence.append(f"SSID matched pattern: '{rule.ssid_regex}'")
                else:
                    continue

            # Device name regex check
            if "device_name" in compiled:
                if device_name and compiled["device_name"].search(device_name):
                    evidence.append(f"Device name matched pattern: '{rule.device_name_regex}'")
                else:
                    continue

            # Capabilities regex check
            if "capabilities" in compiled:
                if capabilities and compiled["capabilities"].search(capabilities):
                    evidence.append(f"Capabilities matched pattern: '{rule.capabilities_regex}'")
                else:
                    continue

            if evidence:
                matches.append((rule, evidence))

        return matches
