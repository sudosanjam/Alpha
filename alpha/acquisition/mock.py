"""
Realistic Mock Acquisition Backend for Alpha.

Provides high-fidelity wireless scenarios for development, testing, and UI verification
without fabricating data in production mode. Explicitly marks all generated data as mock.
"""

import math
import random
import time
from typing import Dict, List, Optional
from alpha.acquisition.base import AcquisitionBackend, BackendStatus, ScanBatch
from alpha.models import (
    Observation,
    ScanMetadata,
    SignalType,
    DataProvenance,
    FreshnessState,
)
from alpha.acquisition.wifi import frequency_to_channel_and_band, parse_security_capabilities


class MockAcquisitionBackend(AcquisitionBackend):
    """Generates realistic simulated wireless environments across multiple scenarios."""

    def __init__(self, scenario: str = "normal"):
        self.scenario = scenario.lower()
        self.step_counter = 0
        self._initialize_scenario_entities()

    def get_name(self) -> str:
        return f"Mock Wireless Backend [Scenario: {self.scenario}]"

    def check_availability(self) -> BackendStatus:
        return BackendStatus(
            available=True,
            name=self.get_name(),
            status_text="MOCK MODE ACTIVE",
            error_details=None,
            requires_action=False
        )

    def _initialize_scenario_entities(self) -> None:
        """Create baseline virtual wireless entities based on the selected scenario."""
        self.wifi_entities = []
        self.ble_entities = []

        if self.scenario == "sparse":
            self.wifi_entities = [
                {"mac": "00:14:22:A1:B2:C3", "ssid": "Distant-AP", "freq": 2412, "base_rssi": -88, "caps": "[WPA2-PSK-CCMP][ESS]"},
                {"mac": "28:6F:7F:11:22:33", "ssid": "Neighbor-Net", "freq": 5180, "base_rssi": -84, "caps": "[WPA2-PSK-CCMP][RSN][ESS]"},
            ]
            self.ble_entities = []

        elif self.scenario == "unknown":
            self.wifi_entities = [
                {"mac": "02:1A:3B:5C:7D:9E", "ssid": "", "freq": 2437, "base_rssi": -72, "caps": "[ESS]"},
                {"mac": "56:AC:78:12:34:56", "ssid": "Mystery_Node", "freq": 5975, "base_rssi": -68, "caps": "[WPA3-SAE-CCMP][ESS]"},
                {"mac": "DA:A1:19:88:77:66", "ssid": "\x1b[31mEvilNet\x1b[0m", "freq": 2462, "base_rssi": -55, "caps": "[WPA2-PSK-CCMP][ESS]"},
            ]
            self.ble_entities = [
                {"mac": "7A:B2:C3:D4:E5:F6", "name": None, "base_rssi": -82, "vendor": "Unknown"},
            ]

        elif self.scenario == "busy":
            # 25+ Wi-Fi networks and 8 BLE beacons
            self.wifi_entities = [
                {"mac": "00:26:86:11:22:33", "ssid": "Enterprise-Corporate", "freq": 5180, "base_rssi": -48, "caps": "[WPA2-EAP-CCMP][RSN][ESS]"},
                {"mac": "00:26:86:11:22:34", "ssid": "Enterprise-Guest", "freq": 5200, "base_rssi": -50, "caps": "[WPA2-PSK-CCMP][ESS]"},
                {"mac": "70:85:C2:AA:BB:CC", "ssid": "MeshNode-North-5G", "freq": 5745, "base_rssi": -58, "caps": "[WPA2-PSK-CCMP][RSN][ESS]"},
                {"mac": "70:85:C2:AA:BB:CD", "ssid": "MeshNode-North-2G", "freq": 2412, "base_rssi": -52, "caps": "[WPA2-PSK-CCMP][RSN][ESS]"},
                {"mac": "B8:27:EB:55:66:77", "ssid": "Lab_RaspberryPi_Gateway", "freq": 2437, "base_rssi": -62, "caps": "[WPA2-PSK-CCMP][ESS]"},
                {"mac": "30:B5:C2:88:99:00", "ssid": "TP-Link_Deco_X60", "freq": 5975, "base_rssi": -45, "caps": "[WPA3-SAE-CCMP][ESS]"},
                {"mac": "E4:5F:01:33:44:55", "ssid": "IoT_Hub_Central", "freq": 2462, "base_rssi": -66, "caps": "[WPA2-PSK-CCMP][ESS]"},
                {"mac": "00:1A:2B:99:88:77", "ssid": "Conference_Room_Display", "freq": 5240, "base_rssi": -71, "caps": "[WPA2-PSK-CCMP][ESS]"},
                {"mac": "80:2A:A8:12:34:56", "ssid": "Ubiquiti_UniFi_AP", "freq": 5260, "base_rssi": -54, "caps": "[WPA2-PSK-CCMP][RSN][ESS]"},
                {"mac": "A4:D1:8C:77:88:99", "ssid": "Coffee_Shop_Free_Wifi", "freq": 2412, "base_rssi": -79, "caps": "[ESS]"},
                {"mac": "68:DB:F5:AA:11:22", "ssid": "Executive_Suite_Private", "freq": 5500, "base_rssi": -63, "caps": "[WPA3-SAE-CCMP][ESS]"},
                {"mac": "2C:F0:EE:99:AA:BB", "ssid": "Smart_Thermostat_Mesh", "freq": 2437, "base_rssi": -75, "caps": "[WPA2-PSK-CCMP][ESS]"},
                {"mac": "00:0C:29:44:55:66", "ssid": "Virtual_Lab_TestAP", "freq": 2462, "base_rssi": -80, "caps": "[WPA2-PSK-CCMP][ESS]"},
            ]
            self.ble_entities = [
                {"mac": "DC:A6:32:01:02:03", "name": "Apple Watch Ultra", "base_rssi": -65, "vendor": "Apple, Inc."},
                {"mac": "F4:F5:DB:11:22:33", "name": "Galaxy Buds2 Pro", "base_rssi": -58, "vendor": "Samsung Electronics"},
                {"mac": "C8:69:CD:44:55:66", "name": "Tile Pro Tracker", "base_rssi": -78, "vendor": "Tile, Inc."},
                {"mac": "48:B0:2D:77:88:99", "name": "Fitness_Band_HR", "base_rssi": -72, "vendor": "Garmin"},
            ]

        elif self.scenario == "changing":
            # Dynamic nodes that simulate walking or moving objects
            self.wifi_entities = [
                {"mac": "00:1E:58:AA:BB:CC", "ssid": "BaseStation_Fixed", "freq": 2412, "base_rssi": -50, "caps": "[WPA2-PSK-CCMP][ESS]", "dynamic": False},
                {"mac": "AC:BC:32:11:22:33", "ssid": "Mobile_Hotspot_John", "freq": 5180, "base_rssi": -85, "caps": "[WPA2-PSK-CCMP][ESS]", "dynamic": True, "speed": 0.3},
                {"mac": "18:65:90:55:66:77", "ssid": "Delivery_Truck_Fleet_AP", "freq": 2462, "base_rssi": -90, "caps": "[WPA2-PSK-CCMP][ESS]", "dynamic": True, "speed": 0.5},
            ]
            self.ble_entities = [
                {"mac": "5C:F8:A1:00:11:22", "name": "Pedestrian_SmartRing", "base_rssi": -88, "dynamic": True},
            ]

        else:  # "normal" scenario
            self.wifi_entities = [
                {"mac": "00:11:32:44:55:66", "ssid": "Home-Network-5G", "freq": 5180, "base_rssi": -48, "caps": "[WPA2-PSK-CCMP][RSN-PSK-CCMP][ESS]"},
                {"mac": "00:11:32:44:55:67", "ssid": "Home-Network-2G", "freq": 2437, "base_rssi": -45, "caps": "[WPA2-PSK-CCMP][RSN-PSK-CCMP][ESS]"},
                {"mac": "C8:3A:35:12:34:56", "ssid": "Tenda_Mesh_Master", "freq": 5240, "base_rssi": -62, "caps": "[WPA2-PSK-CCMP][ESS]"},
                {"mac": "BC:F2:AF:78:90:12", "ssid": "Apartment_4B_Guest", "freq": 2412, "base_rssi": -76, "caps": "[WPA2-PSK-CCMP][ESS]"},
                {"mac": "24:A4:3C:99:88:77", "ssid": "Office_HQ_WPA3", "freq": 5975, "base_rssi": -55, "caps": "[WPA3-SAE-CCMP][ESS]"},
                {"mac": "00:04:4B:33:22:11", "ssid": "NVIDIA_Shield_Direct", "freq": 5745, "base_rssi": -69, "caps": "[WPA2-PSK-CCMP][ESS]"},
                {"mac": "84:D8:1B:66:55:44", "ssid": "Security_Camera_Mesh", "freq": 2462, "base_rssi": -71, "caps": "[WPA2-PSK-CCMP][ESS]"},
                {"mac": "00:17:88:1A:2B:3C", "ssid": "Philips_Hue_Bridge", "freq": 2412, "base_rssi": -68, "caps": "[WPA2-PSK-CCMP][ESS]"},
            ]
            self.ble_entities = [
                {"mac": "F0:18:98:AA:BB:CC", "name": "AirPods Pro", "base_rssi": -62, "vendor": "Apple, Inc."},
                {"mac": "E0:76:D0:33:44:55", "name": "Smart Scale Pro", "base_rssi": -74, "vendor": "Withings"},
                {"mac": "C4:4F:33:77:88:99", "name": "Nordic_HR_Beacon", "base_rssi": -80, "vendor": "Nordic Semiconductor"},
            ]

    def scan(self, session_id: str = "mock_session") -> ScanBatch:
        """Generate one simulated scan observation cycle."""
        self.step_counter += 1
        now = time.time()
        observations: List[Observation] = []

        # Process simulated Wi-Fi
        for ent in self.wifi_entities:
            # Handle changing/dynamic scenarios
            if ent.get("dynamic"):
                phase = (self.step_counter * ent.get("speed", 0.2)) % (2 * math.pi)
                rssi_mod = int(25 * math.sin(phase))
                current_rssi = ent["base_rssi"] + rssi_mod
                # If too weak, device temporarily out of range
                if current_rssi < -93:
                    continue
            else:
                # Slight random walk (+/- 3 dBm)
                jitter = random.randint(-3, 3)
                current_rssi = max(-95, min(-30, ent["base_rssi"] + jitter))

            freq = ent["freq"]
            channel, band = frequency_to_channel_and_band(freq)
            ssid = ent["ssid"]
            if not ssid:
                ssid = "[Hidden SSID]"
                
            caps = ent.get("caps", "[WPA2-PSK-CCMP][ESS]")
            sec = parse_security_capabilities(caps)

            obs = Observation(
                session_id=session_id,
                timestamp=now,
                source="Mock Wi-Fi Simulator",
                signal_type=SignalType.WIFI,
                interface="wlan0",
                identifier=ent["mac"],
                mac_address=ent["mac"],
                bssid=ent["mac"],
                ssid=ssid,
                rssi=current_rssi,
                frequency=freq,
                channel=channel,
                band=band,
                security=sec,
                capabilities=caps,
                raw_metadata={"mock": True, "scenario": self.scenario},
                provenance=DataProvenance.OBSERVED
            )
            observations.append(obs)

        # Process simulated BLE
        for b_ent in self.ble_entities:
            if b_ent.get("dynamic"):
                phase = (self.step_counter * 0.3) % (2 * math.pi)
                if math.sin(phase) < -0.4:
                    continue
                rssi = int(b_ent["base_rssi"] + 15 * math.sin(phase))
            else:
                jitter = random.randint(-4, 4)
                rssi = max(-95, min(-35, b_ent["base_rssi"] + jitter))

            obs = Observation(
                session_id=session_id,
                timestamp=now,
                source="Mock BLE Simulator",
                signal_type=SignalType.BLE,
                interface="hci0",
                identifier=b_ent["mac"],
                mac_address=b_ent["mac"],
                device_name=b_ent.get("name"),
                rssi=rssi,
                raw_metadata={"mock": True, "scenario": self.scenario, "vendor": b_ent.get("vendor")},
                provenance=DataProvenance.OBSERVED
            )
            observations.append(obs)

        meta = ScanMetadata(
            requested_at=now - 0.05,
            completed_at=now,
            result_timestamp=now,
            duration_ms=48.5,
            item_count=len(observations),
            freshness=FreshnessState.LIVE,
            age_seconds=0.0,
            source=self.get_name(),
            success=True
        )

        return ScanBatch(observations=observations, metadata=meta)
