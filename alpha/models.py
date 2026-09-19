"""
Data Models and Data Structures for Alpha.

Defines all core schemas with strong typing, immutability where appropriate,
serialization methods, and clear distinction between OBSERVED, DERIVED, and HEURISTIC data.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
import json
import time
import uuid
from typing import Dict, List, Optional, Any


class DataProvenance(str, Enum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    HEURISTIC = "HEURISTIC"


class SignalType(str, Enum):
    WIFI = "WIFI"
    BLE = "BLE"
    UNKNOWN = "UNKNOWN"


class ContactState(str, Enum):
    NEW = "NEW"
    ACTIVE = "ACTIVE"
    RECENT = "RECENT"
    STALE = "STALE"


class SignalCategory(str, Enum):
    STRONG = "STRONG"        # > -60 dBm
    MEDIUM = "MEDIUM"        # -60 to -75 dBm
    WEAK = "WEAK"            # -75 to -85 dBm
    VERY_WEAK = "VERY_WEAK"  # < -85 dBm
    UNKNOWN = "UNKNOWN"


class DeviceCategory(str, Enum):
    UNKNOWN = "UNKNOWN"
    CONSUMER = "CONSUMER"
    MOBILE_DEVICE = "MOBILE_DEVICE"
    ACCESS_POINT = "ACCESS_POINT"
    ROUTER = "ROUTER"
    NETWORK_INFRASTRUCTURE = "NETWORK_INFRASTRUCTURE"
    IOT = "IOT"
    COMMERCIAL_HARDWARE = "COMMERCIAL_HARDWARE"
    COMPUTER = "COMPUTER"
    PERIPHERAL = "PERIPHERAL"
    WEARABLE = "WEARABLE"
    OTHER = "OTHER"


class FreshnessState(str, Enum):
    LIVE = "LIVE"
    CACHED = "CACHED"
    STALE = "STALE"
    THROTTLED = "THROTTLED"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


class EventSeverity(str, Enum):
    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    ALERT = "ALERT"


@dataclass
class ScanMetadata:
    requested_at: float = field(default_factory=time.time)
    completed_at: float = field(default_factory=time.time)
    result_timestamp: Optional[float] = None
    duration_ms: float = 0.0
    item_count: int = 0
    freshness: FreshnessState = FreshnessState.UNKNOWN
    age_seconds: float = 0.0
    source: str = "unknown"
    success: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requested_at": self.requested_at,
            "completed_at": self.completed_at,
            "result_timestamp": self.result_timestamp,
            "duration_ms": round(self.duration_ms, 2),
            "item_count": self.item_count,
            "freshness": self.freshness.value,
            "age_seconds": round(self.age_seconds, 2),
            "source": self.source,
            "success": self.success,
            "error_message": self.error_message,
        }


@dataclass
class Observation:
    observation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = "default"
    timestamp: float = field(default_factory=time.time)
    source: str = "termux_wifi"
    signal_type: SignalType = SignalType.WIFI
    interface: str = "wlan0"
    identifier: str = "00:00:00:00:00:00"  # MAC or BLE Address
    mac_address: str = "00:00:00:00:00:00"
    ssid: Optional[str] = None
    bssid: Optional[str] = None
    device_name: Optional[str] = None
    rssi: int = -99
    frequency: Optional[int] = None
    channel: Optional[int] = None
    band: Optional[str] = None  # 2.4 GHz, 5 GHz, 6 GHz
    security: str = "UNKNOWN"
    capabilities: str = ""
    manufacturer: str = "UNKNOWN"
    oui: str = "UNKNOWN"
    raw_metadata: Dict[str, Any] = field(default_factory=dict)
    scan_age_seconds: float = 0.0
    is_cached: bool = False
    provenance: DataProvenance = DataProvenance.OBSERVED

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["signal_type"] = self.signal_type.value
        d["provenance"] = self.provenance.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Observation":
        copied = dict(data)
        if "signal_type" in copied and isinstance(copied["signal_type"], str):
            copied["signal_type"] = SignalType(copied["signal_type"])
        if "provenance" in copied and isinstance(copied["provenance"], str):
            copied["provenance"] = DataProvenance(copied["provenance"])
        return cls(**copied)


@dataclass
class Contact:
    contact_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = "default"
    signal_type: SignalType = SignalType.WIFI
    identifier: str = "00:00:00:00:00:00"
    mac_address: str = "00:00:00:00:00:00"
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    device_name: Optional[str] = None
    manufacturer: str = "UNKNOWN"
    oui: str = "UNKNOWN"
    is_randomized_mac: bool = False
    category: DeviceCategory = DeviceCategory.UNKNOWN
    confidence: float = 0.0
    classification_reason: str = "Unclassified"
    evidence: List[str] = field(default_factory=list)
    state: ContactState = ContactState.NEW
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    observation_count: int = 1
    last_rssi: int = -99
    min_rssi: int = -99
    max_rssi: int = -99
    mean_rssi: float = -99.0
    rssi_variance: float = 0.0
    rssi_trend: str = "STEADY"  # RISING, FALLING, STEADY
    signal_category: SignalCategory = SignalCategory.UNKNOWN
    channel: Optional[int] = None
    frequency: Optional[int] = None
    band: Optional[str] = None
    security: str = "UNKNOWN"
    capabilities: str = ""
    is_watchlist_match: bool = False
    watchlist_tags: List[str] = field(default_factory=list)
    recent_rssi_history: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["signal_type"] = self.signal_type.value
        d["category"] = self.category.value
        d["state"] = self.state.value
        d["signal_category"] = self.signal_category.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Contact":
        copied = dict(data)
        if "signal_type" in copied and isinstance(copied["signal_type"], str):
            copied["signal_type"] = SignalType(copied["signal_type"])
        if "category" in copied and isinstance(copied["category"], str):
            copied["category"] = DeviceCategory(copied["category"])
        if "state" in copied and isinstance(copied["state"], str):
            copied["state"] = ContactState(copied["state"])
        if "signal_category" in copied and isinstance(copied["signal_category"], str):
            copied["signal_category"] = SignalCategory(copied["signal_category"])
        return cls(**copied)


@dataclass
class Event:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = "default"
    timestamp: float = field(default_factory=time.time)
    event_type: str = "NEW_CONTACT"
    severity: EventSeverity = EventSeverity.INFO
    related_identifier: str = ""
    related_contact_id: Optional[str] = None
    message: str = ""
    evidence: List[str] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class BaselineSnapshot:
    baseline_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "default_baseline"
    created_at: float = field(default_factory=time.time)
    duration_seconds: float = 0.0
    observation_count: int = 0
    contact_count: int = 0
    wifi_count: int = 0
    ble_count: int = 0
    channel_distribution: Dict[str, int] = field(default_factory=dict)
    manufacturer_distribution: Dict[str, int] = field(default_factory=dict)
    security_distribution: Dict[str, int] = field(default_factory=dict)
    mean_rssi: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Session:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: float = field(default_factory=time.time)
    ended_at: Optional[float] = None
    device_model: str = "Unknown"
    android_version: str = "Unknown"
    termux_version: str = "Unknown"
    alpha_version: str = "1.0.0"
    is_mock: bool = False
    scenario: str = "production"
    observation_count: int = 0
    contact_count: int = 0
    event_count: int = 0
    status: str = "RUNNING"  # RUNNING, COMPLETED, INTERRUPTED

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CapabilityMatrix:
    wifi_scan: bool = False
    wifi_connection_info: bool = False
    wifi_raw_frames: bool = False
    wifi_monitor_mode: bool = False
    ble_scan: bool = False
    ble_raw_capture: bool = False
    termux_api_available: bool = False
    location_permission_granted: bool = False
    location_service_enabled: bool = False
    vibration_supported: bool = False
    notifications_supported: bool = False
    sqlite_wal_supported: bool = True
    terminal_colors_256: bool = True
    unicode_supported: bool = True
    root_available: bool = False

    def to_dict(self) -> Dict[str, bool]:
        return asdict(self)
