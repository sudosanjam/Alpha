"""
Configuration Manager for Alpha.

Handles user settings, persistent storage directories, power profiles,
and defaults with environment variable overrides.
"""

import os
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Any, Optional


def get_default_base_dir() -> Path:
    """Return default config directory (~/.config/alpha or Termux equivalent)."""
    custom = os.environ.get("ALPHA_CONFIG_DIR")
    if custom:
        return Path(custom).expanduser()
    return Path.home() / ".config" / "alpha"


def get_default_data_dir() -> Path:
    """Return default data directory (~/.local/share/alpha or Termux equivalent)."""
    custom = os.environ.get("ALPHA_DATA_DIR")
    if custom:
        return Path(custom).expanduser()
    return Path.home() / ".local" / "share" / "alpha"


@dataclass
class AlphaConfig:
    # Power & Scan Settings
    power_profile: str = "BALANCED"  # LOW_POWER, BALANCED, ACTIVE
    scan_interval_seconds: float = 5.0
    scan_timeout_seconds: float = 8.0
    
    # Temporal Correlation Windows (Seconds)
    new_window_seconds: float = 20.0
    active_window_seconds: float = 45.0
    stale_window_seconds: float = 120.0
    
    # RSSI Thresholds (dBm)
    rssi_strong_threshold: int = -60
    rssi_medium_threshold: int = -75
    rssi_weak_threshold: int = -85
    rssi_jump_threshold: int = 15  # Delta to trigger SIGNAL_CHANGE event
    
    # Alert Settings
    terminal_beep: bool = False
    vibrate_on_watchlist: bool = True
    notification_on_watchlist: bool = True
    vibrate_on_new_contact: bool = False
    alert_rate_limit_seconds: float = 5.0
    
    # UI & Visualization Settings
    theme: str = "cyberpunk"  # cyberpunk, matrix, high_contrast, plain
    ascii_only: bool = False
    ui_refresh_hz: int = 4
    default_view: str = "dashboard"  # dashboard, contacts, radar, analytics, events
    
    # Data Retention
    retention_days: int = 30
    auto_prune_on_startup: bool = False
    
    # Logging
    log_level: str = "INFO"  # DEBUG, INFO, WARNING, ERROR
    
    # Paths (managed at runtime)
    config_dir: str = field(default_factory=lambda: str(get_default_base_dir()))
    data_dir: str = field(default_factory=lambda: str(get_default_data_dir()))
    db_path: str = field(default_factory=lambda: str(get_default_data_dir() / "alpha.db"))
    log_file: str = field(default_factory=lambda: str(get_default_data_dir() / "logs" / "alpha.log"))

    def apply_power_profile(self, profile: str) -> None:
        """Apply pre-tuned parameters for power profiles."""
        p = profile.upper()
        if p == "LOW_POWER":
            self.power_profile = "LOW_POWER"
            self.scan_interval_seconds = 15.0
            self.ui_refresh_hz = 1
        elif p == "ACTIVE":
            self.power_profile = "ACTIVE"
            self.scan_interval_seconds = 2.0
            self.ui_refresh_hz = 5
        else:
            self.power_profile = "BALANCED"
            self.scan_interval_seconds = 5.0
            self.ui_refresh_hz = 4

    def ensure_directories(self) -> None:
        """Ensure config and data directories exist."""
        Path(self.config_dir).mkdir(parents=True, exist_ok=True)
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)
        Path(self.data_dir, "logs").mkdir(parents=True, exist_ok=True)

    def save(self, filepath: Optional[Path] = None) -> None:
        """Save configuration to JSON file."""
        if filepath is None:
            filepath = Path(self.config_dir) / "config.json"
        filepath.parent.mkdir(parents=True, exist_ok=True)
        data = asdict(self)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, filepath: Optional[Path] = None) -> "AlphaConfig":
        """Load configuration from JSON file or return defaults."""
        config = cls()
        if filepath is None:
            filepath = Path(config.config_dir) / "config.json"
        
        if filepath.exists():
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for k, v in data.items():
                    if hasattr(config, k):
                        setattr(config, k, v)
            except Exception:
                # Return defaults if malformed
                pass
        
        # Check environment overrides
        if os.environ.get("ALPHA_LOG_LEVEL"):
            config.log_level = os.environ["ALPHA_LOG_LEVEL"]
        if os.environ.get("ALPHA_ASCII_ONLY") == "1":
            config.ascii_only = True
            
        config.ensure_directories()
        return config
