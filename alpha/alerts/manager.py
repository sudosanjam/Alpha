"""
Alerts Manager Subsystem for Alpha.

Dispatches non-blocking notifications across terminal, Termux notifications,
and device vibrations with strict rate-limiting to prevent alert storms.
"""

import shutil
import subprocess
import sys
import time
from typing import Dict, Optional
from alpha.models import Event, EventSeverity
from alpha.sanitizer import sanitize_string
from alpha.logger import get_logger

logger = get_logger("alerts")


class AlertManager:
    """Manages multi-channel alerts with rate limiting."""

    def __init__(
        self,
        enable_beep: bool = False,
        enable_vibrate: bool = True,
        enable_notification: bool = True,
        rate_limit_seconds: float = 5.0,
    ):
        self.enable_beep = enable_beep
        self.enable_vibrate = enable_vibrate
        self.enable_notification = enable_notification
        self.rate_limit_seconds = rate_limit_seconds
        self.last_alert_time: Dict[str, float] = {}

    def dispatch(self, event: Event) -> None:
        """Dispatch event alert if rate limit allows and severity matches."""
        now = time.time()
        key = f"{event.event_type}:{event.related_identifier}"
        
        last = self.last_alert_time.get(key, 0.0)
        if (now - last) < self.rate_limit_seconds:
            return  # Rate limited

        self.last_alert_time[key] = now

        # Only trigger physical alerts for NOTICE, WARNING, ALERT
        if event.severity not in (EventSeverity.NOTICE, EventSeverity.WARNING, EventSeverity.ALERT):
            return

        # Terminal Beep
        if self.enable_beep:
            try:
                sys.stdout.write("\a")
                sys.stdout.flush()
            except Exception:
                pass

        clean_msg = sanitize_string(event.message, fallback="Wireless Alert")
        clean_title = f"ALPHA: {event.event_type}"

        # Termux Vibration
        if self.enable_vibrate and shutil.which("termux-vibrate"):
            try:
                subprocess.Popen(
                    ["termux-vibrate", "-d", "250"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception as ex:
                logger.debug(f"Failed to trigger vibration: {ex}")

        # Termux Notification
        if self.enable_notification and shutil.which("termux-notification"):
            try:
                subprocess.Popen(
                    [
                        "termux-notification",
                        "--title", clean_title,
                        "--content", clean_msg,
                        "--id", "alpha_alert"
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception as ex:
                logger.debug(f"Failed to trigger notification: {ex}")
