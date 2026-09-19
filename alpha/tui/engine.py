"""
Terminal UI Engine for Alpha.

Provides flicker-free, responsive ANSI rendering supporting compact phone screens
(50-60 cols), standard terminals (80 cols), and wide screens (100+ cols), with full
keyboard navigation and NO_COLOR/ASCII fallback.
"""

import os
import shutil
import sys
import time
from typing import Dict, List, Optional, Any, Callable

from alpha.models import (
    Session,
    Contact,
    Event,
    Observation,
    ContactState,
    SignalType,
    DeviceCategory,
    FreshnessState,
)
from alpha.sanitizer import sanitize_string, strip_ansi, visible_length
from alpha.radar.radar import TerminalRadar
from alpha.analytics.engine import AnalyticsEngine
from alpha.diagnostics import EnvironmentInspector


def _supports_unicode() -> bool:
    try:
        "│─┼·●♦○■".encode(sys.stdout.encoding or "ascii")
        return True
    except Exception:
        return False


class TerminalUI:
    """Responsive Terminal User Interface for Alpha Wireless Platform."""

    def __init__(
        self,
        session: Session,
        config: Any,
        ascii_only: bool = False,
        use_color: bool = True
    ):
        self.session = session
        self.config = config
        self.ascii_only = ascii_only or getattr(config, "ascii_only", False) or not _supports_unicode()
        self.use_color = use_color and (os.environ.get("NO_COLOR") != "1")
        self.active_tab: int = 1  # 1: Dashboard, 2: Contacts, 3: Radar, 4: Analytics, 5: Events, 6: Diagnostics
        self.radar = TerminalRadar(ascii_only=self.ascii_only)
        self.search_filter: str = ""
        self.is_paused: bool = False
        self.selected_contact_index: int = 0
        self.last_scan_metadata: Optional[Any] = None

    def _color(self, code: str, text: str) -> str:
        """Wrap text in ANSI color if color enabled."""
        if not self.use_color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def _pad_line(self, line: str, width: int) -> str:
        """Pad a line to exact terminal width, taking into account ANSI escape sequences."""
        vis_len = visible_length(line)
        if vis_len < width:
            return line + (" " * (width - vis_len))
        elif vis_len > width:
            # Need to truncate without breaking ANSI
            clean = strip_ansi(line)
            return clean[:max(0, width - 3)] + "..."
        return line

    def render_header(self, width: int, scanner_status: str = "IDLE") -> List[str]:
        """Render universal application header and tab bar."""
        app_title = "ALPHA WIRELESS OBSERVATION"
        mock_tag = " [MOCK DATA]" if self.session.is_mock else " [ROOTLESS]"
        profile_tag = f" [{self.config.power_profile}]"
        
        # Pulsing heartbeat indicator
        pulse = "●" if (int(time.time() * 2) % 2 == 0) else "○"
        if self.ascii_only:
            pulse = "*" if (int(time.time() * 2) % 2 == 0) else "."
        status_tag = " [PAUSED]" if self.is_paused else f" [{pulse} LIVE]"
        
        header_text = f" {app_title}{mock_tag}{profile_tag}{status_tag}"
        dur = int(time.time() - self.session.started_at)
        dur_str = f"{dur // 60:02d}:{dur % 60:02d} "
        
        spacing = max(0, width - len(header_text) - len(dur_str))
        top_bar = self._color("1;37;44", f"{header_text}{' ' * spacing}{dur_str}")

        # Tab navigation bar
        tabs = [
            (1, "1:Dashboard"),
            (2, "2:Contacts"),
            (3, "3:Radar"),
            (4, "4:Analytics"),
            (5, "5:Events"),
            (6, "6:Diag"),
        ]
        tab_str = " "
        for num, title in tabs:
            if num == self.active_tab:
                tab_str += self._color("1;30;46", f" [{title}] ") + " "
            else:
                tab_str += self._color("36", f"  {title}  ") + " "

        scan_info = f"[{scanner_status}]"
        pad_tab = max(0, width - visible_length(tab_str) - len(scan_info) - 1)
        tab_bar = tab_str + (" " * pad_tab) + self._color("33", scan_info)

        sep = "-" * width if self.ascii_only else "─" * width
        return [top_bar, tab_bar, self._color("1;34", sep)]

    def render_footer(self, width: int) -> List[str]:
        """Render bottom action hotkey legend with high-contrast Blue/White styling."""
        sep = "-" * width if self.ascii_only else "─" * width
        if width >= 85:
            shortcuts = " ⌨ [Tab/1-6] Tabs  │  [r] Scan Now  │  [p] Pause/Resume  │  [c] Power Profile  │  [q] Quit "
        elif width >= 65:
            shortcuts = " ⌨ [1-6] Tabs  │  [r] Scan  │  [p] Pause  │  [c] Profile  │  [q] Quit "
        else:
            shortcuts = " [1-6]Tabs [r]Scan [p]Pause [c]Prof [q]Quit "

        # High-contrast Bold White on Blue banner spanning full terminal width
        bar_padded = shortcuts.ljust(width)
        footer_bar = self._color("1;37;44", bar_padded)
        sep_line = self._color("1;34", sep)
        return [sep_line, footer_bar]

    def render_dashboard(self, contacts: List[Contact], events: List[Event], width: int, max_lines: int) -> List[str]:
        """Render Dashboard View (Compact, Standard, or Wide)."""
        lines = []
        summary = AnalyticsEngine.compute_summary(contacts)

        # Top metric cards
        total = summary["total_contacts"]
        wifi_c = summary["wifi_count"]
        ble_c = summary["ble_count"]
        active = summary["states"]["ACTIVE"]
        new_c = summary["states"]["NEW"]
        stale_c = summary["states"]["STALE"]

        if width >= 75:
            card1 = f"Total: {self._color('1;37', str(total))} (Wi-Fi: {wifi_c} | BLE: {ble_c})"
            card2 = f"Active: {self._color('93', str(active))} | New: {self._color('92', str(new_c))} | Stale: {self._color('37', str(stale_c))}"
            card3 = f"Mean RSSI: {summary['mean_rssi']} dBm"
            lines.append(f" {card1}  │  {card2}  │  {card3}")
        else:
            lines.append(f" Total: {total} (Wi-Fi:{wifi_c} BLE:{ble_c}) │ Active:{active} New:{new_c} Stale:{stale_c}")
            lines.append(f" Mean RSSI: {summary['mean_rssi']} dBm │ Events: {len(events)}")

        lines.append("")

        # Display Help & Onboarding Banner if 0 contacts observed
        if total == 0:
            border = "-" * min(width - 2, 70) if self.ascii_only else "─" * min(width - 2, 70)
            lines.append(self._color("1;33", f" ┌{border}┐"))
            lines.append(self._color("1;33", f" │  [!] WAITING FOR WIRELESS SCAN RESULTS"))
            lines.append(self._color("1;37", f" │  Android / Termux Discovery Checklist:"))
            lines.append(self._color("36",   f" │  1. Wi-Fi: Turn ON Android Location (GPS) & Grant Termux:API Location"))
            lines.append(self._color("36",   f" │  2. BLE: Enable Bluetooth & Pair devices, or run with '--mock-ble'"))
            lines.append(self._color("32",   f" │  3. Press [r] to force an immediate scan pass now"))
            lines.append(self._color("32",   f" │  (Tip: Run 'alpha --mock' or 'alpha --mock-ble' for hybrid testing)"))
            lines.append(self._color("1;33", f" └{border}┘"))
            lines.append("")

        # Wi-Fi Channel Occupancy Bar
        if summary["channel_distribution"]:
            lines.append(self._color("1;36", "--- Wi-Fi Channel Occupancy ---"))
            ch_items = list(summary["channel_distribution"].items())[:8]
            ch_str = " "
            for ch, count in ch_items:
                ch_str += f"Ch {ch}: {self._color('1;33', str(count))} APs  "
            lines.append(ch_str)
            lines.append("")

        # Scanner Health & Freshness
        if self.last_scan_metadata:
            meta = self.last_scan_metadata
            fresh_color = "92" if meta.freshness == FreshnessState.LIVE else ("33" if meta.freshness == FreshnessState.CACHED else "91")
            fresh_label = self._color(fresh_color, meta.freshness.value)
            lines.append(f"Scanner Health: {fresh_label} (Duration: {meta.duration_ms:.1f}ms | Age: {meta.age_seconds:.1f}s)")
            if meta.error_message:
                lines.append(self._color("33", f"Notice: {meta.error_message}"))
            lines.append("")

        # Recent Events Stream
        lines.append(self._color("1;36", "--- Recent Environmental Events ---"))
        displayed_events = events[:max(3, max_lines - len(lines) - 4)]
        if not displayed_events:
            lines.append(" (No environmental events recorded yet)")
        for ev in displayed_events:
            ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
            sev_color = "91;1" if ev.severity.value == "ALERT" else ("33" if ev.severity.value == "WARNING" else "37")
            msg = sanitize_string(ev.message, max_length=width - 20)
            lines.append(f" [{ts}] {self._color(sev_color, ev.event_type):<18} {msg}")

        return lines

    def render_contacts(self, contacts: List[Contact], width: int, max_lines: int) -> List[str]:
        """Render Filterable Contacts View."""
        lines = []
        filtered = contacts
        if self.search_filter:
            q = self.search_filter.lower()
            filtered = [
                c for c in contacts
                if q in (c.ssid or "").lower()
                or q in (c.device_name or "").lower()
                or q in c.mac_address.lower()
                or q in c.manufacturer.lower()
                or q in c.category.value.lower()
            ]

        # Table header based on width
        if width >= 90:
            hdr = f" {'ST':<3} {'TYP':<4} {'SSID / DEVICE NAME':<22} {'MAC ADDRESS':<18} {'MANUFACTURER':<18} {'RSSI':<8} {'CH':<4} {'SECURITY'}"
            lines.append(self._color("1;36", hdr))
            lines.append(self._color("1;34", "-" * width if self.ascii_only else "─" * width))
            for c in filtered[:max_lines - 4]:
                name = sanitize_string(c.ssid or c.device_name or "[None]", max_length=20)
                mfg = sanitize_string(c.manufacturer, max_length=16)
                st_color = "92" if c.state == ContactState.NEW else ("93" if c.state == ContactState.ACTIVE else "37")
                row = f" {self._color(st_color, c.state.value[:2]):<3} {c.signal_type.value[:3]:<4} {name:<22} {c.mac_address:<18} {mfg:<18} {c.last_rssi:>4}dBm {str(c.channel or '-'):>3}  {c.security}"
                lines.append(row)
        else:
            # Compact view for phone screen
            hdr = f" {'ST':<2} {'SSID/NAME':<16} {'MAC':<17} {'RSSI':<7} {'VENDOR'}"
            lines.append(self._color("1;36", hdr))
            lines.append(self._color("1;34", "-" * width if self.ascii_only else "─" * width))
            for c in filtered[:max_lines - 4]:
                name = sanitize_string(c.ssid or c.device_name or "[None]", max_length=15)
                mfg = sanitize_string(c.manufacturer, max_length=10)
                st_color = "92" if c.state == ContactState.NEW else ("93" if c.state == ContactState.ACTIVE else "37")
                row = f" {self._color(st_color, c.state.value[0]):<2} {name:<16} {c.mac_address:<17} {c.last_rssi:>4}dB {mfg}"
                lines.append(row)

        return lines

    def render_radar(self, contacts: List[Contact], width: int, max_lines: int) -> List[str]:
        """Render Polar Radar View."""
        radar_height = max(12, max_lines - 2)
        radar_str = self.radar.render(contacts, width=width, height=radar_height, use_color=self.use_color)
        return radar_str.splitlines()

    def render_analytics(self, contacts: List[Contact], observations: List[Observation], width: int, max_lines: int) -> List[str]:
        """Render Analytics & Spectrum View."""
        lines = []
        summary = AnalyticsEngine.compute_summary(contacts)

        lines.append(self._color("1;36", "=== RF SPECTRUM & CLASSIFICATION ANALYTICS ==="))
        
        # Band Breakdown
        bands_str = " | ".join(f"{b}: {cnt}" for b, cnt in summary["band_distribution"].items())
        lines.append(f"Frequency Bands: {bands_str}")

        # RSSI Buckets
        rssi_str = " | ".join(f"{k.split()[0]}: {v}" for k, v in summary["rssi_distribution"].items())
        lines.append(f"Signal Strength: {rssi_str}")
        lines.append("")

        # Top Manufacturers
        lines.append(self._color("1;36", "--- Top Manufacturers Observed ---"))
        for mfg, cnt in list(summary["manufacturer_distribution"].items())[:6]:
            pct = (cnt / max(1, summary["total_contacts"])) * 100
            bar_len = int(pct / 5)
            bar = self._color("32", "■" * bar_len if not self.ascii_only else "#" * bar_len)
            lines.append(f" {mfg:<26} {cnt:>3} ({pct:>4.1f}%) {bar}")

        lines.append("")
        # Device Categories
        lines.append(self._color("1;36", "--- Device Classification Breakdown ---"))
        for cat, cnt in list(summary["category_distribution"].items())[:5]:
            lines.append(f" - {cat:<24} : {cnt} contact(s)")

        return lines

    def render_events(self, events: List[Event], width: int, max_lines: int) -> List[str]:
        """Render Events View."""
        lines = [self._color("1;36", "=== STRUCTURED ENVIRONMENTAL EVENT LOG ==="), ""]
        for ev in events[:max_lines - 4]:
            ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
            sev = ev.severity.value
            col = "91;1" if sev == "ALERT" else ("33" if sev == "WARNING" else ("92" if sev == "NOTICE" else "37"))
            lines.append(f"[{ts}] {self._color(col, ev.event_type):<20} ({ev.related_identifier})")
            lines.append(f"  {ev.message}")
            if ev.evidence:
                ev_desc = " | ".join(ev.evidence[:2])
                lines.append(self._color("36", f"  Evidence: {ev_desc}"))
            lines.append("")
        return lines

    def render_diagnostics(self, width: int, max_lines: int) -> List[str]:
        """Render Diagnostics Matrix View."""
        report = EnvironmentInspector.format_diagnostics_report()
        return report.splitlines()

    def render_full_screen(
        self,
        contacts: List[Contact],
        events: List[Event],
        observations: Optional[List[Observation]] = None,
        last_metadata: Optional[Any] = None,
        scanner_status: str = "IDLE"
    ) -> str:
        """Assemble and render the full interactive terminal screen."""
        self.last_scan_metadata = last_metadata
        term_size = shutil.get_terminal_size((80, 24))
        width = max(40, term_size.columns)
        height = max(15, term_size.lines)

        header_lines = self.render_header(width, scanner_status=scanner_status)
        footer_lines = self.render_footer(width)
        content_lines_allowed = max(5, height - len(header_lines) - len(footer_lines))

        if self.active_tab == 1:
            body_lines = self.render_dashboard(contacts, events, width, content_lines_allowed)
        elif self.active_tab == 2:
            body_lines = self.render_contacts(contacts, width, content_lines_allowed)
        elif self.active_tab == 3:
            body_lines = self.render_radar(contacts, width, content_lines_allowed)
        elif self.active_tab == 4:
            body_lines = self.render_analytics(contacts, observations or [], width, content_lines_allowed)
        elif self.active_tab == 5:
            body_lines = self.render_events(events, width, content_lines_allowed)
        else:
            body_lines = self.render_diagnostics(width, content_lines_allowed)

        # Pad or truncate body to fill height exactly without scrolling jitter
        if len(body_lines) < content_lines_allowed:
            body_lines.extend([""] * (content_lines_allowed - len(body_lines)))
        else:
            body_lines = body_lines[:content_lines_allowed]

        all_lines = header_lines + body_lines + footer_lines
        padded_lines = [self._pad_line(line, width) for line in all_lines[:height]]

        # Clear screen and move cursor to top-left
        output = "\033[H" + "\n".join(padded_lines)
        return output
