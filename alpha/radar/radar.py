"""
Terminal Radar Visualizer for Alpha.

Renders an interactive polar radar display in the terminal.
Maps wireless contacts deterministically to polar coordinates based on identifier hash
(stable angle) and RSSI signal strength (relative radius from center).

Explicitly labeled as Relative RF Proximity (non-geographic).
"""

import hashlib
import math
import sys
from typing import Dict, List, Optional, Tuple
from alpha.models import Contact, ContactState, SignalType, SignalCategory
from alpha.sanitizer import sanitize_string


def _supports_unicode() -> bool:
    try:
        "│─┼·●♦○".encode(sys.stdout.encoding or "ascii")
        return True
    except Exception:
        return False


class TerminalRadar:
    """Deterministic polar radar generator for ANSI terminals."""

    def __init__(self, ascii_only: bool = False):
        self.ascii_only = ascii_only or not _supports_unicode()

    def _get_stable_angle(self, identifier: str) -> float:
        """Derive a deterministic, stable polar angle in radians from MAC/identifier hash."""
        digest = hashlib.md5(identifier.encode("utf-8")).hexdigest()
        int_val = int(digest[:6], 16)
        # Normalize to 0 .. 2*pi
        return (int_val % 3600) / 3600.0 * 2.0 * math.pi

    def _rssi_to_radius_ratio(self, rssi: int) -> float:
        """
        Map RSSI (-30 dBm to -95 dBm) to a normalized radius [0.15 .. 0.95].
        -30 dBm -> 0.15 (very close to center)
        -95 dBm -> 0.95 (at perimeter ring)
        """
        clamped = max(-95, min(-30, rssi))
        # Range is 65 dBm (-30 to -95)
        ratio = (-30 - clamped) / 65.0  # 0.0 at -30, 1.0 at -95
        return 0.15 + (ratio * 0.80)

    def render(
        self,
        contacts: List[Contact],
        width: int = 70,
        height: int = 22,
        use_color: bool = True
    ) -> str:
        """
        Render the polar radar grid with placed wireless contacts.
        """
        # Ensure dimensions are reasonable
        width = max(38, width)
        height = max(14, height)

        center_x = width // 2
        center_y = height // 2
        radius_x = (width - 4) // 2
        radius_y = (height - 3) // 2

        # Create character buffer
        grid = [[" " for _ in range(width)] for _ in range(height)]
        color_grid = [["" for _ in range(width)] for _ in range(height)]

        # Character set
        ring_char = "." if self.ascii_only else "·"
        axis_h = "-" if self.ascii_only else "─"
        axis_v = "|" if self.ascii_only else "│"
        center_char = "+" if self.ascii_only else "┼"

        # Draw concentric rings (3 concentric circles for -50dBm, -70dBm, -85dBm)
        rings = [0.35, 0.65, 0.95]
        for r_ratio in rings:
            num_points = int(2.0 * math.pi * max(radius_x, radius_y) * r_ratio * 1.5)
            for i in range(num_points):
                theta = (i / num_points) * 2.0 * math.pi
                px = int(center_x + (radius_x * r_ratio * math.cos(theta)))
                py = int(center_y + (radius_y * r_ratio * math.sin(theta)))
                if 0 <= py < height and 0 <= px < width:
                    grid[py][px] = ring_char
                    color_grid[py][px] = "\033[90m" if use_color else ""

        # Draw Crosshairs
        for x in range(2, width - 2):
            if grid[center_y][x] == " ":
                grid[center_y][x] = axis_h
                color_grid[center_y][x] = "\033[90m" if use_color else ""
        for y in range(1, height - 1):
            if grid[y][center_x] == " ":
                grid[y][center_x] = axis_v
                color_grid[y][center_x] = "\033[90m" if use_color else ""
        grid[center_y][center_x] = center_char

        # Ring Labels
        if center_x + int(radius_x * 0.35) + 1 < width - 6:
            lbl = "-50"
            for idx, ch in enumerate(lbl):
                grid[center_y][center_x + int(radius_x * 0.35) + 1 + idx] = ch
        if center_x + int(radius_x * 0.65) + 1 < width - 6:
            lbl = "-70"
            for idx, ch in enumerate(lbl):
                grid[center_y][center_x + int(radius_x * 0.65) + 1 + idx] = ch
        if center_x + int(radius_x * 0.95) - 3 < width:
            lbl = "-85"
            for idx, ch in enumerate(lbl):
                if center_x + int(radius_x * 0.95) - 3 + idx < width:
                    grid[center_y][center_x + int(radius_x * 0.95) - 3 + idx] = ch

        # Place Contacts on Radar
        for contact in contacts:
            angle = self._get_stable_angle(contact.identifier)
            r_ratio = self._rssi_to_radius_ratio(contact.last_rssi)

            px = int(center_x + (radius_x * r_ratio * math.cos(angle)))
            py = int(center_y + (radius_y * r_ratio * math.sin(angle)))

            if not (0 <= py < height and 0 <= px < width):
                continue

            # Determine marker symbol and color
            if contact.signal_type == SignalType.BLE:
                marker = "B" if self.ascii_only else "♦"
                color_code = "\033[96m"  # Cyan for BLE
            else:
                marker = "W" if self.ascii_only else "●"
                if contact.is_watchlist_match:
                    color_code = "\033[91;1m"  # Bold Red
                elif contact.state == ContactState.NEW:
                    color_code = "\033[92;1m"  # Bold Green
                elif contact.state == ContactState.ACTIVE:
                    color_code = "\033[93m"    # Yellow
                elif contact.state == ContactState.RECENT:
                    color_code = "\033[33m"    # Dark Yellow
                else:  # STALE
                    color_code = "\033[90m"    # Gray
                    marker = "x" if self.ascii_only else "○"

            grid[py][px] = marker
            color_grid[py][px] = color_code if use_color else ""

            # Label on wider screens
            if width >= 70 and contact.state in (ContactState.NEW, ContactState.ACTIVE) and px + 8 < width - 2:
                name_tag = contact.ssid or contact.device_name or contact.manufacturer or ""
                clean_tag = sanitize_string(name_tag, fallback="", max_length=7)
                if clean_tag and clean_tag != "[Hidden SSID]":
                    for idx, ch in enumerate(clean_tag):
                        target_x = px + 2 + idx
                        if target_x < width - 1 and grid[py][target_x] in (" ", ring_char, axis_h):
                            grid[py][target_x] = ch
                            color_grid[py][target_x] = "\033[37m" if use_color else ""

        # Assemble rendered output lines
        reset_code = "\033[0m" if use_color else ""
        lines = []
        
        # Header banner
        header = "=== RELATIVE RF SIGNAL RADAR (NON-GEOGRAPHIC PROXIMITY) ==="
        pad = max(0, (width - len(header)) // 2)
        lines.append(" " * pad + ("\033[1;36m" + header + reset_code if use_color else header))

        for y in range(height):
            line_str = ""
            for x in range(width):
                char = grid[y][x]
                col = color_grid[y][x]
                if use_color and col:
                    line_str += f"{col}{char}{reset_code}"
                else:
                    line_str += char
            lines.append(line_str)

        # Legend
        if use_color and not self.ascii_only:
            legend = "Legend: \033[92;1m● NEW\033[0m  \033[93m● ACTIVE\033[0m  \033[33m● RECENT\033[0m  \033[90m○ STALE\033[0m  \033[96m♦ BLE\033[0m  \033[91;1m● WATCHLIST\033[0m"
        elif use_color:
            legend = "Legend: \033[92;1mW:NEW\033[0m  \033[93mW:ACTIVE\033[0m  \033[33mW:RECENT\033[0m  \033[90mx:STALE\033[0m  \033[96mB:BLE\033[0m  \033[91;1mW:WATCHLIST\033[0m"
        else:
            legend = "Legend: W=Wi-Fi  B=BLE  x=Stale  Center=Strong(-30dBm) Outer=Weak(-95dBm)"
        lines.append(legend)

        return "\n".join(lines)
